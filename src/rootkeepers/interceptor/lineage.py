"""npm/GitHub/Sigstore 증거를 하나로 합치는 통합 릴리스 계보 오케스트레이터."""

from __future__ import annotations

import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse

from rootkeepers.collectors.npm.__main__ import collect_npm_release
from rootkeepers.interceptor.detailed_rule_engine import (
    evaluate_detailed_evidence,
    evidence_from_lineage,
)


SCHEMA_VERSION = "rootkeepers.release-lineage.v1"


class TrackSkipped(Exception):
    """필요한 상위 데이터가 없어 트랙 실행 자체를 건너뛸 때 발생시키는 예외."""


def collect_release_lineage_report(
    package_name: str,
    version: str | None,
    *,
    sigstore_timeout: int = 15,
) -> dict[str, Any]:
    """Track A를 먼저 실행한 뒤 Track B, Track C를 실행해 JSON 문서 하나로 합친다.

    Args:
        package_name: npm 패키지명 (예: "lodash", "@scope/name").
        version: 검사할 버전. None이면 버전 미지정 설치로 간주하고, 이 경우
            npm 트랙이 "latest" dist-tag로 resolve한 뒤 그 resolve된 버전을
            GitHub/Sigstore 트랙에도 그대로 전달한다.
        sigstore_timeout: npm attestation 요청 타임아웃(초).
    """
    started_at = _utc_now()
    npm_result = _run_track("npm", lambda: _collect_npm(package_name, version))

    artifact = _artifact_from_npm(npm_result)
    npm_git_head = artifact.get("git_head")
    npm_repo_url = artifact.get("repo_url")
    npm_owner_repo = normalize_github_repository(npm_repo_url)

    # npm 트랙이 version=None을 latest로 resolve했을 수 있으므로, downstream
    # 트랙(특히 Sigstore attestation URL 조립)에는 원본 version이 아니라
    # 실제로 resolve된 버전을 전달해야 한다. 그렇지 않으면 version=None인
    # "bare install" 케이스에서 Sigstore 요청 URL에 "None"이 그대로 박힌다.
    resolved_version = _resolved_version_from_npm(npm_result, fallback=version)

    track_results = {"npm": npm_result}
    github_git_head = npm_git_head
    github_owner_repo = npm_owner_repo
    commit_source = "npm.artifact.gitHead" if npm_git_head else None
    repository_source = "npm.artifact.repository" if npm_owner_repo else None

    if npm_git_head:
        # The normal path has all of Track B's inputs.  Keep GitHub and
        # Sigstore concurrent to avoid adding latency to ordinary packages.
        downstream_tracks: dict[str, Callable[[], dict[str, Any]]] = {
            "github": lambda: _collect_github(github_owner_repo, github_git_head),
            "sigstore": lambda: _collect_sigstore(
                package_name, resolved_version, sigstore_timeout
            ),
        }
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(_run_track, name, collector): name
                for name, collector in downstream_tracks.items()
            }
            for future in as_completed(futures):
                track_results[futures[future]] = future.result()
        # GitHub 트랙이 Sigstore와 동시에 도는 탓에, "현재 릴리스를 만든 워크플로
        # 경로"(provenance)는 트랙 실행 시점에 아직 없다. 그래서 이 신호만 사후에
        # 보충한다. GitHub 트랙을 통째로 다시 돌리면 커밋·태그·워크플로·기준선까지
        # 20여 회를 중복 호출하지만, 이 신호에 실제로 필요한 건 3회뿐이다.
        _attach_workflow_modification(
            track_results,
            github_owner_repo,
            github_git_head,
            _slsa_workflow_path(track_results.get("sigstore", {})),
        )
    else:
        # npm's dist.gitHead is optional and is frequently absent for
        # monorepo/automated releases.  In that case Track C's signed SLSA
        # provenance is the stronger source of the build commit.  Track B
        # must wait for it instead of being skipped in parallel.
        sigstore_result = _run_track(
            "sigstore",
            lambda: _collect_sigstore(package_name, resolved_version, sigstore_timeout),
        )
        track_results["sigstore"] = sigstore_result
        slsa_repository, slsa_commit = _slsa_git_reference(sigstore_result)
        if slsa_commit:
            github_git_head = slsa_commit
            commit_source = "sigstore.slsa_predicate.commit"
        if slsa_repository:
            github_owner_repo = normalize_github_repository(slsa_repository)
            repository_source = "sigstore.slsa_predicate.repository"
        # 이 경로는 Sigstore가 먼저 끝나 있으므로, 현재 릴리스의 provenance
        # 워크플로 경로를 GitHub 트랙에 곧바로 넘길 수 있다(추가 호출 0회).
        current_workflow = _slsa_workflow_path(sigstore_result)
        track_results["github"] = _run_track(
            "github",
            lambda: _collect_github(
                github_owner_repo,
                github_git_head,
                workflow_entry_point=current_workflow,
            ),
        )

    npm_baseline = _mapping_from_track(npm_result, "baseline")
    github_baseline = _mapping_from_track(track_results.get("github"), "baseline")

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "started_at": started_at,
        "package": {
            "ecosystem": "npm",
            "name": package_name,
            "version": resolved_version,
        },
        "pipeline": {
            "npm_to_github": {
                "git_head": npm_git_head,
                "repository_url": npm_repo_url,
                "owner_repo": npm_owner_repo,
                "github_lookup": {
                    "git_head": github_git_head,
                    "owner_repo": github_owner_repo,
                    "commit_source": commit_source,
                    "repository_source": repository_source,
                },
            }
        },
        "tracks": track_results,
        # Keep baselines at the document root so scoring never depends on a
        # collector-specific track layout.  The original track copies remain
        # available for audit/debugging.
        "baseline": {
            # Keep the npm fields directly accessible for consumers that were
            # introduced before per-track namespaces, while the namespaces
            # prevent collisions as additional collectors add baselines.
            **npm_baseline,
            "npm": npm_baseline,
            "github": github_baseline,
        },
        "summary": _build_summary(track_results),
    }


def evaluate_risk(report: dict[str, Any]) -> dict[str, Any]:
    """계보 리포트를 6개 상세 규칙과 완화된 차단 정책으로 평가한다.

    Args:
        report: ``collect_release_lineage_report``의 반환값.

    Returns:
        규칙별 signal·증거 상태와 최종 verdict/score를 담은 dict.
    """
    return evaluate_detailed_evidence(evidence_from_lineage(report))


def normalize_github_repository(repo_url: str | None) -> str | None:
    """npm에서 흔히 쓰이는 repository URL 형태를 owner/repo로 정규화한다."""
    if not repo_url:
        return None

    cleaned = repo_url.strip()
    cleaned = re.sub(r"^git\+", "", cleaned)
    # npm repository.url에 ``#main``/``#master`` 같은 브랜치 fragment가 붙는
    # 경우가 있다 (예: ``git+https://github.com/owner/repo.git#main``).
    # ``.git`` 제거보다 먼저 잘라내지 않으면 문자열 끝이 ``.git``이 아니게
    # 되어 뒤의 ``.git$`` 정규식이 매칭되지 않고, owner_repo에 ``.git``이
    # 그대로 남아 존재하지 않는 저장소로 조회하게 된다.
    cleaned = re.sub(r"[#?].*$", "", cleaned)
    cleaned = re.sub(r"\.git$", "", cleaned)

    ssh_match = re.match(r"git@github\.com:(?P<owner>[^/]+)/(?P<repo>[^/]+)$", cleaned)
    if ssh_match:
        return f"{ssh_match.group('owner')}/{ssh_match.group('repo')}"

    if cleaned.startswith("github:"):
        return cleaned.removeprefix("github:").strip("/")

    parsed = urlparse(cleaned)
    # ``git+ssh://git@github.com/owner/repo.git`` is a common npm repository
    # form.  ``netloc`` includes the username in that case, while ``hostname``
    # remains github.com.
    if (parsed.hostname or "").lower() != "github.com":
        return None

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return None

    return f"{parts[0]}/{parts[1]}"


def _collect_npm(package_name: str, version: str) -> dict[str, Any]:
    result = collect_npm_release(package_name, version)
    if result is None:
        raise RuntimeError("npm 수집기가 패키지 데이터를 반환하지 않았습니다")
    return result


def _collect_github(
    owner_repo: str | None,
    git_head: str | None,
    *,
    baseline_releases: list[dict[str, Any]] | None = None,
    workflow_entry_point: str | None = None,
) -> dict[str, Any]:
    if not owner_repo:
        raise TrackSkipped("npm 메타데이터에서 GitHub 저장소를 알아낼 수 없습니다")
    if not git_head:
        raise TrackSkipped("npm artifact 메타데이터에 gitHead가 없습니다")
    from rootkeepers.collectors.github.github_collector import collect_github_evidence

    return collect_github_evidence(
        owner_repo=owner_repo,
        git_head=git_head,
        baseline_releases=baseline_releases,
        workflow_entry_point=workflow_entry_point,
    )


def _collect_sigstore(
    package_name: str,
    version: str,
    timeout: int,
) -> dict[str, Any]:
    from rootkeepers.collectors.sigstore.__main__ import collect_release_lineage

    return collect_release_lineage(package_name, version, timeout=timeout)


def _slsa_git_reference(sigstore_track: dict[str, Any]) -> tuple[str | None, str | None]:
    """서명된 SLSA 결과가 담고 있는 저장소와 커밋을 돌려준다.

    Sigstore 수집기는 관련 predicate 필드를 ``slsa_predicate`` 아래로 정규화해
    둔다. 실패했거나 형식이 깨진 Track C 결과는 "증거 없음"으로 취급해서,
    커밋을 추측하는 대신 GitHub 트랙이 ``SKIPPED``로 남게 한다.
    """
    if sigstore_track.get("status") != "SUCCESS":
        return None, None
    data = sigstore_track.get("data")
    if not isinstance(data, dict):
        return None, None
    predicate = data.get("slsa_predicate")
    if not isinstance(predicate, dict):
        return None, None
    repository = predicate.get("repository")
    commit = predicate.get("commit")
    return (
        repository if isinstance(repository, str) and repository else None,
        commit if isinstance(commit, str) and commit else None,
    )


def _attach_workflow_modification(
    track_results: dict[str, dict[str, Any]],
    owner_repo: str | None,
    git_head: str | None,
    workflow_entry_point: str | None,
) -> None:
    """릴리스 커밋에서 provenance 워크플로 파일이 변조됐는지를 GitHub 트랙에 채운다.

    workflow_drift 규칙의 ``workflow_modified_before_release`` 신호는 "현재
    릴리스를 만든 워크플로 경로"를 알아야 판정할 수 있는데, 그 경로는 Sigstore
    트랙의 SLSA provenance에서만 나온다. GitHub와 Sigstore가 병렬로 도는
    경로에서는 GitHub 트랙 실행 시점에 그 값이 없으므로 여기서 보충한다.

    GitHub 트랙 전체를 재실행하지 않는 이유는 비용이다. 재실행은 커밋·태그·
    워크플로·기준선까지 20여 회를 다시 부르지만, 이 신호에 실제로 필요한 것은
    저장소 조회 + 커밋 비교 3회뿐이다.

    보조 신호이므로 실패해도 스캔을 중단시키지 않는다. 값이 채워지지 않으면
    None으로 남고 규칙 엔진이 해당 규칙을 PARTIAL로 표시한다.
    """
    if not (owner_repo and git_head and workflow_entry_point):
        return
    github_track = track_results.get("github")
    if not isinstance(github_track, dict) or github_track.get("status") != "SUCCESS":
        return
    data = github_track.get("data")
    if not isinstance(data, dict):
        return

    from rootkeepers.collectors.github.github_collector import (
        get_repo,
        workflow_modified_before_release,
    )

    try:
        _, repo = get_repo(owner_repo)
        data["workflow_modified_before_release"] = workflow_modified_before_release(
            repo, git_head, workflow_entry_point
        )
    except Exception as exc:  # noqa: BLE001 — 보조 신호 실패가 스캔을 막으면 안 된다
        sys.stderr.write(
            f"[lineage] {owner_repo}@{git_head} 워크플로 변경 조회 실패(무시): {exc}\n"
        )


def _slsa_workflow_path(sigstore_track: dict[str, Any]) -> str | None:
    data = sigstore_track.get("data")
    if sigstore_track.get("status") != "SUCCESS" or not isinstance(data, dict):
        return None
    predicate = data.get("slsa_predicate")
    workflow = predicate.get("workflow_path") if isinstance(predicate, dict) else None
    return workflow if isinstance(workflow, str) and workflow else None


def _run_track(name: str, collector: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return {
            "status": "SUCCESS",
            "data": collector(),
            "error": None,
        }
    except TrackSkipped as error:
        return _track_error("SKIPPED", error)
    except Exception as error:
        if error.__class__.__name__ == "GithubRateLimitError":
            return _track_error(
                "UNVERIFIABLE",
                error,
                reason="GITHUB_RATE_LIMIT_EXCEEDED",
            )
        if name == "sigstore" and error.__class__.__name__ == "CollectorError":
            return _track_error("ERROR", error, reason="SIGSTORE_COLLECT_FAILED")
        return _track_error("ERROR", error, reason=f"{name.upper()}_COLLECT_FAILED")


def _track_error(
    status: str,
    error: Exception,
    *,
    reason: str | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "data": None,
        "error": {
            "type": error.__class__.__name__,
            "reason": reason or error.__class__.__name__.upper(),
            "message": str(error),
        },
    }


def _artifact_from_npm(npm_result: dict[str, Any]) -> dict[str, Any]:
    data = npm_result.get("data")
    if not isinstance(data, dict):
        return {}
    artifact = data.get("artifact")
    return artifact if isinstance(artifact, dict) else {}


def _mapping_from_track(track: dict[str, Any], key: str) -> dict[str, Any]:
    data = track.get("data")
    if not isinstance(data, dict):
        return {}
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def _resolved_version_from_npm(npm_result: dict[str, Any], *, fallback: str | None) -> str | None:
    """npm 트랙이 실제로 resolve한 버전을 다시 꺼내온다.

    ``version``이 생략되면(버전 미지정 ``npm install <package>``), npm
    트랙이 내부적으로 "latest" dist-tag로 resolve한다. downstream
    트랙들은 원본 ``None``/생략값이 아니라 그 resolve된 버전을 써야
    하며, 그렇지 않으면 Sigstore attestation URL 조립이 깨진다.
    """
    data = npm_result.get("data")
    if not isinstance(data, dict):
        return fallback

    package = data.get("package")
    if not isinstance(package, dict):
        return fallback

    resolved = package.get("version")
    return resolved if isinstance(resolved, str) and resolved else fallback


def _build_summary(track_results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    statuses = {
        track_name: track_result.get("status", "UNKNOWN")
        for track_name, track_result in sorted(track_results.items())
    }
    return {
        "overall_status": "SUCCESS"
        if all(status == "SUCCESS" for status in statuses.values())
        else "PARTIAL",
        "track_statuses": statuses,
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

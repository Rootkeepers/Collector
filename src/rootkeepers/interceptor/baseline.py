"""과거 릴리스로 '평소'를 만들어 규칙 엔진에 넘길 기준선(baseline)을 구성한다.

6개 규칙 중 5개는 "절대적으로 나쁘다"가 아니라 **"평소와 달라졌다"**를 본다.
그 '평소'가 없으면 규칙은 감점하지 않고 UNVERIFIABLE로 남는다(모르는 것을
안전하다고 속이지 않기 위한 설계). 이 모듈이 그 '평소'를 만든다.

비용이 단계별로 크게 다르므로 레벨로 나눈다:

    npm       추가 API 호출 **0회**. 패키지 문서 하나에 모든 버전의 배포자와
              attestation 유무가 이미 들어 있다.
              → tag_identity_drift, unexpected_builder, oidc_mismatch

    sigstore  릴리스당 1회. builder.id와 워크플로 경로를 얻는다.
              → workflow_drift, unexpected_builder(builder 비교)

    github    릴리스당 약 5회(커밋·PR·리뷰어·태그·워크플로). 가장 비싸다.
              → unreviewed, orphan_release의 거버넌스 기준선

기본값은 sigstore까지다. github은 레이트리밋 소모가 커서 명시적으로 켜야 한다.
"""

from __future__ import annotations

import sys
from typing import Any

BASELINE_SIZE = 5


def _publisher_of(version_doc: dict) -> str | None:
    user = version_doc.get("_npmUser")
    if isinstance(user, dict) and user.get("name"):
        return str(user["name"])
    return None


def _attestation_present(version_doc: dict) -> bool:
    dist = version_doc.get("dist") or {}
    return "attestations" in dist


def previous_versions(package_doc: dict, current_version: str, limit: int = BASELINE_SIZE) -> list[str]:
    """현재 버전 **이전에** 배포된 릴리스를 최신순으로 고른다.

    레지스트리의 ``time`` 맵(배포 시각)을 기준으로 정렬한다. 버전 문자열을
    semver로 비교하지 않는 이유는, 패치 백포트처럼 나중에 배포된 낮은 버전이
    섞여 있을 때 "그때 실제로 무엇이 정상이었나"를 잘못 잡기 때문이다.
    프리릴리스(-beta 등)는 정식 릴리스의 기준선으로 부적절해 제외한다.
    """
    times = package_doc.get("time") or {}
    versions = package_doc.get("versions") or {}
    current_ts = times.get(current_version)
    if not current_ts:
        return []

    dated = [
        (ts, v) for v, ts in times.items()
        if v in versions and ts < current_ts and "-" not in v
    ]
    dated.sort(reverse=True)
    return [v for _, v in dated[:limit]]


def build_npm_baseline(package_doc: dict, current_version: str,
                       limit: int = BASELINE_SIZE) -> dict[str, Any]:
    """추가 네트워크 호출 없이 npm 기준선을 만든다.

    패키지 문서 하나에 모든 버전의 ``_npmUser``(배포자)와 ``dist.attestations``
    (서명 유무)가 들어 있으므로, 이미 받아온 응답만으로 구성된다.
    """
    versions = package_doc.get("versions") or {}
    picked = previous_versions(package_doc, current_version, limit)

    publishers: list[str] = []
    attestations: list[bool] = []
    releases: list[dict] = []
    for v in picked:
        doc = versions.get(v) or {}
        pub = _publisher_of(doc)
        if pub:
            publishers.append(pub)
        attestations.append(_attestation_present(doc))
        releases.append({"version": v, "publisher": pub,
                         "attestation_present": _attestation_present(doc)})

    return {
        "versions": picked,
        "publishers": publishers,
        "attestations_present": attestations,
        "releases": releases,
    }


def enrich_with_sigstore(npm_baseline: dict, package_name: str,
                         collect_sigstore) -> dict[str, Any]:
    """과거 릴리스의 서명 증거(builder.id, 워크플로 경로)를 채운다.

    릴리스당 1회 호출이 추가된다. 서명이 없는 릴리스는 그냥 건너뛴다
    (예외를 위로 던지지 않는다 — 기준선 수집 실패가 스캔 자체를 막으면 안 된다).

    Args:
        collect_sigstore: ``(package, version) -> dict`` 형태의 수집 함수.
    """
    for release in npm_baseline.get("releases", []):
        if not release.get("attestation_present"):
            continue
        try:
            doc = collect_sigstore(package_name, release["version"])
        except Exception as exc:  # noqa: BLE001 — 기준선은 best-effort
            sys.stderr.write(f"[baseline] {package_name}@{release['version']} 서명 수집 실패(무시): {exc}\n")
            continue
        # 규칙 엔진은 release["sigstore"]["data"] 아래에서 predicate/oidc를 찾는다
        release["sigstore"] = {"data": doc.get("data", doc)}
    return npm_baseline


def _github_releases_from_sigstore(npm_baseline: dict) -> list[dict]:
    """서명 provenance에서 워크플로 진입점을 뽑아 github 기준선을 만든다.

    workflow_drift 규칙은 ``github.releases[*].workflow_entry_points``를 본다.
    GitHub API를 릴리스마다 5번씩 부르지 않아도, SLSA provenance의
    ``workflow_path``가 곧 그 릴리스를 만든 워크플로 경로이므로 그대로 쓸 수
    있다. 현재 릴리스 쪽도 같은 값(provenance의 workflow_path)과 비교하므로
    기준이 어긋나지 않는다.
    """
    releases = []
    for rel in npm_baseline.get("releases", []):
        predicate = (rel.get("sigstore") or {}).get("data", {}).get("slsa_predicate") or {}
        path = predicate.get("workflow_path")
        if path:
            releases.append({"version": rel.get("version"), "workflow_entry_points": [path]})
    return releases


def build_baseline(package_doc: dict, package_name: str, current_version: str,
                   *, limit: int = BASELINE_SIZE,
                   collect_sigstore=None) -> dict[str, Any]:
    """규칙 엔진이 ``report["baseline"]``에서 기대하는 모양으로 조립한다."""
    npm_baseline = build_npm_baseline(package_doc, current_version, limit)
    github_releases: list[dict] = []
    if collect_sigstore is not None and npm_baseline["releases"]:
        npm_baseline = enrich_with_sigstore(npm_baseline, package_name, collect_sigstore)
        github_releases = _github_releases_from_sigstore(npm_baseline)
    # 커밋/PR 이력(orphan_release·unreviewed용)은 릴리스당 GitHub API 약 5회가
    # 더 들어 아직 수집하지 않는다. 그 두 규칙은 UNVERIFIABLE로 남는다.
    return {"npm": npm_baseline, "github": {"releases": github_releases}}


__all__ = ["build_baseline", "build_npm_baseline", "previous_versions", "BASELINE_SIZE"]

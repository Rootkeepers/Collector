"""리팩터링 중 유실됐던 세 가지에 대한 회귀 테스트.

1. ``_slsa_git_reference`` — 정의가 사라진 채 호출부만 남아, npm ``dist.gitHead``가
   없는 패키지(모노레포/자동화 릴리스)를 스캔하면 NameError가 났다.
2. ``workflow_entry_point`` — GitHub 트랙에 전달되지 않아
   ``workflow_modified_before_release`` 신호가 항상 None이었고, workflow_drift
   규칙이 모든 스캔에서 PARTIAL로 남았다.
3. ``report["baseline"]`` 덮어쓰기 — GitHub 트랙이 이미 수집한 기준선을 버려서,
   API 비용은 지불했는데 orphan_release·unreviewed가 UNVERIFIABLE로 남았다.

네트워크를 타지 않는다 — 수집기를 전부 가짜로 바꿔 끼우고, 오케스트레이터가
어떤 값을 어디로 흘려보내는지만 본다.

실행: python tests/interceptor/test_workflow_signal.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from rootkeepers.interceptor import lineage  # noqa: E402
from rootkeepers.interceptor.scanning import _merge_baseline  # noqa: E402

WORKFLOW = ".github/workflows/release.yml"
SHA = "a" * 40


def _npm_result(git_head):
    return {
        "package": {"version": "1.2.3"},
        "artifact": {
            "git_head": git_head,
            "repo_url": "https://github.com/acme/widget",
        },
        "baseline": {"releases": []},
    }


def _sigstore_result():
    return {
        "slsa_predicate": {
            "repository": "https://github.com/acme/widget",
            "commit": SHA,
            "workflow_path": WORKFLOW,
        },
        "fulcio_oidc": {},
    }


def _stub_tracks(monkey, git_head, github_calls):
    """npm/sigstore/github 수집기를 전부 가짜로 바꿔 끼운다."""
    monkey["_collect_npm"] = lineage._collect_npm
    monkey["_collect_sigstore"] = lineage._collect_sigstore
    monkey["_collect_github"] = lineage._collect_github

    def fake_github(owner_repo, head, *, baseline_releases=None, workflow_entry_point=None):
        github_calls.append({
            "owner_repo": owner_repo,
            "git_head": head,
            "baseline_releases": baseline_releases,
            "workflow_entry_point": workflow_entry_point,
        })
        return {
            "repository": "acme/widget",
            "workflow_modified_before_release": None,
            "baseline": {"releases": [], "source": "github_tags"},
        }

    lineage._collect_npm = lambda name, version: _npm_result(git_head)
    lineage._collect_sigstore = lambda name, version, timeout: _sigstore_result()
    lineage._collect_github = fake_github


def _restore(monkey):
    for name, original in monkey.items():
        setattr(lineage, name, original)


def test_sequential_path_has_no_nameerror_and_threads_workflow():
    """gitHead가 없는 경로: NameError 없이 돌고, 워크플로 경로가 전달돼야 한다."""
    monkey, calls = {}, []
    _stub_tracks(monkey, None, calls)
    try:
        report = lineage.collect_release_lineage_report("widget", "1.2.3")
    finally:
        _restore(monkey)

    github_track = report["tracks"]["github"]
    assert github_track["status"] == "SUCCESS", github_track
    # SLSA provenance에서 커밋/저장소를 복구했는지 (_slsa_git_reference 복원 확인)
    lookup = report["pipeline"]["npm_to_github"]["github_lookup"]
    assert lookup["git_head"] == SHA, lookup
    assert lookup["commit_source"] == "sigstore.slsa_predicate.commit", lookup
    assert lookup["repository_source"] == "sigstore.slsa_predicate.repository", lookup
    # 순차 경로에서는 추가 호출 없이 곧바로 전달된다
    assert len(calls) == 1, calls
    assert calls[0]["workflow_entry_point"] == WORKFLOW, calls[0]
    print("PASS  순차 경로: NameError 없음 + workflow_entry_point 전달")


def test_parallel_path_backfills_workflow_modification():
    """gitHead가 있는 경로: 트랙 재실행 없이 변조 신호만 사후 보충돼야 한다."""
    monkey, calls = {}, []
    _stub_tracks(monkey, SHA, calls)

    from rootkeepers.collectors.github import github_collector

    original_get_repo = github_collector.get_repo
    original_modified = github_collector.workflow_modified_before_release
    seen = {}

    def fake_modified(repo, git_head, entry_point):
        seen["git_head"] = git_head
        seen["entry_point"] = entry_point
        return True

    github_collector.get_repo = lambda owner_repo: (None, object())
    github_collector.workflow_modified_before_release = fake_modified
    try:
        report = lineage.collect_release_lineage_report("widget", "1.2.3")
    finally:
        _restore(monkey)
        github_collector.get_repo = original_get_repo
        github_collector.workflow_modified_before_release = original_modified

    data = report["tracks"]["github"]["data"]
    assert data["workflow_modified_before_release"] is True, data
    assert seen["entry_point"] == WORKFLOW, seen
    assert seen["git_head"] == SHA, seen
    # GitHub 트랙을 통째로 재실행하지 않았는지 (예전 구현은 3회 호출했다)
    assert len(calls) == 1, f"GitHub 트랙이 {len(calls)}회 실행됨 — 재실행 없이 보충해야 한다"
    print("PASS  병렬 경로: 트랙 재실행 없이 변조 신호 보충")


def test_parallel_path_survives_github_failure():
    """보충 조회가 실패해도 스캔 전체가 죽으면 안 된다."""
    monkey, calls = {}, []
    _stub_tracks(monkey, SHA, calls)

    from rootkeepers.collectors.github import github_collector

    original_get_repo = github_collector.get_repo

    def boom(owner_repo):
        raise RuntimeError("GitHub API Rate Limit 초과")

    github_collector.get_repo = boom
    try:
        report = lineage.collect_release_lineage_report("widget", "1.2.3")
    finally:
        _restore(monkey)
        github_collector.get_repo = original_get_repo

    data = report["tracks"]["github"]["data"]
    assert data["workflow_modified_before_release"] is None, data
    assert report["tracks"]["github"]["status"] == "SUCCESS", report["tracks"]["github"]
    print("PASS  병렬 경로: 보충 조회 실패해도 스캔 유지")


def test_merge_baseline_keeps_github_track_releases():
    """GitHub 트랙이 수집한 거버넌스 기준선이 살아남아야 한다."""
    existing = {
        "github": {
            "source": "github_tags",
            "releases": [{
                "tag": "v1.2.2",
                "git_head": "b" * 40,
                "commit": {"author_login": "maintainer", "pull_requests": [{"number": 7}]},
                "tags": [{"name": "v1.2.2", "sha": "b" * 40}],
                "workflow_entry_points": [WORKFLOW],
            }],
        },
    }
    collected = {
        "npm": {"publishers": ["maintainer"], "releases": [{"version": "1.2.2"}]},
        "github": {"releases": [{"version": "1.2.2", "workflow_entry_points": [WORKFLOW]}]},
    }

    merged = _merge_baseline(existing, collected)
    releases = merged["github"]["releases"]
    assert len(releases) == 2, releases
    # 거버넌스 근거(PR·리뷰어·author)가 보존돼야 orphan_release/unreviewed가 산다
    assert any(r.get("commit", {}).get("pull_requests") for r in releases), releases
    # sigstore 기반 워크플로 기준선도 함께 남아야 한다
    assert any(r.get("version") == "1.2.2" for r in releases), releases
    assert merged["npm"] == collected["npm"], merged["npm"]
    assert merged["github"]["source"] == "github_tags+sigstore_provenance", merged["github"]
    print("PASS  기준선 병합: GitHub 트랙 기준선 보존")


def test_merge_baseline_without_existing_github():
    """기존 기준선이 없거나 비어 있으면 수집한 것만 그대로 쓴다."""
    collected = {"npm": {}, "github": {"releases": [{"version": "1.2.2"}]}}
    assert _merge_baseline(None, collected) == collected
    assert _merge_baseline({}, collected) == collected
    assert _merge_baseline({"github": {"releases": []}}, collected) == collected
    print("PASS  기준선 병합: 기존 기준선 없음 처리")


if __name__ == "__main__":
    test_sequential_path_has_no_nameerror_and_threads_workflow()
    test_parallel_path_backfills_workflow_modification()
    test_parallel_path_survives_github_failure()
    test_merge_baseline_keeps_github_track_releases()
    test_merge_baseline_without_existing_github()
    print("\n전부 통과했습니다.")

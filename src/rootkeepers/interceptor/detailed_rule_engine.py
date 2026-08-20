"""과거 릴리스 기준선과 현재 증거를 비교해 6개 공급망 규칙을 세부 점수화하는 엔진.

이 모듈은 수집기와 분리된 순수 평가 계층이다. 호출자는 ``current``와
``baseline`` 증거를 전달하고, 이 모듈은 데이터 결측을 패널티로 바꾸지 않고
규칙별 또는 최종 ``UNVERIFIABLE``로 보존한다.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final
from datetime import datetime
import re


class RuleBand(str, Enum):
    """개별 규칙 점수의 보안 판정 밴드."""

    PASS = "PASS"
    WARN = "WARN"
    RISK = "RISK"
    UNVERIFIABLE = "UNVERIFIABLE"


class PackageDecision(str, Enum):
    """인터셉터가 설치 요청에 적용하는 최종 결정."""

    PASS = "PASS"
    RISK = "RISK"
    UNVERIFIABLE = "UNVERIFIABLE (RISK)"


class DetailedRuleName(str, Enum):
    """상세 점수화 대상인 6개 공급망 보안 규칙."""

    ORPHAN_RELEASE = "orphan_release"
    UNREVIEWED = "unreviewed"
    WORKFLOW_DRIFT = "workflow_drift"
    OIDC_MISMATCH = "oidc_mismatch"
    UNEXPECTED_BUILDER = "unexpected_builder"
    TAG_IDENTITY_DRIFT = "tag_identity_drift"


@dataclass(frozen=True)
class Signal:
    """하나의 세부 탐지 항목이 규칙 점수에 기여한 결과.

    Attributes:
        identifier: 감사 가능한 세부 검사 식별자.
        points: 해당 검사로 더한 패널티 점수.
        reason: 점수 부여의 보안 근거.
    """

    identifier: str
    points: int
    reason: str


@dataclass(frozen=True)
class DetailedRuleResult:
    """한 규칙의 세부 신호, 누적 점수, 밴드 결과.

    Attributes:
        rule: 평가한 6개 규칙 중 하나.
        score: 0~100으로 제한한 규칙별 점수.
        band: PASS, WARN, RISK 또는 UNVERIFIABLE 밴드.
        signals: 실제로 확인된 세부 위반 신호 목록.
        reason: 증거 부족 또는 평가 결과의 요약 설명.
    """

    rule: DetailedRuleName
    score: int
    band: RuleBand
    signals: tuple[Signal, ...]
    reason: str


@dataclass(frozen=True)
class DetailedScoringPolicy:
    """가중 합산·동시발동 보너스·보고용 임계값을 보관하는 정책.

    Attributes:
        weights: 규칙별 점수를 최종 합산에 반영하는 가중치.
        corroboration_bonus: 두 번째 WARN 이상 규칙부터 규칙당 추가할 점수.
        block_threshold: 대시보드에서 위험도를 분류할 가중 점수 임계값.
        minimum_corroborating_rules: 보고용 최소 독립 발동 규칙 수.
    """

    weights: Mapping[DetailedRuleName, float]
    corroboration_bonus: int = 10
    block_threshold: int = 75
    minimum_corroborating_rules: int = 2
    minimum_risk_band_rules: int = 2


DEFAULT_DETAILED_POLICY: Final[DetailedScoringPolicy] = DetailedScoringPolicy(
    weights={
        DetailedRuleName.ORPHAN_RELEASE: 0.7,
        DetailedRuleName.UNREVIEWED: 0.6,
        DetailedRuleName.WORKFLOW_DRIFT: 0.8,
        DetailedRuleName.OIDC_MISMATCH: 1.0,
        DetailedRuleName.UNEXPECTED_BUILDER: 0.9,
        DetailedRuleName.TAG_IDENTITY_DRIFT: 0.6,
    },
    corroboration_bonus=10,
    block_threshold=75,
    minimum_corroborating_rules=2,
    minimum_risk_band_rules=2,
)


def evaluate_detailed_evidence(
    evidence: Mapping[str, Any],
    policy: DetailedScoringPolicy = DEFAULT_DETAILED_POLICY,
) -> dict[str, Any]:
    """현재 릴리스와 과거 기준선 증거로 6개 규칙 및 최종 차단 결정을 계산한다.

    Args:
        evidence: ``orphan_release``부터 ``tag_identity_drift``까지의 규칙별 증거 사전.
        policy: 가중치, 동시발동 보너스, 차단 임계값 정책.

    Returns:
        규칙별 점수·밴드·신호와 최종 score/verdict를 포함한 JSON 호환 사전.
    """
    _validate_policy(policy)
    results = (
        _evaluate_orphan_release(_mapping(evidence, "orphan_release")),
        _evaluate_unreviewed(_mapping(evidence, "unreviewed")),
        _evaluate_workflow_drift(_mapping(evidence, "workflow_drift")),
        _evaluate_oidc_mismatch(_mapping(evidence, "oidc_mismatch")),
        _evaluate_unexpected_builder(_mapping(evidence, "unexpected_builder")),
        _evaluate_tag_identity_drift(_mapping(evidence, "tag_identity_drift")),
    )
    activated = [result for result in results if result.band in {RuleBand.WARN, RuleBand.RISK}]
    weighted_score = sum(result.score * policy.weights[result.rule] for result in results)
    corroboration = max(0, len(activated) - 1) * policy.corroboration_bonus
    score = min(100, round(weighted_score + corroboration))
    decision = _package_decision(score, activated, results, policy)
    return {
        "score": score,
        "verdict": decision.value,
        "threshold": policy.block_threshold,
        "corroboration": {
            "activated_rule_count": len(activated),
            "risk_band_rule_count": sum(result.band is RuleBand.RISK for result in activated),
            "bonus": corroboration,
            "minimum_required": policy.minimum_corroborating_rules,
            "minimum_risk_band_required": policy.minimum_risk_band_rules,
        },
        "reason": _decision_reason(decision, score, results, policy),
        "rules": [
            _serialize_rule_result(result, _mapping(evidence, result.rule.value))
            for result in results
        ],
    }


def evidence_from_lineage(report: Mapping[str, Any]) -> dict[str, Any]:
    """현재 통합 수집 보고서에서 가능한 증거만 상세 엔진 입력으로 변환한다.

    Args:
        report: npm, GitHub, Sigstore 트랙을 담은 현재 릴리스 계보 보고서.

    Returns:
        과거 기준선이 아직 없으면 해당 비교 규칙이 UNVERIFIABLE이 되도록 만든
        세부 증거 사전.
    """
    tracks = report.get("tracks") if isinstance(report.get("tracks"), Mapping) else {}
    github = tracks.get("github") if isinstance(tracks, Mapping) else None
    sigstore = tracks.get("sigstore") if isinstance(tracks, Mapping) else None
    github_data = _mapping(github, "data")
    commit = _mapping(github_data, "commit")
    commit_exists = commit.get("found") if isinstance(commit.get("found"), bool) else None
    pull_requests = commit.get("pull_requests") if isinstance(commit.get("pull_requests"), list) else None
    sigstore_data = _mapping(sigstore, "data")
    predicate = _mapping(sigstore_data, "slsa_predicate")
    oidc = _mapping(sigstore_data, "fulcio_oidc")
    pipeline = _mapping(report, "pipeline")
    github_lookup = _mapping(_mapping(pipeline, "npm_to_github"), "github_lookup")
    # npm의 gitHead가 비어있고 Sigstore provenance도 대체 커밋을 못 찾으면
    # GitHub 트랙 자체가 SKIPPED되어 commit_exists가 None으로 남는다. 그런데
    # 저장소는 알고 있는데(owner_repo는 확인됨) 어디서도 gitHead 후보를 못
    # 찾았다는 건, 특정 SHA를 조회했다가 404를 받은 것과 같은 수준의 확정적
    # 증거다 (실제 ua-parser-js 사고의 ``gitHead: None`` 패턴과 정확히 일치).
    if commit_exists is None and github_lookup.get("owner_repo") and not github_lookup.get("git_head"):
        commit_exists = False
    npm_data = _mapping(_mapping(tracks, "npm"), "data")
    artifact = npm_data.get("artifact")
    npm_artifact = artifact if isinstance(artifact, Mapping) else {}
    baseline_root = _mapping(report, "baseline")
    npm_baseline = _mapping(baseline_root, "npm")
    github_baseline = _mapping(baseline_root, "github")
    if not npm_baseline and any(key in baseline_root for key in ("publishers", "attestations_present", "releases")):
        npm_baseline = baseline_root
    # Accept the track-local layout too; it makes callers using older lineage
    # reports forward-compatible while new reports use the root contract.
    if not npm_baseline:
        npm_baseline = _mapping(_mapping(_mapping(tracks, "npm"), "data"), "baseline")
    if not github_baseline:
        github_baseline = _mapping(github_data, "baseline")
    historical_releases = _mappings(github_baseline.get("releases"))
    npm_releases = _mappings(npm_baseline.get("releases"))
    historical_prs = [
        _mappings(_mapping(release, "commit").get("pull_requests"))
        for release in historical_releases
        if isinstance(_mapping(release, "commit").get("pull_requests"), list)
    ]
    historical_pr_flags = [bool(prs) for prs in historical_prs]
    historical_review_flags = [
        any(_human_approval_count(pr) > 0 for pr in prs)
        # An observed release with no linked PR is meaningful historical
        # evidence: its review-governance baseline is False, not unknown.
        for prs in historical_prs
    ]
    baseline_entry_points = [
        entry
        for release in historical_releases
        for entry in _strings(release.get("workflow_entry_points"))
    ]
    historical_authors = [
        _string(_mapping(release, "commit").get("author_login"))
        or _string(_mapping(release, "commit").get("author"))
        for release in historical_releases
    ]
    historical_authors = [author for author in historical_authors if author]
    historical_tags = [
        _string(tag.get("name"))
        for release in historical_releases
        for tag in _mappings(release.get("tags"))
        if _string(tag.get("name"))
    ]
    current_tags = tuple(
        _string(tag.get("name")) for tag in _mappings(github_data.get("tags")) if _string(tag.get("name"))
    )
    historical_sigstore = [
        _mapping(_mapping(release, "sigstore"), "data")
        for release in npm_releases
    ]
    historical_predicates = [_mapping(item, "slsa_predicate") for item in historical_sigstore]
    historical_oidc = [_mapping(item, "fulcio_oidc") for item in historical_sigstore]
    baseline_builder = _first_nonempty_string(predicate.get("builder_id") for predicate in historical_predicates)
    baseline_builder_entry = _first_nonempty_string(predicate.get("workflow_path") for predicate in historical_predicates)
    baseline_oidc_identity = _first_nonempty_string(identity.get("subject") for identity in historical_oidc)
    current_prs = _mappings(pull_requests)
    current_human_approvals = sum(_human_approval_count(pr) for pr in _mappings(pull_requests))
    current_attestation = _attestation_present(npm_artifact)
    evidence = {
        "orphan_release": {
            "commit_exists": commit_exists,
            "has_linked_pr": None if pull_requests is None else bool(pull_requests),
            "governance_pr_baseline": _baseline_majority(historical_pr_flags),
            "direct_push_prohibited": _baseline_majority(historical_pr_flags),
            "new_author": _current_author_is_new(commit, historical_authors),
            "commit_signed": commit.get("signed") if isinstance(commit.get("signed"), bool) else None,
            "immediate_tag": _immediate_release_tag(npm_data, commit, github_data),
        },
        "unreviewed": {
            "has_pr": None if pull_requests is None else bool(pull_requests),
            "review_governance_baseline": _baseline_majority(historical_review_flags),
            "human_approval_count": current_human_approvals if pull_requests is not None else None,
            "self_merge": _has_self_merge(current_prs),
            "bot_only_approval": _has_bot_only_approval(current_prs),
            "external_approval": _has_external_approval(current_prs),
        },
        "workflow_drift": {
            "baseline_entry_points": baseline_entry_points,
            "current_entry_point": predicate.get("workflow_path"),
            "workflow_modified_before_release": github_data.get("workflow_modified_before_release"),
        },
        "oidc_mismatch": {
            "attestation_present": current_attestation,
            "baseline_attestation_present": _baseline_majority(_booleans(npm_baseline.get("attestations_present"))),
            "npm_repository": npm_artifact.get("repo_url"),
            "oidc_repository": oidc.get("subject_repo"),
            "provenance_entry_point": predicate.get("workflow_path"),
            "oidc_workflow": oidc.get("subject_workflow"),
            "issuer": oidc.get("issuer"),
            "expected_issuers": ["https://token.actions.githubusercontent.com"],
            # Missing builder identity is unknown, not suspicious. A present
            # identity outside the documented GitHub-hosted runner namespace
            # is surfaced as a separate low-weight signal.
            "official_runner": _is_official_github_actions_runner(
                predicate.get("builder_id")
            ),
        },
        "unexpected_builder": {
            "baseline_attestations": npm_baseline.get("attestations_present"),
            "current_attestation_present": current_attestation,
            "baseline_builder_id": baseline_builder,
            "current_builder_id": predicate.get("builder_id"),
            "baseline_entry_point": baseline_builder_entry,
            "current_entry_point": predicate.get("workflow_path"),
        },
        "tag_identity_drift": {
            "baseline_publishers": npm_baseline.get("publishers"),
            "current_publisher": npm_artifact.get("publisher"),
            "baseline_git_or_tag_present": bool(historical_releases),
            # npm's dist.gitHead is optional.  Lineage may have safely
            # recovered the same build commit from signed SLSA provenance for
            # the GitHub lookup; that is valid git identity evidence too.
            "current_git_or_tag_present": (
                bool(npm_artifact.get("git_head"))
                or bool(github_lookup.get("git_head"))
                or bool(github_data.get("tags"))
            ),
            "baseline_oidc_identity": baseline_oidc_identity,
            "current_oidc_identity": oidc.get("subject"),
            "tag_pattern_mismatch": _tag_pattern_mismatch(historical_tags, current_tags),
        },
    }
    return _annotate_evidence_status(evidence)


def _annotate_evidence_status(evidence: dict[str, Any]) -> dict[str, Any]:
    """Expose incomplete/approximate evidence instead of hiding it in PASS.

    ``PARTIAL`` means the rule's core decision was possible but one or more
    secondary signals could not be checked. ``UNVERIFIABLE`` is assigned later
    when the evaluator lacks a required core input.
    """
    optional_fields = {
        "orphan_release": {
            "direct_push_prohibited": "branch-protection policy unavailable",
            "new_author": "historical commit authors unavailable",
            "commit_signed": "current commit signature unavailable",
            "immediate_tag": "tag/publish timing unavailable",
        },
        "unreviewed": {
            "self_merge": "PR author or merger unavailable",
            "bot_only_approval": "reviewer identity unavailable",
            "external_approval": "reviewer association unavailable",
        },
        "workflow_drift": {
            "workflow_modified_before_release": "release-commit workflow diff unavailable",
        },
        "oidc_mismatch": {
            "npm_repository": "npm repository identity unavailable",
            "oidc_repository": "OIDC repository identity unavailable",
            "provenance_entry_point": "provenance workflow path unavailable",
            "oidc_workflow": "OIDC workflow identity unavailable",
            "issuer": "OIDC issuer unavailable",
            "official_runner": "provenance builder.id unavailable",
        },
        "unexpected_builder": {
            "baseline_builder_id": "historical SLSA builder.id unavailable",
            "current_builder_id": "current SLSA builder.id unavailable",
            "baseline_entry_point": "historical provenance workflow path unavailable",
            "current_entry_point": "current provenance workflow path unavailable",
        },
        "tag_identity_drift": {
            "baseline_oidc_identity": "historical OIDC subject unavailable",
            "current_oidc_identity": "current OIDC subject unavailable",
            "tag_pattern_mismatch": "comparable Git tag names unavailable",
        },
    }
    for rule_id, fields in optional_fields.items():
        rule = evidence.get(rule_id)
        if not isinstance(rule, dict):
            continue
        limitations = [
            message for field, message in fields.items()
            if rule.get(field) is None or rule.get(field) == ""
        ]
        rule["evidence_status"] = "PARTIAL" if limitations else "COMPLETE"
        rule["evidence_limitations"] = limitations
    return evidence


def _evaluate_orphan_release(evidence: Mapping[str, Any]) -> DetailedRuleResult:
    """gitHead 실존 여부를 최우선으로, PR 부재·보호 우회·즉시 태그·새
    author·서명 결측을 점수화한다.

    Args:
        evidence: 현재 커밋과 과거 거버넌스 기준선 증거.

    Returns:
        Orphan Release 규칙의 점수·밴드·세부 신호.
    """
    # npm이 배포한 gitHead가 GitHub에 아예 존재하지 않으면, 이 저장소의 PR
    # 사용 관행(governance_pr_baseline)과 무관하게 그 자체로 결정적 위반
    # 신호다. PR 없이 직접 push하는 저장소도 "존재하는 커밋"을 배포하는 것과,
    # "가리키는 커밋 자체가 없는" 배포는 전혀 다른 위험 수준이므로 baseline
    # 게이트보다 먼저 판단한다.
    if evidence.get("commit_exists") is False:
        return _result(
            DetailedRuleName.ORPHAN_RELEASE,
            [Signal(
                "commit_not_found",
                100,
                "저장소는 확인되지만, 이 릴리스의 gitHead가 GitHub에 존재하지 않거나"
                " (gitHead 값이 있는데 커밋을 못 찾음) npm/Sigstore 어디에도 gitHead"
                " 후보 자체가 없습니다 (dangling / missing commit).",
            )],
            "이 릴리스의 git 커밋을 GitHub에서 확인할 수 없습니다.",
        )
    if evidence.get("has_linked_pr") is None or evidence.get("governance_pr_baseline") is None:
        return _unverifiable(DetailedRuleName.ORPHAN_RELEASE, "PR 거버넌스 기준선 또는 현재 PR 연결 정보가 없습니다.")
    if evidence.get("governance_pr_baseline") is False:
        return _pass(DetailedRuleName.ORPHAN_RELEASE, "과거 릴리스가 PR 없이 배포된 패턴이므로 PR 부재를 위반으로 보지 않습니다.")
    signals: list[Signal] = []
    if evidence.get("has_linked_pr") is False:
        signals.append(Signal("missing_pr", 70, "PR 기록 없이 릴리스 커밋이 생성됐습니다."))
        if evidence.get("direct_push_prohibited") is True:
            signals.append(Signal("branch_protection_bypass", 20, "직접 push 금지 기준선과 다른 직접 커밋입니다."))
        if evidence.get("immediate_tag") is True:
            signals.append(Signal("immediate_tag", 10, "커밋 직후 태그·릴리스가 생성됐습니다."))
        if evidence.get("new_author") is True:
            signals.append(Signal("new_author", 20, "최근 메인테이너 기준선에 없는 author가 릴리스를 만들었습니다."))
        if evidence.get("commit_signed") is False:
            signals.append(Signal("unsigned_commit", 10, "서명 커밋 기준선에 반해 현재 커밋 서명이 없습니다."))
    return _result(DetailedRuleName.ORPHAN_RELEASE, signals, "PR 거버넌스 기준선과 비교를 완료했습니다.")


def _evaluate_unreviewed(evidence: Mapping[str, Any]) -> DetailedRuleResult:
    """사람 승인·self-merge·봇 승인·외부인 승인을 점수화한다.

    Args:
        evidence: PR 리뷰 및 과거 리뷰 거버넌스 기준선 증거.

    Returns:
        Unreviewed 규칙의 점수·밴드·세부 신호.
    """
    if evidence.get("has_pr") is None or evidence.get("review_governance_baseline") is None:
        return _unverifiable(DetailedRuleName.UNREVIEWED, "PR 리뷰 거버넌스 기준선 또는 현재 PR 정보가 없습니다.")
    if evidence.get("has_pr") is False:
        return _pass(DetailedRuleName.UNREVIEWED, "연결된 PR이 없어 Unreviewed 규칙은 적용하지 않습니다.")
    if evidence.get("review_governance_baseline") is False:
        return _pass(DetailedRuleName.UNREVIEWED, "과거 릴리스의 사람 승인 기준선이 없어 단독 미승인을 위반으로 보지 않습니다.")
    human_approvals = evidence.get("human_approval_count")
    if not isinstance(human_approvals, int):
        return _unverifiable(DetailedRuleName.UNREVIEWED, "사람 승인 수를 확인할 수 없습니다.")
    signals: list[Signal] = []
    if human_approvals == 0:
        signals.append(Signal("no_human_approval", 30, "사람 승인 없이 PR이 머지됐습니다."))
        if evidence.get("self_merge") is True:
            signals.append(Signal("self_merge", 40, "PR 작성자가 사람 승인 없이 직접 머지했습니다."))
        if evidence.get("bot_only_approval") is True:
            signals.append(Signal("bot_only_approval", 20, "사람 승인 없이 봇 승인만 존재합니다."))
        if evidence.get("external_approval") is True:
            signals.append(Signal("external_approval", 20, "저장소와 무관한 계정이 승인했습니다."))
    return _result(DetailedRuleName.UNREVIEWED, signals, "PR 승인 기준선과 비교를 완료했습니다.")


def _evaluate_workflow_drift(evidence: Mapping[str, Any]) -> DetailedRuleResult:
    """과거 워크플로 기준선 대비 부재·경로 이탈·직전 수정을 점수화한다.

    Args:
        evidence: 현재 entry point와 최근 릴리스 워크플로 기준선 증거.

    Returns:
        Workflow Drift 규칙의 점수·밴드·세부 신호.
    """
    baseline = _strings(evidence.get("baseline_entry_points"))
    if not baseline:
        return _unverifiable(DetailedRuleName.WORKFLOW_DRIFT, "최근 릴리스의 PRESENT 워크플로 기준선을 만들 수 없습니다.")
    current = _string(evidence.get("current_entry_point"))
    signals: list[Signal] = []
    if not current:
        signals.append(Signal("workflow_absent", 80, "과거에는 존재하던 provenance 워크플로가 현재 릴리스에 없습니다."))
        return _result(DetailedRuleName.WORKFLOW_DRIFT, signals, "워크플로 부재를 확인했습니다.")
    if current not in baseline or not current.startswith(".github/workflows/"):
        signals.append(Signal("entry_point_drift", 50, "기준선과 다른 또는 외부 워크플로 경로가 사용됐습니다."))
    elif evidence.get("workflow_modified_before_release") is True:
        signals.append(Signal("workflow_modified_before_release", 20, "릴리스 직전 워크플로 파일이 수정됐습니다."))
    return _result(DetailedRuleName.WORKFLOW_DRIFT, signals, "워크플로 경로 기준선과 비교를 완료했습니다.")


def _evaluate_oidc_mismatch(evidence: Mapping[str, Any]) -> DetailedRuleResult:
    """attestation·저장소·워크플로·issuer·runner의 절대 교차검증을 점수화한다.

    Args:
        evidence: npm, provenance, Fulcio OIDC에서 얻은 현재 릴리스 증거.

    Returns:
        OIDC Mismatch 규칙의 점수·밴드·세부 신호.
    """
    attestation_present = evidence.get("attestation_present")
    if attestation_present is None:
        return _unverifiable(DetailedRuleName.OIDC_MISMATCH, "attestation 존재 여부를 확인할 수 없습니다.")
    if attestation_present is False:
        if evidence.get("baseline_attestation_present") is True:
            return _result(DetailedRuleName.OIDC_MISMATCH, [Signal("attestation_missing", 90, "과거에는 존재하던 attestation이 현재 릴리스에 없습니다.")], "attestation 플립을 확인했습니다.")
        return _unverifiable(DetailedRuleName.OIDC_MISMATCH, "attestation 기준선이 없어 부재를 위반으로 단정할 수 없습니다.")
    signals: list[Signal] = []
    npm_repository = _normalize_repository(_string(evidence.get("npm_repository")))
    oidc_repository = _normalize_repository(_string(evidence.get("oidc_repository")))
    if npm_repository and oidc_repository and npm_repository != oidc_repository:
        signals.append(Signal("repository_mismatch", 70, "npm 저장소와 서명 OIDC 저장소가 다릅니다."))
    entry_point = _string(evidence.get("provenance_entry_point"))
    oidc_workflow = _string(evidence.get("oidc_workflow"))
    if entry_point and oidc_workflow and entry_point != oidc_workflow:
        signals.append(Signal("workflow_identity_mismatch", 50, "provenance 워크플로와 인증서 워크플로 신원이 다릅니다."))
    expected_issuers = _strings(evidence.get("expected_issuers"))
    issuer = _string(evidence.get("issuer"))
    if expected_issuers and issuer and issuer not in expected_issuers:
        signals.append(Signal("issuer_mismatch", 40, "정책에서 신뢰하지 않는 OIDC issuer가 사용됐습니다."))
    if evidence.get("official_runner") is False:
        signals.append(Signal("unofficial_runner", 10, "공식 기준선과 다른 runner 환경에서 빌드됐습니다."))
    if not signals and not any((npm_repository, oidc_repository, entry_point, oidc_workflow, issuer)):
        return _unverifiable(DetailedRuleName.OIDC_MISMATCH, "attestation은 있으나 교차검증 가능한 신원 필드가 없습니다.")
    return _result(DetailedRuleName.OIDC_MISMATCH, signals, "서명 신원과 provenance를 절대 교차검증했습니다.")


def _evaluate_unexpected_builder(evidence: Mapping[str, Any]) -> DetailedRuleResult:
    """attestation 존재율과 builder·entry point 변화를 과거 대비 점수화한다.

    Args:
        evidence: 현재 provenance와 최근 릴리스 attestation 기준선 증거.

    Returns:
        Unexpected Builder 규칙의 점수·밴드·세부 신호.
    """
    baseline_attestations = _booleans(evidence.get("baseline_attestations"))
    if not baseline_attestations or sum(baseline_attestations) / len(baseline_attestations) < 0.4:
        return _unverifiable(DetailedRuleName.UNEXPECTED_BUILDER, "최근 릴리스의 attestation PRESENT 비율이 40% 미만입니다.")
    if evidence.get("current_attestation_present") is None:
        return _unverifiable(DetailedRuleName.UNEXPECTED_BUILDER, "현재 attestation 존재 여부를 확인할 수 없습니다.")
    signals: list[Signal] = []
    if evidence.get("current_attestation_present") is False:
        signals.append(Signal("attestation_flip", 60, "attestation 기준선이 성립하는데 현재 릴리스에는 없습니다."))
        return _result(DetailedRuleName.UNEXPECTED_BUILDER, signals, "attestation 플립을 확인했습니다.")
    baseline_builder = _normalize_builder(_string(evidence.get("baseline_builder_id")))
    current_builder = _normalize_builder(_string(evidence.get("current_builder_id")))
    builder_changed = bool(baseline_builder and current_builder and baseline_builder != current_builder)
    if builder_changed:
        signals.append(Signal("builder_changed", 40, "직전 PRESENT 릴리스와 builder.id가 다릅니다."))
    baseline_entry = _string(evidence.get("baseline_entry_point"))
    current_entry = _string(evidence.get("current_entry_point"))
    if not builder_changed and baseline_entry and current_entry and baseline_entry != current_entry:
        signals.append(Signal("entry_point_changed", 25, "builder는 같지만 provenance 진입점이 바뀌었습니다."))
    if not baseline_builder and not baseline_entry:
        # npm's registry baseline deliberately contains only publisher and
        # attestation presence.  When the current attestation is present, that
        # is sufficient to evaluate the flip branch as a clean result; do not
        # incorrectly turn a verified all-present history into UNVERIFIABLE.
        return _pass(DetailedRuleName.UNEXPECTED_BUILDER, "attestation 존재 기준선과 현재 릴리스를 비교했으며 builder 식별자는 제공되지 않았습니다.")
    return _result(DetailedRuleName.UNEXPECTED_BUILDER, signals, "builder와 provenance 진입점 기준선과 비교를 완료했습니다.")


def _evaluate_tag_identity_drift(evidence: Mapping[str, Any]) -> DetailedRuleResult:
    """배포자·새 신원·gitHead/태그·OIDC 신원·태그 패턴 변화를 점수화한다.

    Args:
        evidence: 현재 배포 신원과 최근 5개 릴리스 기준선 증거.

    Returns:
        Tag/Identity Drift 규칙의 점수·밴드·세부 신호.
    """
    baseline_publishers = _strings(evidence.get("baseline_publishers"))
    current_publisher = _string(evidence.get("current_publisher"))
    if not baseline_publishers or not current_publisher:
        return _unverifiable(DetailedRuleName.TAG_IDENTITY_DRIFT, "현재 또는 과거 배포자 신원이 없어 비교할 수 없습니다.")
    signals: list[Signal] = []
    allowed_publishers = set(_strings(evidence.get("allowed_publishers")))
    if current_publisher not in baseline_publishers and current_publisher not in allowed_publishers:
        publisher_points = 40
        if evidence.get("publisher_has_no_history") is True:
            publisher_points = min(50, publisher_points + 30)
        signals.append(Signal("publisher_drift", publisher_points, "최근 배포자 기준선과 다른 신원이 배포했습니다."))
    if evidence.get("baseline_git_or_tag_present") is True and evidence.get("current_git_or_tag_present") is False:
        signals.append(Signal("git_tag_flip", 30, "평소 존재하던 gitHead 또는 태그가 이번 릴리스에서만 결측입니다."))
    baseline_oidc = _string(evidence.get("baseline_oidc_identity"))
    current_oidc = _string(evidence.get("current_oidc_identity"))
    if baseline_oidc and current_oidc and baseline_oidc != current_oidc:
        signals.append(Signal("oidc_identity_drift", 25, "직전 PRESENT 릴리스와 Fulcio OIDC 신원이 다릅니다."))
    if evidence.get("tag_pattern_mismatch") is True:
        signals.append(Signal("tag_pattern_drift", 10, "기존 태그 명명 패턴과 다른 태그가 사용됐습니다."))
    return _result(DetailedRuleName.TAG_IDENTITY_DRIFT, signals, "배포자·태그·신원 기준선과 비교를 완료했습니다.")


def _result(rule: DetailedRuleName, signals: Sequence[Signal], reason: str) -> DetailedRuleResult:
    """세부 신호 합계에서 0~100 점수와 밴드를 생성한다.

    Args:
        rule: 결과를 만들 보안 규칙.
        signals: 확인된 세부 위반 신호.
        reason: 평가 완료 근거.

    Returns:
        점수 상한과 PASS/WARN/RISK 밴드가 적용된 규칙 결과.
    """
    score = min(100, sum(signal.points for signal in signals))
    band = RuleBand.RISK if score >= 60 else RuleBand.WARN if score >= 30 else RuleBand.PASS
    return DetailedRuleResult(rule, score, band, tuple(signals), reason)


def _pass(rule: DetailedRuleName, reason: str) -> DetailedRuleResult:
    """위반 신호가 없는 규칙 PASS 결과를 만든다.

    Args:
        rule: PASS 처리할 보안 규칙.
        reason: PASS 근거.

    Returns:
        0점 PASS 규칙 결과.
    """
    return DetailedRuleResult(rule, 0, RuleBand.PASS, (), reason)


def _unverifiable(rule: DetailedRuleName, reason: str) -> DetailedRuleResult:
    """핵심 증거가 없어 감점하지 않는 UNVERIFIABLE 규칙 결과를 만든다.

    Args:
        rule: 검증할 수 없는 보안 규칙.
        reason: 필요한 기준선 또는 현재 증거가 없는 이유.

    Returns:
        0점 UNVERIFIABLE 규칙 결과.
    """
    return DetailedRuleResult(rule, 0, RuleBand.UNVERIFIABLE, (), reason)


def _package_decision(
    score: int,
    activated: Sequence[DetailedRuleResult],
    results: Sequence[DetailedRuleResult],
    policy: DetailedScoringPolicy,
) -> PackageDecision:
    """fail-closed 원칙으로 최종 설치 결정을 만든다.

    Args:
        score: 가중치와 corroboration을 반영한 최종 점수.
        activated: WARN 또는 RISK 밴드인 독립 규칙 목록.
        results: 6개 규칙의 전체 결과.
        policy: 차단 임계값과 최소 동시발동 수 정책.

    Returns:
        RISK 밴드 하나 또는 검증 불가 규칙 하나를 보류하는 결정.
    """
    if any(result.band is RuleBand.UNVERIFIABLE for result in results):
        return PackageDecision.UNVERIFIABLE
    if any(result.band is RuleBand.RISK for result in activated):
        return PackageDecision.RISK
    return PackageDecision.PASS


def _decision_reason(
    decision: PackageDecision,
    score: int,
    results: Sequence[DetailedRuleResult],
    policy: DetailedScoringPolicy,
) -> str:
    """최종 점수와 규칙 밴드에 대한 사람이 읽을 수 있는 한국어 근거를 만든다.

    Args:
        decision: 최종 설치 결정.
        score: 최종 가중 점수.
        results: 규칙별 평가 결과.
        policy: 임계값과 동시발동 정책.

    Returns:
        감사 로그에 남길 최종 결정 근거 문자열.
    """
    active_names = [result.rule.value for result in results if result.band in {RuleBand.WARN, RuleBand.RISK}]
    unverifiable_names = [result.rule.value for result in results if result.band is RuleBand.UNVERIFIABLE]
    if decision is PackageDecision.RISK:
        risk_names = [result.rule.value for result in results if result.band is RuleBand.RISK]
        return f"fail-closed 정책: RISK 밴드 규칙 {', '.join(risk_names)}가 하나 이상 확인되어 설치를 차단합니다 (감사용 점수 {score}, 기준 {policy.block_threshold})."
    if decision is PackageDecision.UNVERIFIABLE:
        return f"fail-closed 정책: 검증 불가 규칙 {', '.join(unverifiable_names)}의 현재 증거나 과거 기준선이 없어 UNVERIFIABLE (RISK)로 설치를 보류합니다."
    if active_names:
        return f"WARN 신호만 확인되어 설치를 허용합니다: {', '.join(active_names)}"
    return "평가 가능한 규칙에서 위험 신호가 확인되지 않았습니다."


def _serialize_rule_result(
    result: DetailedRuleResult, evidence: Mapping[str, Any]
) -> dict[str, Any]:
    """규칙 결과를 JSON 보고서에 넣을 수 있는 사전으로 변환한다.

    Args:
        result: 직렬화할 상세 규칙 결과.

    Returns:
        점수, 밴드, 세부 신호, 근거를 가진 JSON 호환 사전.
    """
    limitations = _strings(evidence.get("evidence_limitations"))
    evidence_status = (
        "UNVERIFIABLE"
        if result.band is RuleBand.UNVERIFIABLE
        else _string(evidence.get("evidence_status")) or "COMPLETE"
    )
    return {
        "id": result.rule.value,
        "score": result.score,
        "band": result.band.value,
        "state": "MATCH" if result.score else "UNVERIFIABLE" if result.band is RuleBand.UNVERIFIABLE else "NO_MATCH",
        "reason": result.reason,
        "evidence_status": evidence_status,
        "evidence_limitations": list(limitations),
        "signals": [
            {"id": signal.identifier, "points": signal.points, "reason": signal.reason}
            for signal in result.signals
        ],
    }


def _validate_policy(policy: DetailedScoringPolicy) -> None:
    """상세 점수 정책의 가중치와 임계값 범위를 검증한다.

    Args:
        policy: 검증할 상세 점수 정책.

    Returns:
        None.

    Raises:
        ValueError: 규칙 가중치·임계값·동시발동 수가 안전한 범위를 벗어난 경우.
    """
    if set(policy.weights) != set(DetailedRuleName):
        raise ValueError("6개 규칙 모두에 대한 가중치가 필요합니다.")
    if any(weight < 0 for weight in policy.weights.values()):
        raise ValueError("규칙 가중치는 0 이상이어야 합니다.")
    if not 1 <= policy.block_threshold <= 100:
        raise ValueError("차단 임계값은 1~100 범위여야 합니다.")
    if not 1 <= policy.minimum_corroborating_rules <= len(DetailedRuleName):
        raise ValueError("최소 동시발동 규칙 수가 유효하지 않습니다.")
    if not 1 <= policy.minimum_risk_band_rules <= policy.minimum_corroborating_rules:
        raise ValueError("최소 RISK 밴드 규칙 수가 유효하지 않습니다.")


def _mapping(value: Any, key: str) -> Mapping[str, Any]:
    """매핑에서 중첩 매핑 값을 안전하게 꺼낸다.

    Args:
        value: 조회할 원본 매핑 또는 다른 값.
        key: 꺼낼 중첩 키.

    Returns:
        키의 매핑 값 또는 빈 매핑.
    """
    if not isinstance(value, Mapping):
        return {}
    nested = value.get(key)
    return nested if isinstance(nested, Mapping) else {}


def _string(value: Any) -> str:
    """문자열 증거 값을 안전하게 정규화한다.

    Args:
        value: 문자열일 수 있는 증거 값.

    Returns:
        문자열이면 공백 제거 결과, 아니면 빈 문자열.
    """
    return value.strip() if isinstance(value, str) else ""


def _strings(value: Any) -> tuple[str, ...]:
    """문자열 시퀀스 증거를 빈 값 없이 정규화한다.

    Args:
        value: 문자열 목록일 수 있는 증거 값.

    Returns:
        비어 있지 않은 문자열 튜플.
    """
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return tuple(item.strip() for item in value if isinstance(item, str) and item.strip())


def _booleans(value: Any) -> tuple[bool, ...]:
    """불리언 시퀀스를 기준선 존재율 계산용으로 정규화한다.

    Args:
        value: 불리언 목록일 수 있는 증거 값.

    Returns:
        실제 불리언 값만 가진 튜플.
    """
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return tuple(item for item in value if isinstance(item, bool))


def _mappings(value: Any) -> tuple[Mapping[str, Any], ...]:
    """Return only mapping members of an untrusted JSON list."""
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return tuple(item for item in value if isinstance(item, Mapping))


def _baseline_majority(values: Sequence[bool]) -> bool | None:
    """Return a conservative 40% historical-policy threshold, or unknown."""
    if not values:
        return None
    return sum(values) / len(values) >= 0.4


def _human_approval_count(pull_request: Mapping[str, Any]) -> int:
    """Count non-bot APPROVED reviews in collector-normalized PR evidence."""
    count = 0
    for review in _mappings(pull_request.get("reviewers")):
        login = _string(review.get("login")).lower()
        if review.get("approved") is True and not login.endswith("[bot]"):
            count += 1
    return count


def _attestation_present(artifact: Mapping[str, Any]) -> bool | None:
    """Interpret the npm collector's explicit PRESENT/ABSENT enum only."""
    value = artifact.get("attestation")
    if value == "PRESENT":
        return True
    if value == "ABSENT":
        return False
    return None


def _is_official_github_actions_runner(builder_id: Any) -> bool | None:
    """Classify the known GitHub-hosted runner builder without guessing."""
    normalized = _normalize_builder(_string(builder_id))
    if not normalized:
        return None
    return normalized.startswith("https://github.com/actions/runner/")


def _first_nonempty_string(values: Sequence[Any] | Any) -> str:
    for value in values:
        normalized = _string(value)
        if normalized:
            return normalized
    return ""


def _current_author_is_new(commit: Mapping[str, Any], historical_authors: Sequence[str]) -> bool | None:
    current = _string(commit.get("author_login")) or _string(commit.get("author"))
    if not current or not historical_authors:
        return None
    return current not in set(historical_authors)


def _has_self_merge(pull_requests: Sequence[Mapping[str, Any]]) -> bool | None:
    if not pull_requests:
        return False
    known = False
    for pull_request in pull_requests:
        author = _string(pull_request.get("author"))
        merged_by = _string(pull_request.get("merged_by"))
        if author and merged_by:
            known = True
            if author == merged_by:
                return True
    return False if known else None


def _has_bot_only_approval(pull_requests: Sequence[Mapping[str, Any]]) -> bool | None:
    approvals = [
        review for pull_request in pull_requests
        for review in _mappings(pull_request.get("reviewers"))
        if review.get("approved") is True
    ]
    if not approvals:
        return False
    return all(_string(review.get("login")).lower().endswith("[bot]") for review in approvals)


def _has_external_approval(pull_requests: Sequence[Mapping[str, Any]]) -> bool | None:
    approvals = [
        review for pull_request in pull_requests
        for review in _mappings(pull_request.get("reviewers"))
        if review.get("approved") is True
    ]
    if not approvals:
        return False
    associations = [_string(review.get("author_association")).upper() for review in approvals]
    if not any(associations):
        return None
    trusted = {"OWNER", "MEMBER", "COLLABORATOR"}
    return any(association and association not in trusted for association in associations)


def _immediate_release_tag(
    npm_data: Mapping[str, Any], commit: Mapping[str, Any], github_data: Mapping[str, Any]
) -> bool | None:
    if not _mappings(github_data.get("tags")):
        return False
    package = _mapping(npm_data, "package")
    published = _string(package.get("published_at"))
    committed = _string(commit.get("timestamp"))
    if not published or not committed:
        return None
    try:
        delta = abs((datetime.fromisoformat(published.replace("Z", "+00:00")) - datetime.fromisoformat(committed.replace("Z", "+00:00"))).total_seconds())
    except ValueError:
        return None
    return delta <= 600


def _tag_pattern_mismatch(baseline_tags: Sequence[str], current_tags: Sequence[str]) -> bool | None:
    if not baseline_tags or not current_tags:
        return None
    def pattern(tag: str) -> str:
        return re.sub(r"\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?", "#", tag.lower())
    baseline_patterns = {pattern(tag) for tag in baseline_tags}
    return all(pattern(tag) not in baseline_patterns for tag in current_tags)


def _normalize_repository(value: str) -> str:
    """저장소 URL 또는 owner/repo 문자열을 비교 가능한 형태로 정규화한다.

    Args:
        value: npm 또는 OIDC provenance가 제공한 저장소 식별자.

    Returns:
        소문자 owner/repo 또는 정규화할 수 없는 경우 빈 문자열.
    """
    cleaned = value.removeprefix("git+").removesuffix(".git").strip("/")
    if "github.com/" in cleaned:
        cleaned = cleaned.split("github.com/", 1)[1]
    parts = [part for part in cleaned.split("/") if part]
    return "/".join(parts[-2:]).lower() if len(parts) >= 2 else ""


def _normalize_builder(value: str) -> str:
    """builder.id의 가변 ref 접미사를 제거해 과거 값과 비교한다.

    Args:
        value: provenance에서 얻은 builder.id 문자열.

    Returns:
        @refs 이후을 제거한 비교용 builder 식별자.
    """
    return value.split("@refs", 1)[0].rstrip("/")


__all__ = [
    "DEFAULT_DETAILED_POLICY",
    "DetailedRuleName",
    "DetailedRuleResult",
    "DetailedScoringPolicy",
    "PackageDecision",
    "RuleBand",
    "Signal",
    "evaluate_detailed_evidence",
    "evidence_from_lineage",
]

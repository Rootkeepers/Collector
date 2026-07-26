"""수집된 공급망 증거의 6개 규칙 판정을 점수와 설치 차단 결정으로 변환하는 평가 모듈.

이 모듈은 npm/GitHub/Sigstore 수집기 자체를 호출하지 않는다. 수집기가 만든
규칙 상태를 입력받아 일관된 패널티, 판정 근거, 최종 설치 정책을 반환하므로
인터셉터와 향후 변조 패키지 테스트가 같은 점수 정책을 공유할 수 있다.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Final, Mapping

from rootkeepers.interceptor.detailed_rule_engine import (
    evaluate_detailed_evidence,
    evidence_from_lineage,
)


class RuleName(str, Enum):
    """점수 평가 대상인 공급망 보안 규칙 이름."""

    ORPHAN_RELEASE = "orphan_release"
    UNREVIEWED = "unreviewed"
    WORKFLOW_DRIFT = "workflow_drift"
    OIDC_MISMATCH = "oidc_mismatch"
    UNEXPECTED_BUILDER = "unexpected_builder"
    TAG_IDENTITY_DRIFT = "tag_identity_drift"


class RuleState(str, Enum):
    """개별 규칙의 증거 기반 판정 상태."""

    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    UNVERIFIABLE = "UNVERIFIABLE"
    NOT_EVALUATED = "NOT_EVALUATED"


class Decision(str, Enum):
    """인터셉터가 설치 요청에 적용할 최종 결정."""

    PASS = "PASS"
    RISK = "RISK"
    UNVERIFIABLE = "UNVERIFIABLE"


class InvalidRuleStateError(ValueError):
    """알 수 없는 규칙 이름 또는 상태가 입력된 경우 발생하는 예외."""


@dataclass(frozen=True)
class ScoringPolicy:
    """규칙별 패널티와 차단 임계값을 보관하는 변경 가능한 정책 객체.

    Attributes:
        penalties: MATCH일 때 규칙별로 더할 패널티 점수.
        block_threshold: 이 점수 이상이면 RISK로 설치를 차단하는 기준.
    """

    penalties: Mapping[RuleName, int]
    block_threshold: int = 60


@dataclass(frozen=True)
class RuleScore:
    """개별 규칙이 최종 점수에 기여한 결과.

    Attributes:
        rule: 평가한 보안 규칙.
        state: 수집 증거에서 계산된 규칙 상태.
        penalty: 해당 상태 때문에 추가된 패널티 점수.
        reason: 사용자와 감사 로그에 남길 한국어 판정 근거.
    """

    rule: RuleName
    state: RuleState
    penalty: int
    reason: str


@dataclass(frozen=True)
class ScoringResult:
    """6개 규칙 점수를 합산한 최종 설치 정책 결과.

    Attributes:
        score: 0~100 범위로 제한된 누적 패널티 점수.
        decision: PASS, RISK 또는 증거 부족의 UNVERIFIABLE 결정.
        threshold: 이번 정책에서 적용한 RISK 차단 임계값.
        rule_scores: 모든 규칙의 개별 점수와 근거.
    """

    score: int
    decision: Decision
    threshold: int
    rule_scores: tuple[RuleScore, ...]

    def to_dict(self) -> dict[str, Any]:
        """점수 결과를 기존 JSON 보고서에 넣을 수 있는 사전으로 변환한다.

        Returns:
            score, verdict, threshold, rules를 포함한 JSON 직렬화 가능 사전.
        """
        return {
            "score": self.score,
            "verdict": self.decision.value,
            "threshold": self.threshold,
            "reason": self.reason(),
            "rules": [
                {
                    "id": item.rule.value,
                    "state": item.state.value,
                    "penalty": item.penalty,
                    "reason": item.reason,
                }
                for item in self.rule_scores
            ],
        }

    def reason(self) -> str:
        """최종 설치 결정에 대한 사람이 읽을 수 있는 한국어 근거를 만든다.

        Returns:
            RISK, PASS 또는 UNVERIFIABLE 결정의 요약 근거 문자열.
        """
        matched = [item.reason for item in self.rule_scores if item.state is RuleState.MATCH]
        if self.decision is Decision.RISK:
            return f"누적 위험 점수 {self.score}점이 차단 임계값 {self.threshold}점 이상입니다: {' '.join(matched)}"
        if self.decision is Decision.UNVERIFIABLE:
            return "6개 규칙을 판정할 수 있는 수집 증거가 없습니다."
        if matched:
            return f"위반 신호가 있으나 누적 위험 점수 {self.score}점은 차단 임계값 미만입니다: {' '.join(matched)}"
        return "확인 가능한 규칙에서 위반 증거가 발견되지 않았습니다."


# OIDC 불일치는 서명된 빌드 출처 자체가 다를 수 있어 단일 규칙 중 가장 큰
# 비중을 둔다. PR/승인 부재는 정상 프로젝트의 운영 방식일 수 있으므로 함께
# 나타날 때만 차단 임계값에 도달하도록 낮은 패널티로 유지한다.
DEFAULT_POLICY: Final[ScoringPolicy] = ScoringPolicy(
    penalties={
        RuleName.ORPHAN_RELEASE: 20,
        RuleName.UNREVIEWED: 20,
        RuleName.WORKFLOW_DRIFT: 30,
        RuleName.OIDC_MISMATCH: 40,
        RuleName.UNEXPECTED_BUILDER: 30,
        RuleName.TAG_IDENTITY_DRIFT: 25,
    },
    block_threshold=60,
)


RULE_REASONS: Final[Mapping[RuleName, str]] = {
    RuleName.ORPHAN_RELEASE: "릴리스 커밋에 연결된 PR이 없습니다.",
    RuleName.UNREVIEWED: "연결된 PR에 승인한 사람이 없습니다.",
    RuleName.WORKFLOW_DRIFT: "기준 릴리스와 다른 빌드 워크플로가 사용됐습니다.",
    RuleName.OIDC_MISMATCH: "Sigstore OIDC 신원과 SLSA 빌드 출처가 일치하지 않습니다.",
    RuleName.UNEXPECTED_BUILDER: "기준 릴리스와 다른 빌드 주체가 릴리스를 생성했습니다.",
    RuleName.TAG_IDENTITY_DRIFT: "기준 릴리스와 배포자·태그·Git 신원이 달라졌습니다.",
}


def evaluate_rule_states(
    rule_states: Mapping[str | RuleName, str | RuleState],
    policy: ScoringPolicy = DEFAULT_POLICY,
) -> ScoringResult:
    """6개 보안 규칙 상태를 패널티 점수와 설치 결정으로 평가한다.

    Args:
        rule_states: 규칙 이름과 MATCH/NO_MATCH/UNVERIFIABLE/NOT_EVALUATED 상태의 매핑.
        policy: 규칙별 패널티와 차단 임계값을 정의한 점수 정책.

    Returns:
        ScoringResult: 누적 점수, PASS/RISK/UNVERIFIABLE 결정 및 규칙별 근거.

    Raises:
        InvalidRuleStateError: 규칙 이름, 상태, 정책 점수가 유효하지 않은 경우.
    """
    _validate_policy(policy)
    normalized = _normalize_rule_states(rule_states)
    rule_scores = tuple(
        _score_rule(rule, normalized[rule], policy)
        for rule in RuleName
    )
    score = min(100, sum(item.penalty for item in rule_scores))
    decision = _decide(score, rule_scores, policy.block_threshold)
    return ScoringResult(
        score=score,
        decision=decision,
        threshold=policy.block_threshold,
        rule_scores=rule_scores,
    )


def extract_rule_states_from_lineage(report: Mapping[str, Any]) -> dict[str, str]:
    """통합 계보 보고서에서 현재 수집 가능한 규칙 상태를 추출한다.

    Args:
        report: npm, GitHub, Sigstore 트랙을 포함한 릴리스 계보 보고서.

    Returns:
        각 6개 보안 규칙의 상태를 담은 문자열 사전. 비교 기준선이 없는 규칙은
        NOT_EVALUATED로, 필요한 증거가 없는 규칙은 UNVERIFIABLE로 반환한다.
    """
    tracks = report.get("tracks")
    if not isinstance(tracks, Mapping):
        return {rule.value: RuleState.UNVERIFIABLE.value for rule in RuleName}

    github = tracks.get("github")
    sigstore = tracks.get("sigstore")
    states = {
        RuleName.ORPHAN_RELEASE.value: RuleState.UNVERIFIABLE.value,
        RuleName.UNREVIEWED.value: RuleState.UNVERIFIABLE.value,
        # 이전 릴리스 기준선이 아직 수집되지 않았으므로 이상으로 취급하지 않는다.
        RuleName.WORKFLOW_DRIFT.value: RuleState.NOT_EVALUATED.value,
        RuleName.OIDC_MISMATCH.value: _oidc_state(sigstore),
        RuleName.UNEXPECTED_BUILDER.value: RuleState.NOT_EVALUATED.value,
        RuleName.TAG_IDENTITY_DRIFT.value: RuleState.NOT_EVALUATED.value,
    }
    states.update(_github_review_states(github))
    return states


def evaluate_lineage_report(
    report: Mapping[str, Any],
    policy: ScoringPolicy = DEFAULT_POLICY,
) -> dict[str, Any]:
    """통합 계보 보고서의 세부 6개 보안 규칙을 평가해 인터셉터 결과를 만든다.

    Args:
        report: 수집기가 생성한 릴리스 계보 보고서.
        policy: 이전 단순 상태 평가 호출과의 호환성을 위한 정책 인자.

    Returns:
        score, verdict, threshold, 규칙별 세부 신호를 포함한 JSON 호환 사전.
    """
    # UPDATE: 규칙당 하나의 고정 패널티 대신 현재 증거와 과거 기준선을 분리해
    # 평가하여, 데이터 결측을 위험 점수로 오인하지 않도록 상세 엔진에 위임한다.
    del policy
    return evaluate_detailed_evidence(evidence_from_lineage(report))


def _validate_policy(policy: ScoringPolicy) -> None:
    """점수 정책이 6개 보안 규칙을 안전하게 평가할 수 있는지 검증한다.

    Args:
        policy: 검증할 점수 정책.

    Returns:
        None.

    Raises:
        InvalidRuleStateError: 임계값 또는 패널티 범위가 안전하지 않은 경우.
    """
    if not 1 <= policy.block_threshold <= 100:
        raise InvalidRuleStateError("차단 임계값은 1~100 범위여야 합니다.")
    missing = set(RuleName) - set(policy.penalties)
    if missing:
        raise InvalidRuleStateError(f"패널티가 없는 규칙이 있습니다: {sorted(rule.value for rule in missing)}")
    if any(not isinstance(value, int) or value < 0 for value in policy.penalties.values()):
        raise InvalidRuleStateError("규칙 패널티는 0 이상의 정수여야 합니다.")


def _normalize_rule_states(
    rule_states: Mapping[str | RuleName, str | RuleState],
) -> dict[RuleName, RuleState]:
    """입력 규칙 상태를 열거형으로 정규화해 누락과 오타를 차단한다.

    Args:
        rule_states: 문자열 또는 열거형으로 표현된 규칙 상태 매핑.

    Returns:
        모든 6개 규칙을 포함하는 정규화된 RuleName-RuleState 사전.

    Raises:
        InvalidRuleStateError: 규칙이 누락됐거나 상태 문자열이 유효하지 않은 경우.
    """
    normalized: dict[RuleName, RuleState] = {}
    for rule in RuleName:
        raw_state = rule_states.get(rule, rule_states.get(rule.value))
        if raw_state is None:
            raise InvalidRuleStateError(f"규칙 상태가 누락됐습니다: {rule.value}")
        try:
            normalized[rule] = raw_state if isinstance(raw_state, RuleState) else RuleState(raw_state)
        except ValueError as error:
            raise InvalidRuleStateError(
                f"유효하지 않은 규칙 상태입니다: {rule.value}={raw_state}"
            ) from error
    return normalized


def _score_rule(rule: RuleName, state: RuleState, policy: ScoringPolicy) -> RuleScore:
    """하나의 보안 규칙 MATCH에만 패널티를 적용한다.

    Args:
        rule: 점수화할 6개 보안 규칙 중 하나.
        state: 수집 증거로 확정된 규칙 상태.
        policy: 해당 규칙의 패널티를 가진 점수 정책.

    Returns:
        RuleScore: 규칙 상태, 적용 패널티, 감사용 근거.
    """
    if state is RuleState.MATCH:
        return RuleScore(rule, state, policy.penalties[rule], RULE_REASONS[rule])
    if state is RuleState.NO_MATCH:
        return RuleScore(rule, state, 0, "위반 증거가 확인되지 않았습니다.")
    if state is RuleState.NOT_EVALUATED:
        return RuleScore(rule, state, 0, "비교 기준선이 없어 이 규칙은 아직 평가하지 않았습니다.")
    return RuleScore(rule, state, 0, "필요한 수집 증거가 없어 이 규칙은 검증할 수 없습니다.")


def _decide(score: int, rule_scores: tuple[RuleScore, ...], threshold: int) -> Decision:
    """누적 패널티와 증거 가용성으로 최종 설치 결정을 내린다.

    Args:
        score: 0~100으로 제한된 누적 패널티 점수.
        rule_scores: 6개 규칙의 개별 평가 결과.
        threshold: RISK로 차단할 최소 점수.

    Returns:
        점수가 임계값 이상이면 RISK, 모든 규칙이 검증 불가이면 UNVERIFIABLE,
        그 외에는 PASS 결정.
    """
    if score >= threshold:
        return Decision.RISK
    evaluated = any(item.state in {RuleState.MATCH, RuleState.NO_MATCH} for item in rule_scores)
    return Decision.PASS if evaluated else Decision.UNVERIFIABLE


def _github_review_states(github_track: Any) -> dict[str, str]:
    """GitHub 커밋·PR 증거로 Orphan Release와 Unreviewed를 판정한다.

    Args:
        github_track: GitHub 수집 트랙의 상태와 데이터.

    Returns:
        orphan_release와 unreviewed 상태를 담은 사전. 커밋이 없으면 두 규칙을
        UNVERIFIABLE로 반환해 증거 부재를 위반으로 오인하지 않는다.
    """
    if not isinstance(github_track, Mapping) or github_track.get("status") != "SUCCESS":
        return {
            RuleName.ORPHAN_RELEASE.value: RuleState.UNVERIFIABLE.value,
            RuleName.UNREVIEWED.value: RuleState.UNVERIFIABLE.value,
        }
    data = github_track.get("data")
    commit = data.get("commit") if isinstance(data, Mapping) else None
    if not isinstance(commit, Mapping):
        return {
            RuleName.ORPHAN_RELEASE.value: RuleState.UNVERIFIABLE.value,
            RuleName.UNREVIEWED.value: RuleState.UNVERIFIABLE.value,
        }
    pull_requests = commit.get("pull_requests")
    if not isinstance(pull_requests, list):
        pull_requests = []
    approved = any(
        isinstance(review, Mapping)
        and review.get("approved") is True
        and isinstance(review.get("login"), str)
        and bool(review["login"])
        for pull_request in pull_requests
        if isinstance(pull_request, Mapping)
        for review in (pull_request.get("reviewers") or [])
        if isinstance(review, Mapping)
    )
    return {
        RuleName.ORPHAN_RELEASE.value: (
            RuleState.MATCH.value if not pull_requests else RuleState.NO_MATCH.value
        ),
        RuleName.UNREVIEWED.value: (
            RuleState.MATCH.value if pull_requests and not approved else RuleState.NO_MATCH.value
        ),
    }


def _oidc_state(sigstore_track: Any) -> str:
    """Sigstore 교차검증 결과로 OIDC Mismatch 규칙을 판정한다.

    Args:
        sigstore_track: Sigstore 수집 트랙의 상태와 검증 결과.

    Returns:
        검증 실패면 MATCH, 통과면 NO_MATCH, 증거가 없으면 UNVERIFIABLE 상태.
    """
    if not isinstance(sigstore_track, Mapping) or sigstore_track.get("status") != "SUCCESS":
        return RuleState.UNVERIFIABLE.value
    data = sigstore_track.get("data")
    validation = data.get("validation") if isinstance(data, Mapping) else None
    if not isinstance(validation, Mapping):
        return RuleState.UNVERIFIABLE.value
    if validation.get("status") == "FAIL" or validation.get("passed") is False:
        return RuleState.MATCH.value
    if validation.get("status") == "PASS" or validation.get("passed") is True:
        return RuleState.NO_MATCH.value
    return RuleState.UNVERIFIABLE.value


__all__ = [
    "DEFAULT_POLICY",
    "Decision",
    "InvalidRuleStateError",
    "RuleName",
    "RuleScore",
    "RuleState",
    "ScoringPolicy",
    "ScoringResult",
    "evaluate_lineage_report",
    "evaluate_rule_states",
    "extract_rule_states_from_lineage",
]

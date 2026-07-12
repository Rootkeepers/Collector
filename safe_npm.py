"""safe-npm: npm install 인터셉트 wrapper 커맨드.

npm install 요청을 가로채 Track A/B/C 수집기가 만든 계보(lineage)를 기반으로
트러스트 스코어를 판정한 뒤, PASS인 경우에만 실제 npm에 설치를 위임한다.

install/i 서브커맨드만 검사 대상으로 가로채고, 그 외 서브커맨드(run, ci,
publish 등)는 전부 그대로 npm에 통과시킨다 (npq-hero와 동일한 설계 원칙).

사용 예:
    $ safe-npm install lodash react@18
    $ safe-npm run build          # 검사 없이 그대로 npm run build 실행
"""

import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum


class CollectorError(Exception):
    """수집 또는 판정 과정에서 발생하는 에러를 감싸는 예외."""


class Verdict(str, Enum):
    """판정 결과 상태."""

    PASS = "PASS"
    RISK = "RISK"
    UNVERIFIABLE = "UNVERIFIABLE"


@dataclass
class RiskResult:
    """단일 패키지에 대한 판정 결과.

    Attributes:
        package_spec: 검사 대상 패키지 명세 (예: "lodash", "react@18").
        verdict: PASS / RISK / UNVERIFIABLE 중 하나.
        score: 0~100 트러스트 스코어.
        reason: 판정 근거 요약.
    """

    package_spec: str
    verdict: Verdict
    score: int
    reason: str


def find_real_npm() -> str:
    """alias/PATH 우회 없이 실제 npm 바이너리 경로를 찾는다.

    Returns:
        진짜 npm 실행 파일의 절대 경로.

    Raises:
        CollectorError: npm을 PATH 상에서 찾지 못한 경우.
    """
    npm_path = shutil.which("npm")
    if npm_path is None:
        raise CollectorError("PATH에서 npm 바이너리를 찾을 수 없습니다.")
    return npm_path


def parse_install_targets(args: list[str]) -> list[str]:
    """install 서브커맨드 인자에서 패키지명@버전 목록을 추출한다.

    -g, --save-dev 같은 플래그는 제외하고 실제 패키지 명세만 골라낸다.

    Args:
        args: "install" 뒤에 오는 인자 목록.

    Returns:
        패키지 명세 문자열 목록 (예: ["lodash", "react@18"]).
    """
    return [a for a in args if not a.startswith("-")]


def check_package(package_spec: str) -> RiskResult:
    """단일 패키지에 대해 위험 판정을 수행한다.

    NOTE: 수집기(Track A/B/C) 통합 전까지는 mock 판정을 사용한다.
    인터셉트 메커니즘(가로채기 -> 검사 -> 차단/위임) 자체가 제대로
    동작하는지 독립적으로 테스트하기 위한 임시 구현.

    수집기 통합이 끝나면 이 함수 내부만 아래처럼 교체하면 된다:
        from crawler import collect_lineage, evaluate_risk
        lineage = collect_lineage(package_spec)
        result = evaluate_risk(lineage)

    Args:
        package_spec: 검사할 패키지 명세 (예: "lodash", "react@18").

    Returns:
        RiskResult: 판정 결과.

    Raises:
        CollectorError: 검사 과정에서 실패한 경우.
    """
    try:
        result = _mock_evaluate(package_spec)
    except Exception as exc:  # noqa: BLE001 - 상위에서 CollectorError로 통일
        raise CollectorError(f"{package_spec} 검사 실패: {exc}") from exc

    return result


def _mock_evaluate(package_spec: str) -> RiskResult:
    """수집기 통합 전 임시 판정 로직.

    데모/테스트 목적으로 패키지명에 "evil"이 포함되면 RISK,
    "unknown"이 포함되면 UNVERIFIABLE, 나머지는 PASS로 처리한다.
    실제 트러스트 스코어 로직이 아니라 인터셉트 흐름 검증용.
    """
    name = package_spec.split("@")[0].lower()

    if "evil" in name:
        return RiskResult(package_spec, Verdict.RISK, 10, "mock: 위험 패키지명 패턴 탐지")
    if "unknown" in name:
        return RiskResult(package_spec, Verdict.UNVERIFIABLE, 50, "mock: 계보 정보 부족")
    return RiskResult(package_spec, Verdict.PASS, 90, "mock: 이상 없음")


def report(result: RiskResult) -> None:
    """판정 결과를 사용자에게 출력한다."""
    if result.verdict is Verdict.RISK:
        print(f"[BLOCKED] {result.package_spec} (score={result.score}) - {result.reason}")
    elif result.verdict is Verdict.UNVERIFIABLE:
        print(f"[WARN] {result.package_spec} (score={result.score}) - 검증 불가: {result.reason}")
    else:
        print(f"[PASS] {result.package_spec} (score={result.score})")


def gate_install(targets: list[str]) -> bool:
    """install 대상 패키지들을 전부 검사하고, 하나라도 RISK면 차단한다.

    Args:
        targets: 검사할 패키지 명세 목록.

    Returns:
        True면 설치 진행 가능, False면 차단.
    """
    blocked = False
    for pkg_spec in targets:
        try:
            result = check_package(pkg_spec)
        except CollectorError as exc:
            print(f"[ERROR] {pkg_spec}: {exc}")
            blocked = True
            continue

        report(result)
        if result.verdict is Verdict.RISK:
            blocked = True

    return not blocked


def run_real_npm(args: list[str]) -> int:
    """검사를 통과한 요청을 실제 npm에 위임해 실행한다.

    Args:
        args: npm에 그대로 전달할 전체 인자 목록.

    Returns:
        npm 프로세스의 종료 코드.
    """
    npm_path = find_real_npm()
    completed = subprocess.run([npm_path, *args], check=False)
    return completed.returncode


def main() -> int:
    args = sys.argv[1:]

    if not args:
        return run_real_npm(args)

    subcommand = args[0]

    # install/i가 아니면 검사 없이 그대로 통과 (npq-hero 방식)
    if subcommand not in ("install", "i"):
        return run_real_npm(args)

    targets = parse_install_targets(args[1:])

    # 대상 패키지가 없으면 (예: "npm install"만 실행 = package.json 기준 설치)
    # 현재는 개별 패키지 지정 케이스만 검사 대상으로 처리
    # TODO: package.json/lock 파일 기반 전체 설치 케이스 처리 (6.2/6.3 항목 연계)
    if not targets:
        print("[INFO] 개별 패키지 미지정 설치는 아직 검사 대상이 아닙니다. 그대로 진행합니다.")
        return run_real_npm(args)

    if not gate_install(targets):
        print("[HALTED] 위험 패키지가 감지되어 설치를 중단합니다.")
        return 1

    return run_real_npm(args)


if __name__ == "__main__":
    sys.exit(main())

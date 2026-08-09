"""safe-npm: npm install 인터셉트 wrapper 커맨드.

npm install 요청을 가로채 Track A/B/C 수집기가 만든 계보(lineage)를 기반으로
트러스트 스코어를 판정한 뒤, PASS인 경우에만 실제 npm에 설치를 위임한다.

install/i 서브커맨드만 검사 대상으로 가로채고, 그 외 서브커맨드(run, ci,
publish 등)는 전부 그대로 npm에 통과시킨다 (npq-hero와 동일한 설계 원칙).

사용 예:
    $ safe-npm install lodash react@18
    $ safe-npm run build          # 검사 없이 그대로 npm run build 실행
"""

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from rootkeepers.interceptor.cooldown import check_cooldown, get_latest_version
from rootkeepers.paths import load_env
from rootkeepers.interceptor.reporting import report_event
from rootkeepers.interceptor.scanning import scan_package

# 이 모듈은 항상 패키지의 일부로 import된다(`python -m rootkeepers.interceptor`
# 또는 콘솔이 import). src/ 를 경로에 넣는 일은 그 진입점이 이미 끝냈다.
load_env()


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
        scan: scan_package()의 전체 결과. 이력 전송에 재사용한다.
            쿨다운 미경과 등으로 계보 수집을 건너뛴 경우 None이다.
    """

    package_spec: str
    verdict: Verdict
    score: int
    reason: str
    scan: dict | None = None


def find_real_npm() -> str:
    """진짜 npm 실행 파일을 찾는다.

    PATH에 `npm`이라는 이름의 래퍼를 끼워 넣어 쓰는 경우, 단순한
    ``shutil.which("npm")``은 **그 래퍼 자신**을 찾아내 무한 재귀에 빠진다.
    ``TRUSTGATE_SHIM_DIR``에 래퍼가 있는 디렉터리를 지정하면 탐색에서 제외한다
    (지정하지 않으면 PATH 순서대로 그냥 찾는다).

    `npm` 커맨드 자체가 이 인터셉터로 shim 처리된 경우, shim 스크립트가
    자기 자신을 제외한 PATH에서 미리 찾은 진짜 npm 경로를
    ``ROOTKEEPERS_REAL_NPM`` 환경변수로 넘겨준다. 그 값이 있으면 우선
    사용해 shim이 자기 자신을 다시 호출하는 무한 재귀를 방지한다.

    Returns:
        진짜 npm 실행 파일의 절대 경로.

    Raises:
        CollectorError: npm을 PATH 상에서 찾지 못한 경우.
    """
    env_path = os.environ.get("ROOTKEEPERS_REAL_NPM")
    if env_path:
        return env_path

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


def _split_package_spec(package_spec: str) -> tuple[str, str | None]:
    """package_spec을 (패키지명, 버전) 튜플로 분리한다.

    스코프 패키지(``@scope/name``, ``@scope/name@1.0.0``)의 "@"는 이름의
    일부이므로, 버전 구분자로 쓰이는 마지막 "@"만 기준으로 분리한다.

    Args:
        package_spec: 검사할 패키지 명세 (예: "lodash", "react@18",
            "@scope/name@1.0.0").

    Returns:
        (패키지명, 버전 또는 None) 튜플. 버전이 명시되지 않으면 None이며,
        이 경우 수집기가 npm의 "latest" dist-tag로 자동 resolve한다.
    """
    body = package_spec[1:] if package_spec.startswith("@") else package_spec
    if "@" not in body:
        return package_spec, None

    name_part, version = package_spec.rsplit("@", 1)
    return name_part, version


def check_package(package_spec: str) -> RiskResult:
    """단일 패키지에 대해 위험 판정을 수행한다.

    Track A(npm)/B(GitHub)/C(Sigstore) 수집기를 실제로 호출해 계보를 수집하고,
    정식 6규칙 엔진(detailed_rule_engine)으로 판정한다 — 웹 콘솔과 완전히
    동일한 ``rootkeepers.interceptor.scanning.scan_package()``를 쓰므로, 같은 패키지에
    대해 터미널과 대시보드의 판정이 갈리지 않는다.

    판정 결과는 콘솔로 fire-and-forget 전송된다
    (``TRUSTGATE_CONSOLE_URL``이 가리키는 콘솔로, 실패해도 설치 흐름 무관).

    Args:
        package_spec: 검사할 패키지 명세 (예: "lodash", "react@18").

    Returns:
        RiskResult: 판정 결과.

    Raises:
        CollectorError: 검사 과정에서 실패한 경우.
    """
    name, version = _split_package_spec(package_spec)

    # 쿨다운 게이트: 신버전이 배포된 지 충분히 지났는지 먼저 확인.
    # 미경과면 아직 관찰 기간이므로 무거운 계보 수집을 건너뛰고 보류 처리한다.
    # 버전 미지정이면 최신 버전으로 resolve (쿨다운을 재려면 버전이 필요)
    if version is None:
        version = get_latest_version(name)
        if version is None:
            return RiskResult(package_spec, Verdict.UNVERIFIABLE, 0,
                            "최신 버전 조회 실패")

    # 쿨다운 게이트: 미경과면 무거운 계보 수집 스킵하고 보류
    cd = check_cooldown(name, version)
    print(f"  [cooldown] {cd.reason}")
    if not cd.passed:
        reason = f"쿨다운 미경과 ({cd.remain_days:.1f}일 대기)"
        # 계보 수집을 건너뛰더라도 "쿨다운 때문에 설치가 보류됐다"는 사실 자체는
        # 이력에 남겨야 한다 — 안 그러면 History에서 이 시도가 통째로 보이지 않는다.
        report_event("cooldown_hold", {
            "package": {"name": name, "version": version},
            "verdict": Verdict.UNVERIFIABLE.value,
            "score": 0,
            "reason": reason,
            "rules": [],
        }, {"remain_days": round(cd.remain_days, 2) if cd.remain_days is not None else None})
        return RiskResult(package_spec, Verdict.UNVERIFIABLE, 0, reason)

    try:
        scan = scan_package(name, version)
    except Exception as exc:
        raise CollectorError(f"{package_spec} 검사 실패: {exc}") from exc

    report_event("scan", scan)
    return RiskResult(package_spec, Verdict(scan["verdict"]), scan["score"], scan["reason"], scan)


def report(result: RiskResult) -> None:
    """판정 결과를 사용자에게 출력한다."""
    if result.verdict is Verdict.RISK:
        print(f"[BLOCKED] {result.package_spec} (score={result.score}) - {result.reason}")
    elif result.verdict is Verdict.UNVERIFIABLE:
        print(f"[WARN] {result.package_spec} (score={result.score}) - 검증 불가: {result.reason}")
    else:
        print(f"[PASS] {result.package_spec} (score={result.score})")


def gate_install(targets: list[str]) -> tuple[bool, list[RiskResult]]:
    """install 대상 패키지들을 전부 검사하고, 하나라도 RISK면 차단한다.

    Args:
        targets: 검사할 패키지 명세 목록.

    Returns:
        (설치 진행 가능 여부, 검사 결과 목록). 결과 목록은 호출자가 설치
        성공 후 "install" 이벤트를 보낼 때 재사용한다.
    """
    blocked = False
    results: list[RiskResult] = []
    for pkg_spec in targets:
        try:
            result = check_package(pkg_spec)
        except CollectorError as exc:
            print(f"[ERROR] {pkg_spec}: {exc}")
            blocked = True
            continue

        results.append(result)
        report(result)
        if result.verdict is Verdict.RISK:
            blocked = True
            if result.scan:
                report_event("block", result.scan)

    return (not blocked), results


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

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
from pathlib import Path


def _find_project_root(start_dir: Path) -> Path:
    """`safe_npm.py`가 어느 위치로 옮겨져도 안전하게 레포 루트를 찾는다.

    `requirements.txt`나 `.git`이 있는 폴더를 만날 때까지 상위 디렉토리를
    거슬러 올라가며 찾는다. 그래서 이 파일이 나중에 또 다른 위치로 옮겨져도
    이 부분을 다시 고칠 필요가 없다.

    Args:
        start_dir: 탐색을 시작할 디렉토리 (보통 이 파일이 있는 폴더).

    Returns:
        레포 루트로 판단되는 디렉토리. 표식을 못 찾으면 `start_dir` 그대로 반환.
    """
    for candidate in (start_dir, *start_dir.parents):
        if (candidate / "requirements.txt").exists() or (candidate / ".git").exists():
            return candidate
    return start_dir


PROJECT_ROOT = _find_project_root(Path(__file__).resolve().parent)
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

try:
    from dotenv import load_dotenv

    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:  # pragma: no cover - dotenv is a soft dependency here
    pass

from rootkeepers.interceptor.lineage import collect_release_lineage_report, evaluate_risk


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

    Track A(npm)/B(GitHub)/C(Sigstore) 수집기를 실제로 호출해 계보를
    수집하고, 임시 evaluate_risk()로 판정한다. evaluate_risk()는 정식
    규칙 엔진(5.1~5.6)이 완성되기 전까지의 잠정 로직이다.

    Args:
        package_spec: 검사할 패키지 명세 (예: "lodash", "react@18").

    Returns:
        RiskResult: 판정 결과.

    Raises:
        CollectorError: 검사 과정에서 실패한 경우.
    """
    name, version = _split_package_spec(package_spec)

    try:
        report = collect_release_lineage_report(name, version)
        risk = evaluate_risk(report)
    except Exception as exc:  # noqa: BLE001 - 상위에서 CollectorError로 통일
        raise CollectorError(f"{package_spec} 검사 실패: {exc}") from exc

    return RiskResult(
        package_spec=package_spec,
        verdict=Verdict(risk["verdict"]),
        score=risk["score"],
        reason=risk["reason"],
    )


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

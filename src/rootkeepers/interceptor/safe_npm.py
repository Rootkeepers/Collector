"""safe-npm: npm install 인터셉트 wrapper 커맨드.

npm install 요청을 가로채 Track A/B/C 수집기가 만든 계보(lineage)를 기반으로
트러스트 스코어를 판정한 뒤, PASS인 경우에만 실제 npm에 설치를 위임한다.

install/i 서브커맨드만 검사 대상으로 가로채고, 그 외 서브커맨드(run, ci,
publish 등)는 전부 그대로 npm에 통과시킨다 (npq-hero와 동일한 설계 원칙).

사용 예:
    $ safe-npm install lodash react@18
    $ safe-npm run build          # 검사 없이 그대로 npm run build 실행
"""

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum
from rootkeepers.interceptor.cooldown import (
    check_cooldown,
    fetch_package_meta,
    get_latest_version,
)
from rootkeepers.paths import load_env
from rootkeepers.interceptor.reporting import report_event
from rootkeepers.interceptor.scanning import scan_package

# npm view는 네트워크를 타므로 무한정 기다리지 않는다. 설치 게이트 앞단이라
# 사용자가 체감하는 지연에 직접 더해진다.
_NPM_VIEW_TIMEOUT_SEC = 20

# 이 모듈은 항상 패키지의 일부로 import된다(`python -m rootkeepers.interceptor`
# 또는 콘솔이 import). src/ 를 경로에 넣는 일은 그 진입점이 이미 끝냈다.
load_env()


class CollectorError(Exception):
    """수집 또는 판정 과정에서 발생하는 에러를 감싸는 예외."""


class Verdict(str, Enum):
    """판정 결과 상태."""

    PASS = "PASS"
    RISK = "RISK"
    UNVERIFIABLE = "UNVERIFIABLE (RISK)"


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


_EXACT_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]*)?$")

# npm에 넘길 수 있는 명세만 통과시킨다. `-`로 시작하는 값이 인자로 들어가면
# npm이 이를 플래그로 해석하므로, 첫 글자에서 `-`를 제외한다. 범위는 `^`·`~`·
# `>`·`<`·`=`·`*`로 시작할 수 있어 그 문자들은 선두에도 허용해야 한다.
_SAFE_RANGE = re.compile(r"^[0-9A-Za-z^~<>=*][0-9A-Za-z.\-+_^~<>=*|\s]*$")


def _resolve_range_with_npm(name: str, spec: str) -> tuple[str | None, str | None]:
    """semver 범위를 실제 npm에 물어 정확한 버전 하나로 해석한다.

    범위 해석을 직접 구현하지 않고 npm에 위임하는 이유는 두 가지다. 첫째,
    prerelease·`||` 합집합·하이픈 범위 등 semver 규칙이 까다로워 재구현은
    조용히 틀릴 위험이 크다. 둘째, **실제로 설치될 버전과 검사한 버전이
    반드시 같아야** 게이트가 의미를 갖는데, 그 답을 아는 것은 설치를 수행할
    npm 자신이다.

    ``shutil.which()`` 대신 ``find_real_npm()``을 쓴다. 다만 shim 환경에서
    ``ROOTKEEPERS_REAL_NPM``이 없으면 ``find_real_npm()``도 결국 shim 경로를
    돌려주고, 그 경우 shim → safe-npm → 실제 npm 순으로 한 단계를 더 거친다.
    `view`는 install이 아니므로 safe-npm이 그대로 통과시켜 재귀는 생기지
    않는다(실측 오버헤드 약 0.1초). shim을 건너뛰고 실제 npm을 직접 찾는
    것은 ``find_real_npm()`` 자체의 과제라 여기서 우회하지 않는다.

    Args:
        name: 패키지명.
        spec: `^18`, `>=17 <19` 같은 semver 범위 문자열.

    Returns:
        (해석된 버전, 실패 사유). 성공하면 사유가 None, 실패하면 버전이 None.
    """
    if not _SAFE_RANGE.match(spec):
        return None, f"해석할 수 없는 버전 명세입니다: {spec}"
    try:
        npm_path = find_real_npm()
    except CollectorError as exc:
        return None, f"버전 해석용 npm을 찾지 못했습니다: {exc}"

    try:
        proc = subprocess.run(
            [npm_path, "view", f"{name}@{spec}", "version", "--json"],
            capture_output=True, text=True, timeout=_NPM_VIEW_TIMEOUT_SEC, check=False,
        )
    except subprocess.TimeoutExpired:
        return None, f"버전 해석이 {_NPM_VIEW_TIMEOUT_SEC}초 내에 끝나지 않았습니다: {name}@{spec}"
    except OSError as exc:
        return None, f"버전 해석 실행 실패: {exc}"

    if proc.returncode != 0 or not proc.stdout.strip():
        return None, f"{name}@{spec}에 해당하는 버전을 찾지 못했습니다."

    try:
        payload = json.loads(proc.stdout)
    except ValueError:
        return None, f"버전 해석 결과를 해석하지 못했습니다: {name}@{spec}"

    # 단일 매치는 문자열, 복수 매치는 오름차순 배열로 온다. 복수면 npm이
    # 실제로 설치할 값과 같도록 가장 높은 버전을 고른다.
    if isinstance(payload, str):
        return payload, None
    if isinstance(payload, list) and payload:
        newest = payload[-1]
        if isinstance(newest, str):
            return newest, None
    return None, f"{name}@{spec}에 해당하는 버전을 찾지 못했습니다."


def resolve_install_version(name: str, spec: str | None) -> tuple[str | None, str | None]:
    """설치 명세를 레지스트리에 실재하는 정확한 버전 하나로 해석한다.

    쿨다운 판정과 계보 수집(Track A/B/C)은 모두 "레지스트리에 실재하는 정확한
    버전"을 전제로 한다. `latest` 같은 dist-tag나 `^18` 같은 범위를 그대로
    넘기면 배포일도 계보도 찾지 못해, 정상 패키지까지 UNVERIFIABLE로 보류된다.

    Args:
        name: 패키지명.
        spec: `_split_package_spec()`이 뽑아낸 버전 부분. 생략되면 None.

    Returns:
        (해석된 버전, 실패 사유). 성공하면 사유가 None, 실패하면 버전이 None.
    """
    if spec is None:
        latest = get_latest_version(name)
        return (latest, None) if latest else (None, "최신 버전 조회 실패")

    if _EXACT_VERSION.match(spec):
        return spec, None

    # dist-tag(latest/next/beta…)는 레지스트리 문서 한 번으로 끝난다.
    # 범위 해석보다 흔하고 저렴하므로 npm 서브프로세스보다 먼저 시도한다.
    meta = fetch_package_meta(name)
    if meta is not None:
        resolved = meta.get("dist-tags", {}).get(spec)
        if isinstance(resolved, str) and resolved:
            return resolved, None

    return _resolve_range_with_npm(name, spec)


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
    name, spec = _split_package_spec(package_spec)

    # 쿨다운 판정과 계보 수집 모두 레지스트리에 실재하는 정확한 버전을
    # 전제로 한다. 버전 미지정(None)뿐 아니라 dist-tag(`latest`)와
    # 범위(`^18`)도 여기서 정확한 버전 하나로 해석한다.
    version, resolve_error = resolve_install_version(name, spec)
    if version is None:
        return RiskResult(package_spec, Verdict.UNVERIFIABLE, 0,
                          resolve_error or "버전을 해석하지 못했습니다.")

    # 쿨다운 게이트: 신버전이 배포된 지 충분히 지났는지 먼저 확인.
    # 미경과면 아직 관찰 기간이므로 무거운 계보 수집을 건너뛰고 보류 처리한다.
    cd = check_cooldown(name, version)
    print(f"  [cooldown] {cd.reason}")
    if not cd.passed:
        # 배포일을 못 찾으면 check_cooldown이 remain_days=None으로 보류시킨다.
        # 남은 일수를 모르는 상태이므로 숫자 대신 판정 사유를 그대로 싣는다.
        if cd.remain_days is None:
            reason = f"쿨다운 판정 불가: {cd.reason}"
        else:
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
    """install 대상 패키지들을 전부 검사하고, 하나라도 PASS가 아니면 차단한다.

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
        if result.verdict is not Verdict.PASS:
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

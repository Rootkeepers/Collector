"""safe-npm 실행 진입점.

npm install 요청을 가로채 6규칙 엔진으로 판정한 뒤, 통과한 경우에만 실제 npm에
위임한다. 판정/설치 결과는 콘솔로 fire-and-forget 전송된다
(``TRUSTGATE_CONSOLE_URL``이 가리키는 콘솔로).
"""

import sys
from pathlib import Path

try:
    from .safe_npm import (
        CollectorError, find_real_npm, gate_install, parse_install_targets, run_real_npm,
    )
except ImportError:
    from safe_npm import (  # type: ignore[no-redef]
        CollectorError, find_real_npm, gate_install, parse_install_targets, run_real_npm,
    )

try:
    from .reporting import flush_reports, report_event, report_inventory
    from .inventory import collect_inventory, collect_lock_packages
    from .bulk_gate import gate_bulk_install, review_new_packages
except ImportError:
    from rootkeepers.interceptor.reporting import flush_reports, report_event, report_inventory
    from rootkeepers.interceptor.inventory import collect_inventory, collect_lock_packages
    from rootkeepers.interceptor.bulk_gate import gate_bulk_install, review_new_packages

SYNC_FLAG = "--trustgate-sync"


def _sync_inventory(project_dir: Path | None = None) -> int:
    """현재 디렉터리에 설치된 패키지 목록을 콘솔로 보낸다.

    컨테이너 안에서는 호스트 PC의 패키지를 볼 수 없으므로, 이 PC에서 도는
    이 코드가 읽어서 알려주는 것이 유일한 방법이다.
    """
    project_dir = project_dir or Path.cwd()
    inv = collect_inventory(project_dir)
    if inv is None:
        print(f"[sync] {project_dir}에 package.json이 없습니다.")
        return 1
    report_inventory(inv)
    print(f"[sync] {inv['project']}: 패키지 {len(inv['packages'])}개를 콘솔로 전송했습니다.")
    return 0


def _sync_after_install(project_dir: Path) -> None:
    """설치로 node_modules/lock이 바뀌었으니 갱신된 목록을 콘솔에 보낸다."""
    inv = collect_inventory(project_dir)
    if inv:
        report_inventory(inv)


def _run_bulk(args: list[str], command: str) -> int:
    """lock 전체를 대상으로 하는 설치(인자 없는 install, ci)를 처리한다.

    개별 패키지 게이트와 달리 계보를 수집하지 않는다 — 전이 의존성까지 계보를
    모으는 것은 설치 앞단에서 감당할 수 있는 비용이 아니다. 대신 lock 기준
    알려진 취약 버전 점검을 붙이고, 무엇을 검사하지 않았는지 명시한다.
    자세한 근거는 ``bulk_gate`` 모듈 docstring 참고.
    """
    project_dir = Path.cwd()
    try:
        npm_path = find_real_npm()
    except CollectorError as exc:
        print(f"[ERROR] {exc}")
        return 1

    if not gate_bulk_install(project_dir, npm_path, command):
        return 1

    before = collect_lock_packages(project_dir)
    returncode = run_real_npm(args)
    if returncode != 0:
        return returncode

    _sync_after_install(project_dir)
    # 사전 점검은 그 시점의 lock을 봤다. package.json이 lock보다 앞서 있으면
    # npm이 설치 중에 새 패키지를 더 끌어오므로, 변화분을 다시 확인한다.
    if not review_new_packages(project_dir, before, command=command):
        return 1
    return returncode


def _run(args: list[str]) -> int:
    if args and args[0] == SYNC_FLAG:
        return _sync_inventory()

    if not args:
        return run_real_npm(args)

    # npm ci는 install 계열이 아니지만 하는 일은 lock 전체 설치다 — clone 직후와
    # CI에서 가장 흔한 경로이므로 인자 없는 install과 같은 점검을 태운다.
    if args[0] == "ci":
        return _run_bulk(args, "npm ci")

    if args[0] not in ("install", "i"):
        return run_real_npm(args)

    targets = parse_install_targets(args[1:])
    if not targets:
        return _run_bulk(args, "npm install")

    allowed, results = gate_install(targets)
    if not allowed:
        print("[HALTED] 위험 패키지가 감지되어 설치를 중단합니다.")
        return 1

    project_dir = Path.cwd()
    before = collect_lock_packages(project_dir)
    returncode = run_real_npm(args)

    # 실제 설치가 성공한 경우에만 install 이벤트를 보낸다 — 대시보드의
    # "Installed" 집계가 실제 설치와 어긋나지 않도록.
    if returncode != 0:
        return returncode

    for result in results:
        if result.scan:
            report_event("install", result.scan, {"install_returncode": returncode})
    _sync_after_install(project_dir)

    # 계보를 검증한 것은 지목한 패키지 하나뿐이다. 그 패키지가 함께 끌고 온
    # 서브트리는 여기서 처음 드러난다.
    command = f"npm install {' '.join(targets)}"
    if not review_new_packages(project_dir, before, command=command):
        return 1
    return returncode


def main() -> int:
    try:
        return _run(sys.argv[1:])
    finally:
        # CLI는 여기서 프로세스가 끝나 데몬 스레드가 죽는다 — 방금 쏜 리포트가
        # 유실되지 않도록 짧게 기다린다 (리포팅이 꺼져 있으면 즉시 반환).
        flush_reports()


if __name__ == "__main__":
    sys.exit(main())

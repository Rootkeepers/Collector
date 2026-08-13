"""safe-npm 실행 진입점.

npm install 요청을 가로채 6규칙 엔진으로 판정한 뒤, 통과한 경우에만 실제 npm에
위임한다. 판정/설치 결과는 콘솔로 fire-and-forget 전송된다
(``TRUSTGATE_CONSOLE_URL``이 가리키는 콘솔로).
"""

import sys
from pathlib import Path

try:
    from .safe_npm import gate_install, parse_install_targets, run_real_npm
except ImportError:
    from safe_npm import gate_install, parse_install_targets, run_real_npm

try:
    from .reporting import flush_reports, report_event, report_inventory
    from .inventory import collect_inventory
except ImportError:
    from rootkeepers.interceptor.reporting import flush_reports, report_event, report_inventory
    from rootkeepers.interceptor.inventory import collect_inventory

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


def _run(args: list[str]) -> int:
    if args and args[0] == SYNC_FLAG:
        return _sync_inventory()

    if not args:
        return run_real_npm(args)

    if args[0] not in ("install", "i"):
        return run_real_npm(args)

    targets = parse_install_targets(args[1:])
    if not targets:
        print("[INFO] 개별 패키지 미지정 설치는 아직 검사 대상이 아닙니다. 그대로 진행합니다.")
        return run_real_npm(args)

    allowed, results = gate_install(targets)
    if not allowed:
        print("[HALTED] 위험 패키지가 감지되어 설치를 중단합니다.")
        return 1

    returncode = run_real_npm(args)

    # 실제 설치가 성공한 경우에만 install 이벤트를 보낸다 — 대시보드의
    # "Installed" 집계가 실제 설치와 어긋나지 않도록.
    if returncode == 0:
        for result in results:
            if result.scan:
                report_event("install", result.scan, {"install_returncode": returncode})
        # 설치가 끝나 node_modules/lock이 바뀌었으니, 갱신된 목록을 함께 보낸다.
        inv = collect_inventory(Path.cwd())
        if inv:
            report_inventory(inv)

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

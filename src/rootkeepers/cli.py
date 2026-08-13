"""trustgate: 이 도구의 단일 진입점.

기능은 이미 모듈로 다 있었지만, 쓰려면 ``python -m rootkeepers.dashboard
--background`` 같은 긴 명령을 외워야 했고, 무엇보다 **환경이 어긋났을 때 그걸
알 방법이 없었다.** 실제로 자주 겪는 사고는 기능 버그가 아니라 이런 것들이다:

- 코드를 pull하고 콘솔을 재시작하지 않아, 새 API가 404가 난다
- shim이 여러 디렉터리에 남아 서로를 진짜 npm으로 착각한다
- 클론이 여러 개라 ``safe-npm``이 엉뚱한 사본을 실행한다
- 콘솔과 터미널이 서로 다른 이력 DB를 봐서 기록이 갈린다

``trustgate doctor``가 그 상태를 한 번에 보여 준다. 나머지 서브커맨드는 기존
모듈로 넘기는 얇은 껍데기다 — 로직을 여기서 중복 구현하지 않는다.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import unicodedata
import urllib.error
import urllib.request
from pathlib import Path

from rootkeepers.paths import PROJECT_ROOT, load_env, project_dir

OK, WARN, BAD, INFO = "OK", "경고", "문제", "정보"
_MARK = {OK: "[ OK ]", WARN: "[경고]", BAD: "[문제]", INFO: "[    ]"}


def _cols(text: str) -> int:
    """터미널에서 차지하는 칸 수. 한글·한자는 두 칸이라 len()으로는 정렬이 깨진다."""
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _cols(text))


class Report:
    """진단 결과를 모아 두었다가 한 번에 출력한다."""

    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str, str]] = []

    def add(self, level: str, item: str, detail: str, fix: str = "") -> None:
        self.rows.append((level, item, detail, fix))

    def render(self) -> int:
        width = max((_cols(r[1]) for r in self.rows), default=0)
        mark_width = max(_cols(m) for m in _MARK.values())
        for level, item, detail, fix in self.rows:
            print(f"{_pad(_MARK[level], mark_width)} {_pad(item, width)}  {detail}")
            if fix:
                print(f"{' ' * (mark_width + 1)}{' ' * width}  → {fix}")
        bad = sum(1 for r in self.rows if r[0] == BAD)
        warn = sum(1 for r in self.rows if r[0] == WARN)
        print()
        if bad:
            print(f"{bad}개 문제, {warn}개 경고. 위의 → 를 따라 고치세요.")
        elif warn:
            print(f"{warn}개 경고. 동작은 하지만 확인해 두는 게 좋습니다.")
        else:
            print("이상 없습니다.")
        return 1 if bad else 0


def _get_json(url: str, timeout: float = 2) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as res:
            return json.loads(res.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None


def _npms_on_path() -> list[tuple[Path, bool]]:
    """PATH의 모든 npm을 순서대로. (경로, 우리 shim인지)"""
    from rootkeepers.interceptor.shim_installer import SHIM_MARKER

    found = []
    for raw in os.environ.get("PATH", "").split(os.pathsep):
        if not raw:
            continue
        for name in ("npm", "npm.cmd", "npm.exe"):
            candidate = Path(raw) / name
            if not candidate.is_file():
                continue
            try:
                is_shim = SHIM_MARKER in candidate.read_text(encoding="utf-8", errors="replace")
            except OSError:
                is_shim = False
            found.append((candidate, is_shim))
            break
    return found


def _safe_npm_source() -> tuple[Path | None, Path | None]:
    """(safe-npm 실행 파일, 그게 실제로 import하는 rootkeepers 위치)."""
    exe = shutil.which("safe-npm")
    if not exe:
        return None, None

    # 콘솔 스크립트의 shebang이 가리키는 인터프리터로 물어봐야 정확하다.
    # 여러 클론이 있을 때 "지금 이 파이썬"과 다를 수 있기 때문이다.
    interpreter = sys.executable
    try:
        first = Path(exe).read_text(encoding="utf-8", errors="replace").splitlines()[0]
        if first.startswith("#!"):
            interpreter = first[2:].strip().strip('"')
    except (OSError, IndexError):
        pass

    try:
        out = subprocess.run(
            [interpreter, "-c", "import rootkeepers,sys; sys.stdout.write(rootkeepers.__file__)"],
            capture_output=True, text=True, timeout=15, check=False)
        if out.returncode == 0 and out.stdout.strip():
            return Path(exe), Path(out.stdout.strip()).resolve().parents[1]
    except (OSError, subprocess.SubprocessError):
        pass
    return Path(exe), None


def cmd_doctor(_args) -> int:
    load_env()
    from rootkeepers.dashboard import background, store

    rep = Report()
    here = Path(__file__).resolve().parents[1]

    # --- 코드 위치 ------------------------------------------------------
    rep.add(INFO, "이 코드", str(PROJECT_ROOT))

    exe, used_root = _safe_npm_source()
    if exe is None:
        rep.add(BAD, "safe-npm", "설치되지 않았습니다.",
                f"pip install --user -e {PROJECT_ROOT}")
    elif used_root is None:
        rep.add(WARN, "safe-npm", f"{exe} (어느 사본을 쓰는지 확인 실패)")
    elif used_root == here:
        rep.add(OK, "safe-npm", f"{exe}")
    else:
        rep.add(BAD, "safe-npm", f"다른 사본을 실행합니다: {used_root.parent}",
                f"pip install --user -e {PROJECT_ROOT}")

    # --- npm shim -------------------------------------------------------
    npms = _npms_on_path()
    shims = [p for p, is_shim in npms if is_shim]
    reals = [p for p, is_shim in npms if not is_shim]
    if not npms:
        rep.add(BAD, "npm", "PATH에서 npm을 찾을 수 없습니다.")
    elif not shims:
        rep.add(WARN, "npm shim", "설치되지 않았습니다 — 터미널 npm install이 검사를 거치지 않습니다.",
                "safe-npm-setup")
    elif npms[0][1] is False:
        rep.add(WARN, "npm shim", f"shim({shims[0]})보다 실제 npm({npms[0][0]})이 PATH 앞에 있습니다.",
                "safe-npm-setup 을 다시 실행하거나 PATH 순서를 확인하세요.")
    else:
        rep.add(OK, "npm shim", str(shims[0]))
    if len(shims) > 1:
        rep.add(WARN, "낡은 shim", f"shim이 {len(shims)}개 있습니다: {', '.join(str(s) for s in shims)}",
                "safe-npm-setup --uninstall 후 다시 설치하세요.")
    if shims and not reals:
        rep.add(BAD, "실제 npm", "shim 말고 진짜 npm이 PATH에 없습니다 — 설치가 진행되지 않습니다.")
    elif reals:
        rep.add(INFO, "실제 npm", str(reals[0]))

    # --- 콘솔 -----------------------------------------------------------
    info = background.status()
    if not info["running"]:
        rep.add(INFO, "콘솔", "실행 중이 아닙니다 (이력은 로컬 DB에 계속 쌓입니다).",
                "trustgate up")
        console_db = None
    else:
        host = "127.0.0.1" if info["host"] in ("0.0.0.0", "::", "") else info["host"]  # noqa: S104
        base = f"http://{host}:{info['port']}"
        health = _get_json(f"{base}/api/health")
        if health is None:
            rep.add(BAD, "콘솔", f"pid {info['pid']}는 살아 있으나 {base} 가 응답하지 않습니다.",
                    "trustgate down 후 trustgate up")
            console_db = None
        else:
            rep.add(OK, "콘솔", f"{base} (pid {info['pid']})")
            console_db = health.get("db_path")
            # 코드를 pull하고 재시작하지 않으면 새 API가 없다. 이번 세션에서
            # /api/scans 404로 Explorer가 비었던 바로 그 상황이다.
            if _get_json(f"{base}/api/scans") is None:
                rep.add(BAD, "콘솔 코드", "지금 코드보다 오래된 프로세스입니다 (새 API 없음).",
                        "trustgate down && trustgate up")
            if not health.get("github_token_configured"):
                rep.add(WARN, "콘솔 토큰", "콘솔 쪽에 GITHUB_TOKEN이 없습니다.")

    # --- 이력 DB --------------------------------------------------------
    try:
        rep.add(OK, "이력 DB", f"{store.DB_PATH} (이벤트 {store.stats()['total_events']}건)")
    except Exception as exc:  # noqa: BLE001
        rep.add(BAD, "이력 DB", f"{store.DB_PATH} 열기 실패: {exc}")
    if console_db and console_db != str(store.DB_PATH):
        rep.add(WARN, "DB 불일치", f"콘솔은 {console_db} 를 봅니다 — 터미널 기록이 그 화면에 안 보입니다.",
                "콘솔을 로컬로 띄우거나 TRUSTGATE_DB_PATH를 맞추세요.")

    # --- 설정 -----------------------------------------------------------
    if os.getenv("GITHUB_TOKEN"):
        rep.add(OK, "GITHUB_TOKEN", "설정됨")
    else:
        rep.add(WARN, "GITHUB_TOKEN", "없음 — GitHub 트랙 수집이 실패합니다.",
                f"{PROJECT_ROOT / '.env'} 에 GITHUB_TOKEN=... 를 넣으세요.")

    target = project_dir()
    if (target / "package.json").is_file():
        rep.add(OK, "검사 대상", str(target))
    else:
        rep.add(WARN, "검사 대상", f"{target} 에 package.json이 없습니다.",
                "trustgate doctor 는 TRUSTGATE_PROJECT_DIR 를 따릅니다.")

    return rep.render()


def cmd_up(args) -> int:
    from rootkeepers.dashboard import background
    return background.start(args.host, args.port, args.project)


def cmd_down(args) -> int:
    from rootkeepers.dashboard import background
    return background.stop(force=args.force)


def cmd_status(_args) -> int:
    from rootkeepers.dashboard import background
    info = background.status()
    if info["running"]:
        print(f"실행 중 · pid {info['pid']} · http://{info['host']}:{info['port']}")
    else:
        print("실행 중이 아닙니다.")
    print(f"로그: {info['log']}")
    return 0


def cmd_scan(args) -> int:
    """설치하지 않고 판정만 본다."""
    from rootkeepers.interceptor.safe_npm import check_package, report
    from rootkeepers.interceptor.reporting import flush_reports

    load_env()
    code = 0
    for spec in args.package:
        result = check_package(spec)
        report(result)
        if result.verdict.value == "RISK":
            code = 1
    flush_reports()
    return code


def cmd_install(args) -> int:
    from rootkeepers.interceptor.__main__ import main as interceptor_main

    sys.argv = ["safe-npm", "install", *args.package]
    return interceptor_main()


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="trustgate", description="npm 공급망 계보 검증 콘솔")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("doctor", help="환경이 제대로 물려 있는지 진단한다")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("up", help="콘솔을 백그라운드로 띄운다")
    p.add_argument("--port", type=int, default=int(os.getenv("TRUSTGATE_PORT", "8000")))
    p.add_argument("--host", default=os.getenv("TRUSTGATE_HOST", "127.0.0.1"))
    p.add_argument("--project", default=os.getenv("TRUSTGATE_PROJECT_DIR", ""))
    p.set_defaults(func=cmd_up)

    p = sub.add_parser("down", help="콘솔을 종료한다")
    p.add_argument("--force", action="store_true", help="프로세스 확인 실패해도 강행")
    p.set_defaults(func=cmd_down)

    p = sub.add_parser("status", help="콘솔 실행 상태")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("scan", help="설치하지 않고 판정만 본다")
    p.add_argument("package", nargs="+", help="예: lodash react@18.2.0")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("install", help="검사 후 통과하면 실제로 설치한다")
    p.add_argument("package", nargs="+")
    p.set_defaults(func=cmd_install)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

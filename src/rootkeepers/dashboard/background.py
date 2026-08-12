"""콘솔을 터미널에서 떼어 백그라운드로 돌리기 위한 보조 도구.

``nohup ... &`` 로도 되지만, 그러면 PID를 사용자가 직접 챙겨야 하고 로그가 어디
쌓이는지도 매번 달라진다. 여기서 PID 파일과 로그 위치를 한 곳으로 정해
``--background`` / ``--stop`` / ``--status`` 세 가지로 다룰 수 있게 한다.

PID 재사용 주의: PID만 믿고 죽이면 그 사이 같은 번호를 받은 **엉뚱한 프로세스**를
죽일 수 있다. 그래서 정지 전에 "정말 우리 콘솔인지"를 한 번 더 확인한다
(리눅스는 /proc의 cmdline, 그 외는 health 응답). 확인에 실패하면 죽이지 않고
``--force``를 요구한다.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

#: PID/로그를 두는 곳. 이력 DB 기본 위치(~/.trustgate)와 같은 폴더를 쓴다.
RUNTIME_DIR = Path(os.getenv("TRUSTGATE_RUNTIME_DIR", "") or (Path.home() / ".trustgate"))
PID_FILE = RUNTIME_DIR / "console.pid"
LOG_FILE = RUNTIME_DIR / "console.log"

_MODULE = "rootkeepers.dashboard"
_START_TIMEOUT_SEC = 10


def _loopback(host: str) -> str:
    """0.0.0.0 은 접속 대상 주소가 아니다 — 확인은 루프백으로 한다."""
    return "127.0.0.1" if host in ("0.0.0.0", "::", "") else host  # noqa: S104


def _read_record() -> dict | None:
    try:
        return json.loads(PID_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        # OpenProcess는 **이미 끝난** 프로세스에도 성공한다(핸들이 남아 있는 동안
        # 커널 오브젝트가 유지된다). 종료 코드까지 봐야 실제 생존을 알 수 있다.
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        code = ctypes.c_ulong()
        ok = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return bool(ok) and code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # 살아 있으나 우리 소유가 아님
    return True


def _health_ok(host: str, port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://{_loopback(host)}:{port}/api/health", timeout=1) as res:
            res.read()
            return res.status == 200
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def _is_ours(pid: int, host: str, port: int) -> bool | None:
    """이 PID가 우리 콘솔인지. 판단할 수 없으면 None."""
    cmdline = Path(f"/proc/{pid}/cmdline")
    try:
        if cmdline.exists():
            return _MODULE in cmdline.read_bytes().decode("utf-8", "replace")
    except OSError:
        pass
    return True if _health_ok(host, port) else None


def status() -> dict:
    """{running, pid, host, port, log} — 실행 중이 아니면 running=False."""
    rec = _read_record()
    if not rec or not _alive(int(rec.get("pid", 0))):
        return {"running": False, "log": str(LOG_FILE)}
    return {"running": True, "pid": rec["pid"], "host": rec.get("host", "127.0.0.1"),
            "port": rec.get("port"), "log": str(LOG_FILE)}


def write_record(host: str, port: int) -> None:
    """서버가 뜨자마자 자기 정보를 남긴다 (포그라운드 실행도 포함).

    포그라운드로 띄운 것도 기록해야 ``--status``가 거짓말을 하지 않는다.
    """
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(json.dumps({"pid": os.getpid(), "host": host, "port": port}), encoding="utf-8")


def clear_record() -> None:
    try:
        PID_FILE.unlink()
    except OSError:
        pass


def start(host: str, port: int, project: str = "") -> int:
    """자기 자신을 터미널에서 분리해 다시 띄운다. 종료 코드를 돌려준다."""
    current = status()
    if current["running"]:
        print(f"[INFO] 이미 실행 중입니다 (pid {current['pid']}, "
              f"http://{_loopback(current['host'])}:{current['port']}).")
        return 0

    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    argv = [sys.executable, "-m", _MODULE, "--host", host, "--port", str(port)]
    if project:
        argv += ["--project", project]

    # 부모가 죽어도 살아남도록 새 세션(윈도우는 DETACHED_PROCESS)으로 띄운다.
    if os.name == "nt":
        extra = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000008}
    else:
        extra = {"start_new_session": True}

    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(f"\n=== {time.strftime('%Y-%m-%d %H:%M:%S')} 백그라운드 시작 ===\n")
        log.flush()
        proc = subprocess.Popen(argv, stdout=log, stderr=log,
                                stdin=subprocess.DEVNULL, **extra)

    # "떴다"고 말하기 전에 실제로 응답하는지 본다 — 포트 충돌로 즉사하는 경우가 흔하다.
    deadline = time.monotonic() + _START_TIMEOUT_SEC
    while time.monotonic() < deadline:
        if _health_ok(host, port):
            print(f"TrustGate Scan Console (백그라운드) → http://{_loopback(host)}:{port}")
            print(f"  pid {proc.pid} · 로그 {LOG_FILE}")
            print(f"  정지: python -m {_MODULE} --stop")
            return 0
        if proc.poll() is not None:
            break
        time.sleep(0.2)

    print(f"[ERROR] 백그라운드 실행에 실패했습니다. 로그를 확인하세요: {LOG_FILE}", file=sys.stderr)
    clear_record()
    return 1


def stop(force: bool = False) -> int:
    current = status()
    if not current["running"]:
        clear_record()
        print("[INFO] 실행 중인 콘솔이 없습니다.")
        return 0

    pid, host, port = current["pid"], current["host"], current["port"]
    if not force and _is_ours(pid, host, port) is not True:
        print(f"[ERROR] pid {pid}가 TrustGate 콘솔인지 확인할 수 없습니다. "
              f"PID가 재사용됐을 수 있어 종료하지 않습니다.\n"
              f"        정말 종료하려면: python -m {_MODULE} --stop --force", file=sys.stderr)
        return 1

    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        print(f"[ERROR] 종료 실패: {exc}", file=sys.stderr)
        return 1

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and _alive(pid):
        time.sleep(0.2)

    clear_record()
    print(f"[OK] 콘솔을 종료했습니다 (pid {pid})." if not _alive(pid)
          else f"[경고] pid {pid}가 아직 살아 있습니다. 필요하면 강제 종료하세요.")
    return 0


__all__ = ["start", "stop", "status", "write_record", "clear_record", "PID_FILE", "LOG_FILE"]

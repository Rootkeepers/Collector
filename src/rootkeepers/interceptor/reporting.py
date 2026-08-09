"""CLI 래퍼(safe-npm)가 로컬 콘솔로 결과를 흘려보내는 fire-and-forget 리포터.

콘솔이 직접 스캔한 결과는 콘솔이 자기 저장소에 바로 기록한다. 이 모듈은
**터미널에서 일어난 일**(`python -m rootkeepers.interceptor install ...`)을
콘솔에도 남기기 위한 통로다. 그게 없으면 터미널 활동이 대시보드에 전혀
보이지 않는다.

설계 원칙(변경 금지):
- 호출자는 절대 기다리지 않는다. 전송은 데몬 스레드에서 일어나고 이 모듈의
  함수는 즉시 리턴한다. **콘솔이 꺼져 있어도 npm install 차단/허용 흐름은
  100% 그대로 동작해야 한다.**
- 기본은 로컬 콘솔(127.0.0.1:8000). ``TRUSTGATE_CONSOLE_URL``로 바꿀 수 있고,
  빈 값으로 두면 전송 자체를 끈다.

인증이 없는 이유: 콘솔은 인증 없이 패키지 설치까지 실행하는 로컬 전용
도구다. 리포트 수집에만 인증을 붙이는 것은 앞뒤가 맞지 않으며, 실제 방어는
콘솔을 127.0.0.1에만 바인드하는 것으로 한다.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

CONSOLE_URL = os.getenv("TRUSTGATE_CONSOLE_URL", "http://127.0.0.1:8000").strip().rstrip("/")
REPORT_TIMEOUT_SEC = 3

# CLI처럼 수명이 짧은 프로세스는 종료 시 데몬 스레드가 그대로 죽어 전송이
# 유실된다. flush_reports()로 짧게 기다려 줄 수 있게 보관한다.
_pending_lock = threading.Lock()
_pending: list[threading.Thread] = []


def _client_name() -> str:
    return os.getenv("TRUSTGATE_CLIENT", "safe-npm")


def _post(path: str, payload: dict, label: str) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        f"{CONSOLE_URL}{path}", data=body, method="POST",
        headers={"Content-Type": "application/json; charset=utf-8"},
    )
    try:
        urllib.request.urlopen(req, timeout=REPORT_TIMEOUT_SEC).close()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        # fire-and-forget: 콘솔이 꺼져 있어도 설치 흐름엔 영향 없음
        sys.stderr.write(f"[report] {label} 전송 실패 (무시하고 진행): {exc}\n")


def _spawn(fn) -> None:
    thread = threading.Thread(target=fn, daemon=True)
    with _pending_lock:
        # 끝난 스레드는 버린다 — 정리하지 않으면 죽은 Thread 객체가 계속 쌓인다.
        _pending[:] = [t for t in _pending if t.is_alive()]
        _pending.append(thread)
    thread.start()


def report_event(event: str, scan: dict, extra: dict | None = None) -> None:
    """스캔/설치/차단 결과를 콘솔로 보낸다 (즉시 리턴)."""
    if not CONSOLE_URL:
        return

    def _send():
        _post("/api/ingest", {
            "event": event,
            "source": _client_name(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan": scan,
            "extra": extra or {},
        }, event)

    _spawn(_send)


def report_inventory(inventory: dict) -> None:
    """이 PC에 설치된 패키지 목록(스냅샷)을 콘솔로 보낸다."""
    if not CONSOLE_URL or not inventory:
        return

    def _send():
        _post("/api/ingest-inventory", {
            "source": _client_name(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **inventory,
        }, "인벤토리")

    _spawn(_send)


def flush_reports(timeout: float = REPORT_TIMEOUT_SEC + 1) -> None:
    """전송이 끝날 때까지 짧게 기다린다 (CLI 종료 직전용).

    수명이 긴 콘솔은 부를 필요가 없다. CLI는 마지막 이벤트를 쏘자마자 프로세스가
    끝나 데몬 스레드가 죽으므로 종료 전에 한 번 불러 준다. 설치 **판정**을 막지
    않고, 이미 모든 작업이 끝난 시점에만 상한을 두고 기다린다.
    """
    if not CONSOLE_URL:
        return
    with _pending_lock:
        threads = list(_pending)
        _pending.clear()
    deadline = time.monotonic() + timeout
    for thread in threads:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        thread.join(timeout=remaining)


__all__ = ["report_event", "report_inventory", "flush_reports", "CONSOLE_URL"]

"""스캔·설치 이력과 설치된 패키지 목록을 로컬 SQLite에 보관한다.

콘솔이 메모리 배열만 쓰던 시절에는 서버를 재시작하면 대시보드가 비었다.
이 모듈이 그 기록을 파일로 남긴다.

대시보드 전용이다 — 터미널 CLI는 이 저장소를 직접 만지지 않고 HTTP로
`/api/ingest`에 보내기만 한다(reporting.py). 그래서 dashboard/ 안에 둔다.

인증이 없는 이유: 이 저장소를 쓰는 콘솔은 애초에 인증 없이 패키지 설치까지
실행하는 **로컬 전용 도구**다. 리포트 수집에만 별도 인증을 붙이는 것은
앞뒤가 맞지 않고, 실제 방어는 "127.0.0.1에만 바인드한다"로 한다.
"""

from __future__ import annotations

import functools
import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

DB_PATH = Path(os.getenv("TRUSTGATE_DB_PATH", "") or (Path.home() / ".trustgate" / "history.sqlite3"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

_conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
_conn.row_factory = sqlite3.Row

# ThreadingHTTPServer는 요청마다 스레드를 만든다. check_same_thread=False는
# "동시에 써도 된다"가 아니라 "검사를 끈다"는 뜻이라, 직렬화하지 않으면
# sqlite3.InterfaceError가 난다.
_db_lock = threading.RLock()


def _with_db(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        with _db_lock:
            return fn(*args, **kwargs)
    return wrapper


_conn.executescript("""
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,              -- scan / install / block / cooldown_hold
    source TEXT,                      -- console / safe-npm
    package_name TEXT,
    package_version TEXT,
    verdict TEXT,
    score INTEGER,
    reason TEXT,
    rules_json TEXT,                  -- 규칙별 점수·밴드·신호 (드릴다운용)
    tracks_json TEXT,
    timing_json TEXT,
    extra_json TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_pkg ON events(package_name);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);

-- 프로젝트별 "지금 설치된 패키지" 스냅샷 (흐름이 아니라 상태)
CREATE TABLE IF NOT EXISTS inventory (
    project_key TEXT NOT NULL,
    project TEXT,
    package_name TEXT NOT NULL,
    version TEXT,
    spec TEXT,
    dev INTEGER DEFAULT 0,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inv_pkg ON inventory(package_name);
CREATE INDEX IF NOT EXISTS idx_inv_proj ON inventory(project_key);
""")
_conn.commit()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@_with_db
def record_event(event: str, scan: dict, source: str = "console", extra: dict | None = None) -> None:
    """스캔/설치 결과를 남긴다. 저장 실패가 판정 흐름을 막으면 안 되므로
    호출부에서 예외를 삼키도록 되어 있다."""
    pkg = scan.get("package") or {}
    _conn.execute(
        """INSERT INTO events
           (event, source, package_name, package_version, verdict, score, reason,
            rules_json, tracks_json, timing_json, extra_json, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (event, source, pkg.get("name"), pkg.get("version"),
         scan.get("verdict"), scan.get("score"), scan.get("reason"),
         json.dumps(scan.get("rules"), ensure_ascii=False),
         json.dumps(scan.get("track_statuses"), ensure_ascii=False),
         json.dumps(scan.get("timing"), ensure_ascii=False),
         json.dumps(extra or {}, ensure_ascii=False),
         _now()),
    )
    _conn.commit()


@_with_db
def save_inventory(project: str, project_key: str, packages: list) -> int:
    """한 프로젝트의 설치 목록을 통째로 교체한다(스냅샷). 증분이 아니라
    전체 교체라 삭제된 패키지가 유령처럼 남지 않는다."""
    now = _now()
    with _conn:
        _conn.execute("DELETE FROM inventory WHERE project_key = ?", (project_key,))
        rows = [
            (project_key, project, str(p.get("name"))[:214],
             (str(p["version"])[:64] if p.get("version") else None),
             (str(p["spec"])[:64] if p.get("spec") else None),
             1 if p.get("dev") else 0, now)
            for p in packages if isinstance(p, dict) and p.get("name")
        ]
        _conn.executemany(
            """INSERT INTO inventory (project_key, project, package_name, version, spec, dev, updated_at)
               VALUES (?,?,?,?,?,?,?)""", rows)
    return len(rows)


def _row_to_event(r: sqlite3.Row) -> dict:
    return {
        "id": r["id"], "event": r["event"], "source": r["source"],
        "package_name": r["package_name"], "package_version": r["package_version"],
        "verdict": r["verdict"], "score": r["score"], "reason": r["reason"],
        "rules": json.loads(r["rules_json"]) if r["rules_json"] else None,
        "track_statuses": json.loads(r["tracks_json"]) if r["tracks_json"] else None,
        "timing": json.loads(r["timing_json"]) if r["timing_json"] else None,
        "extra": json.loads(r["extra_json"]) if r["extra_json"] else None,
        "created_at": r["created_at"],
    }


@_with_db
def history(limit: int = 100, event: str = "", verdict: str = "", q: str = "") -> list[dict]:
    where, params = [], []
    if event:
        where.append("event = ?"); params.append(event)
    if verdict:
        where.append("verdict = ?"); params.append(verdict)
    if q:
        where.append("(package_name LIKE ? OR source LIKE ?)"); params += [f"%{q}%"] * 2
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    rows = _conn.execute(
        f"SELECT * FROM events {clause} ORDER BY id DESC LIMIT ?", (*params, limit)).fetchall()
    return [_row_to_event(r) for r in rows]


# 판정이 실린 이벤트만 고른다. cooldown_hold는 계보 수집을 건너뛴 보류라
# 규칙 정보가 비어 있어, "이 패키지의 마지막 판정"으로 쓰면 오해를 준다.
_VERDICT_EVENTS = "event IN ('scan','install','block') AND package_name IS NOT NULL AND verdict IS NOT NULL"


@_with_db
def latest_scans(limit: int = 200) -> list[dict]:
    """패키지별 **가장 최근 판정** 하나씩. 최신순.

    Package Explorer와 Installed Packages가 이걸 읽는다. 그 두 화면은 원래
    브라우저 메모리의 이번 세션 스캔만 보여줘서, 터미널(safe-npm)에서 일어난
    설치가 전혀 보이지 않았다.
    """
    rows = _conn.execute(
        f"""SELECT * FROM events
            WHERE {_VERDICT_EVENTS}
              AND id IN (SELECT MAX(id) FROM events WHERE {_VERDICT_EVENTS} GROUP BY package_name)
            ORDER BY id DESC LIMIT ?""", (limit,)).fetchall()
    return [_row_to_event(r) for r in rows]


@_with_db
def stats() -> dict[str, Any]:
    total = _conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    by_verdict = {r["verdict"]: r["c"] for r in _conn.execute(
        "SELECT verdict, COUNT(*) c FROM events WHERE event='scan' GROUP BY verdict")}
    blocked = _conn.execute("SELECT COUNT(*) c FROM events WHERE event='block'").fetchone()["c"]
    installed = _conn.execute("SELECT COUNT(*) c FROM events WHERE event='install'").fetchone()["c"]
    # created_at은 ISO(T구분자)이고 datetime('now')는 공백 구분자라, 문자열로
    # 비교하면 같은 날짜에서 'T'(0x54) > ' '(0x20) 때문에 잘못 걸린다.
    last_24h = _conn.execute(
        "SELECT COUNT(*) c FROM events WHERE datetime(created_at) >= datetime('now','-1 day')"
    ).fetchone()["c"]
    scans = sum(by_verdict.values())
    verifiable = scans - by_verdict.get("UNVERIFIABLE", 0)
    return {
        "total_events": total, "by_verdict": by_verdict, "blocked": blocked,
        "installed": installed, "last_24h": last_24h, "scans": scans,
        "verifiable_rate": round(verifiable / scans * 100) if scans else None,
        "db_path": str(DB_PATH),
    }


@_with_db
def timeseries(days: int = 14) -> list[dict]:
    rows = _conn.execute(
        """SELECT date(created_at) AS day,
                  SUM(event='scan') scans, SUM(event='block') blocks, SUM(event='install') installs
           FROM events WHERE datetime(created_at) >= datetime('now', ?)
           GROUP BY day ORDER BY day""", (f"-{days} day",)).fetchall()
    by_day = {r["day"]: r for r in rows}
    today = datetime.now(timezone.utc).date()
    out = []
    for off in range(days - 1, -1, -1):
        day = (today - timedelta(days=off)).isoformat()
        r = by_day.get(day)
        out.append({"day": day, "scans": r["scans"] if r else 0,
                    "blocks": r["blocks"] if r else 0, "installs": r["installs"] if r else 0})
    return out


@_with_db
def inventory_view(q: str = "") -> dict[str, Any]:
    where, params = ("WHERE package_name LIKE ?", [f"%{q}%"]) if q else ("", [])
    packages = [dict(r) for r in _conn.execute(
        f"""SELECT package_name, COUNT(DISTINCT project_key) project_count,
                   COUNT(DISTINCT version) version_count,
                   GROUP_CONCAT(DISTINCT version) versions
            FROM inventory {where}
            GROUP BY package_name
            ORDER BY version_count DESC, package_name LIMIT 300""", params)]
    for p in packages:
        p["versions"] = sorted(v for v in (p["versions"] or "").split(",") if v)
    projects = [dict(r) for r in _conn.execute(
        """SELECT project_key, project, COUNT(*) package_count, MAX(updated_at) updated_at
           FROM inventory GROUP BY project_key ORDER BY updated_at DESC""")]
    return {"packages": packages, "projects": projects}


__all__ = ["record_event", "save_inventory", "history", "latest_scans", "stats",
           "timeseries", "inventory_view", "DB_PATH"]

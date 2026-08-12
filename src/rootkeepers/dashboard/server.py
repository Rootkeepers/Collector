"""TrustGate Scan Console — 로컬 통합 서버.

collect_release_lineage_report + detailed_rule_engine을 실제로 호출해
대시보드(dashboard/static/console.html)에 JSON으로 서빙하는 stdlib-only HTTP 서버.
외부 프레임워크 의존성 없이 http.server만 사용한다.

실행:
    python -m rootkeepers.dashboard [--port 8000]   # 포그라운드
    trustgate up                                     # 백그라운드

그다음 브라우저에서 http://localhost:8000 접속.

이 모듈은 서버를 띄우는 일만 한다. 백그라운드 실행·정지·상태 조회는
``trustgate`` CLI(rootkeepers/cli.py)가 background.py를 통해 담당한다.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import subprocess
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# 패키지를 import하려면 src/ 가 먼저 경로에 있어야 한다. 이 두 줄만 직접
# 계산하고, 나머지 경로는 전부 rootkeepers.paths 에서 가져온다.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from rootkeepers.paths import STATIC_DIR, load_env, project_dir  # noqa: E402

load_env()

# Windows의 mimetypes는 .woff2/.js를 모르는 경우가 있어 OS마다 응답 헤더가
# 달라진다. 직접 등록해 로컬과 컨테이너의 동작을 맞춘다.
mimetypes.add_type("font/woff2", ".woff2")
mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("text/css", ".css")

from rootkeepers.interceptor.cooldown import check_cooldown, get_latest_version  # noqa: E402
from rootkeepers.interceptor.cooldown_gate import read_baseline  # noqa: E402
from rootkeepers.interceptor.safe_npm import find_real_npm, CollectorError  # noqa: E402

DEFAULT_PROJECT_DIR = project_dir()
INSTALL_TIMEOUT_SEC = 180

# 리포팅·스캔 로직은 CLI 래퍼(safe-npm)와 공유한다 — 같은 패키지에 대해
# 터미널과 대시보드가 다른 판정을 내놓지 않도록 하기 위함이다.
from rootkeepers.dashboard import background, store  # noqa: E402
from rootkeepers.interceptor.scanning import scan_package  # noqa: E402


def _pipeline_nodes(package_name, scan) -> list[dict]:
    """스캔 결과를 Decision Flow 패널이 쓰는 노드 목록으로 정리한다.

    각 노드의 status/detail은 전부 이번 스캔에서 실제로 나온 값이다 —
    화면상 노드 순서(버전 확인 → 쿨다운 → GitHub 계보 → Sigstore → 규칙 평가
    → 최종 판정)는 실제 실행 순서(lineage.py)와 cooldown_gate.py의 흐름을
    그대로 반영한다.
    """
    report = scan.get("raw_report", {})
    cooldown = scan.get("cooldown", {})

    tracks = report.get("tracks", {})
    npm_track = tracks.get("npm", {})
    github_track = tracks.get("github", {})
    sigstore_track = tracks.get("sigstore", {})
    pipeline = report.get("pipeline", {}).get("npm_to_github", {})

    npm_data = npm_track.get("data") or {}
    npm_package = npm_data.get("package", {})
    npm_artifact = npm_data.get("artifact", {})

    decision = scan
    activated = [r for r in decision["rules"] if r["band"] in ("WARN", "RISK")]

    nodes = [
        {
            "id": "resolve_version",
            "label": "버전 확인 (npm)",
            "status": npm_track.get("status", "UNKNOWN"),
            "detail": {
                "package": package_name,
                "resolved_version": report.get("package", {}).get("version"),
                "published_at": npm_package.get("published_at"),
                "attestation": npm_artifact.get("attestation"),
                "git_head": npm_artifact.get("git_head"),
                "repo_url": npm_artifact.get("repo_url"),
                "error": npm_track.get("error"),
            },
        },
        {
            "id": "cooldown",
            "label": "쿨다운 게이트",
            "status": "PASS" if cooldown.get("passed") else "HOLD",
            "detail": {
                "published": cooldown.get("published"),
                "age_days": cooldown.get("age_days"),
                "remain_days": cooldown.get("remain_days"),
                "reason": cooldown.get("reason"),
            },
        },
        {
            "id": "lineage",
            "label": "GitHub 계보 수집",
            "status": github_track.get("status", "UNKNOWN"),
            "detail": {
                "owner_repo": pipeline.get("github_lookup", {}).get("owner_repo"),
                "git_head": pipeline.get("github_lookup", {}).get("git_head"),
                "commit_source": pipeline.get("github_lookup", {}).get("commit_source"),
                "commit": (github_track.get("data") or {}).get("commit"),
                "error": github_track.get("error"),
            },
        },
        {
            "id": "sigstore",
            "label": "Sigstore / OIDC",
            "status": sigstore_track.get("status", "UNKNOWN"),
            "detail": {
                "slsa_predicate": (sigstore_track.get("data") or {}).get("slsa_predicate"),
                "fulcio_oidc": (sigstore_track.get("data") or {}).get("fulcio_oidc"),
                "error": sigstore_track.get("error"),
            },
        },
        {
            "id": "rule_engine",
            "label": "규칙 엔진 평가",
            "status": (
                "RISK" if decision["verdict"] == "RISK"
                else "WARN" if activated
                else "UNVERIFIABLE" if decision["verdict"] == "UNVERIFIABLE"
                else "PASS"
            ),
            "detail": {
                "activated_rules": [r["id"] for r in activated],
                "activated_rule_count": decision["corroboration"]["activated_rule_count"],
                "risk_band_rule_count": decision["corroboration"]["risk_band_rule_count"],
                "corroboration_bonus": decision["corroboration"]["bonus"],
            },
        },
        {
            "id": "decision",
            "label": "최종 판정",
            "status": decision["verdict"],
            "detail": {
                "score": decision["score"],
                "threshold": decision["threshold"],
                "reason": decision["reason"],
            },
        },
    ]
    return nodes


def run_scan(package_name: str, version: str | None) -> dict:
    """공용 scan_package()로 실제 수집·채점을 돌리고, 콘솔이 쓰는 JSON을 만든다.

    판정 자체는 CLI 래퍼(safe-npm)와 완전히 동일한 코드 경로를 탄다.
    여기서는 Decision Flow 패널용 파이프라인 노드만 덧붙인다.
    """
    result = scan_package(package_name, version)
    result["pipeline"] = _pipeline_nodes(package_name, result)
    result.pop("raw_report", None)
    _record("scan", result)
    return result


def _record(event: str, scan: dict, source: str = "console", extra: dict | None = None) -> None:
    """이력을 남긴다. 저장 실패가 스캔·설치 흐름을 막아서는 안 된다."""
    try:
        store.record_event(event, scan, source=source, extra=extra)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"[store] 이력 저장 실패 (무시하고 진행): {exc}\n")


def list_installed(project_dir: Path) -> dict:
    """project_dir의 package.json/package-lock.json을 읽어 설치된 패키지별
    쿨다운 상태를 정리한다. 실제 npm 레지스트리 조회(get_latest_version,
    check_cooldown)를 그대로 사용한다 — 지어낸 값 없음.
    """
    pkg_json_path = project_dir / "package.json"
    lock_path = project_dir / "package-lock.json"
    if not pkg_json_path.exists():
        raise FileNotFoundError(f"{pkg_json_path}에 package.json이 없습니다.")

    with open(pkg_json_path, encoding="utf-8") as f:
        pkg_json = json.load(f)
    names = sorted({
        *pkg_json.get("dependencies", {}).keys(),
        *pkg_json.get("devDependencies", {}).keys(),
    })

    # 이력에 남은 마지막 판정을 함께 실어 보낸다 — 콘솔 스캔이든 터미널
    # safe-npm이든, 이미 판정한 패키지를 다시 "미검사"로 보여주지 않도록.
    try:
        last_by_name = {e["package_name"]: e for e in store.latest_scans()}
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"[store] 마지막 판정 조회 실패 (무시하고 진행): {exc}\n")
        last_by_name = {}

    rows = []
    for name in names:
        installed_version = read_baseline(name, lockfile=str(lock_path)) if lock_path.exists() else None
        latest_version = get_latest_version(name)
        cooldown = None
        if latest_version and installed_version != latest_version:
            cd = check_cooldown(name, latest_version)
            cooldown = {
                "passed": cd.passed,
                "published": cd.published.isoformat() if cd.published else None,
                "age_days": round(cd.age_days, 2) if cd.age_days is not None else None,
                "remain_days": round(cd.remain_days, 2) if cd.remain_days is not None else None,
                "reason": cd.reason,
            }
        last = last_by_name.get(name)
        rows.append({
            "name": name,
            "installed_version": installed_version,
            "latest_version": latest_version,
            "up_to_date": bool(latest_version) and installed_version == latest_version,
            "cooldown": cooldown,
            "last_scan": None if last is None else {
                "verdict": last["verdict"], "score": last["score"], "reason": last["reason"],
                "version": last["package_version"], "source": last["source"],
                "event": last["event"], "created_at": last["created_at"],
            },
        })
    return {"ok": True, "project": str(project_dir), "packages": rows}


def run_install(package_name: str, version: str, project_dir: Path) -> dict:
    """설치 직전 후보 버전을 실제 규칙 엔진으로 재검증하고, RISK가 아니면
    실제 npm install을 실행한다. 쿨다운 통과 여부와 무관하게 이 마지막
    검증은 항상 수행한다 (조기 승인 경로도 여기로 들어온다).
    """
    scan = run_scan(package_name, version)  # already fires its own "scan" report event
    if scan["verdict"] == "RISK":
        _record("block", scan, extra={"project": str(project_dir)})
        return {
            "ok": False, "blocked": True,
            "verdict": scan["verdict"], "score": scan["score"], "reason": scan["reason"],
            "message": "RISK 판정으로 설치가 차단되었습니다.",
        }

    try:
        npm_path = find_real_npm()
    except CollectorError as exc:
        return {"ok": False, "blocked": False, "error": str(exc)}

    try:
        proc = subprocess.run(
            [npm_path, "install", f"{package_name}@{version}"],
            cwd=str(project_dir), capture_output=True, text=True, timeout=INSTALL_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "blocked": False, "error": f"npm install이 {INSTALL_TIMEOUT_SEC}초 내에 끝나지 않았습니다."}

    _record("install", scan, extra={"project": str(project_dir), "install_returncode": proc.returncode})
    return {
        "ok": proc.returncode == 0, "blocked": False,
        "verdict": scan["verdict"], "score": scan["score"], "reason": scan["reason"],
        "returncode": proc.returncode,
        "stdout": proc.stdout[-4000:], "stderr": proc.stderr[-4000:],
        "project": str(project_dir),
    }


def run_early_approve(package_name: str, installed_version: str, candidate_version: str) -> dict:
    """cooldown_gate.gate_package()의 '조기 승인(EARLY_APPROVE)' 분기를
    그대로 재현한다 — 단, verify()로 가짜 True 대신 실제 규칙 엔진 결과를 쓴다.

    쿨다운이 아직 안 지났어도, 현재 설치된 버전(기준선)과 신버전 후보가
    둘 다 RISK가 아니면 조기 승인 — 기준선 자체가 RISK면 전체 차단, 신버전만
    RISK면 조기 승인 거부(쿨다운 유지)로 gate_package()와 동일하게 갈린다.
    """
    baseline_scan = run_scan(package_name, installed_version) if installed_version else None
    if baseline_scan is not None and baseline_scan["verdict"] == "RISK":
        return {
            "ok": True, "approved": False, "stage": "baseline",
            "message": f"설치된 버전({installed_version}) 자체가 RISK 판정 — 기준선을 신뢰할 수 없어 전체 차단합니다.",
            "baseline_scan": baseline_scan, "candidate_scan": None,
        }

    candidate_scan = run_scan(package_name, candidate_version)
    if candidate_scan["verdict"] == "RISK":
        return {
            "ok": True, "approved": False, "stage": "candidate",
            "message": "신버전이 RISK 판정 — 조기 승인 거부, 쿨다운을 유지합니다.",
            "baseline_scan": baseline_scan, "candidate_scan": candidate_scan,
        }

    return {
        "ok": True, "approved": True, "stage": "both",
        "message": "기준선·신버전 모두 RISK가 아니므로 쿨다운 잔여 기간과 무관하게 조기 승인합니다.",
        "baseline_scan": baseline_scan, "candidate_scan": candidate_scan,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "TrustGateConsole/0.1"

    def log_message(self, fmt, *args):  # quieter default logging
        sys.stderr.write("[server] " + (fmt % args) + "\n")

    def handle_one_request(self):
        """클라이언트가 응답을 다 받기 전에 끊는 경우를 조용히 넘긴다.

        헬스체크나 새로고침처럼 연결을 먼저 닫는 클라이언트 때문에
        BrokenPipeError 스택트레이스가 로그를 뒤덮으면, 정작 봐야 할
        진짜 예외가 묻힌다.
        """
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def _send_json(self, status: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path, content_type: str):
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 (stdlib naming)
        parsed = urlparse(self.path)

        if parsed.path == "/api/scan":
            qs = parse_qs(parsed.query)
            package = (qs.get("package") or [""])[0].strip()
            version = (qs.get("version") or [""])[0].strip() or None
            if not package:
                self._send_json(400, {"ok": False, "error": "package 파라미터가 필요합니다."})
                return
            try:
                result = run_scan(package, version)
                self._send_json(200, result)
            except Exception as exc:  # noqa: BLE001 — surface any collector failure as JSON
                traceback.print_exc()
                self._send_json(200, {
                    "ok": False,
                    "error": f"{exc.__class__.__name__}: {exc}",
                    "package": {"name": package, "version": version},
                })
            return

        if parsed.path == "/api/health":
            self._send_json(200, {
                "ok": True,
                "github_token_configured": bool(os.getenv("GITHUB_TOKEN")),
                "default_project": str(DEFAULT_PROJECT_DIR),
                "db_path": str(store.DB_PATH),
            })
            return

        if parsed.path == "/api/history":
            qs = parse_qs(parsed.query)
            self._send_json(200, {
                "stats": store.stats(),
                "days": store.timeseries(_int_param(qs, "days", 14, 1, 90)),
                "events": store.history(
                    _int_param(qs, "limit", 100, 1, 500),
                    event=(qs.get("event") or [""])[0].strip(),
                    verdict=(qs.get("verdict") or [""])[0].strip(),
                    q=(qs.get("q") or [""])[0].strip(),
                ),
                "inventory": store.inventory_view((qs.get("pkg") or [""])[0].strip()),
            })
            return

        if parsed.path == "/api/scans":
            qs = parse_qs(parsed.query)
            try:
                self._send_json(200, {
                    "ok": True,
                    "scans": store.latest_scans(_int_param(qs, "limit", 200, 1, 500)),
                })
            except Exception as exc:  # noqa: BLE001
                traceback.print_exc()
                self._send_json(200, {"ok": False, "error": f"{exc.__class__.__name__}: {exc}"})
            return

        if parsed.path == "/api/installed":
            qs = parse_qs(parsed.query)
            project = (qs.get("project") or [""])[0].strip()
            project_dir = Path(project) if project else DEFAULT_PROJECT_DIR
            try:
                self._send_json(200, list_installed(project_dir))
            except Exception as exc:  # noqa: BLE001
                traceback.print_exc()
                self._send_json(200, {"ok": False, "error": f"{exc.__class__.__name__}: {exc}"})
            return

        # static files — dashboard/static/ 밖은 절대 내보내지 않는다
        rel = parsed.path.lstrip("/") or "console.html"
        file_path = (STATIC_DIR / rel).resolve()
        if STATIC_DIR not in file_path.parents and file_path != STATIC_DIR / rel:
            self.send_error(403)
            return
        if not file_path.exists() or not file_path.is_file():
            self.send_error(404)
            return
        content_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        self._send_file(file_path, content_type)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8") or "{}")

    def do_POST(self):  # noqa: N802
        parsed = urlparse(self.path)

        if parsed.path == "/api/early_approve":
            try:
                payload = self._read_json_body()
            except Exception:
                self._send_json(400, {"ok": False, "error": "잘못된 JSON body"})
                return
            package = (payload.get("package") or "").strip()
            installed_version = (payload.get("installed_version") or "").strip() or None
            candidate_version = (payload.get("candidate_version") or "").strip()
            if not package or not candidate_version:
                self._send_json(400, {"ok": False, "error": "package/candidate_version이 필요합니다."})
                return
            try:
                self._send_json(200, run_early_approve(package, installed_version, candidate_version))
            except Exception as exc:  # noqa: BLE001
                traceback.print_exc()
                self._send_json(200, {"ok": False, "error": f"{exc.__class__.__name__}: {exc}"})
            return

        if parsed.path == "/api/ingest":
            # safe-npm CLI 가 터미널에서 한 일을 이력에 남긴다.
            # (콘솔이 직접 스캔한 것은 run_scan 에서 이미 기록된다)
            try:
                payload = self._read_json_body()
            except Exception:
                self._send_json(400, {"ok": False, "error": "잘못된 JSON body"})
                return
            scan = payload.get("scan") or {}
            _record(payload.get("event") or "scan", scan,
                    source=payload.get("source") or "safe-npm",
                    extra=payload.get("extra"))
            self._send_json(200, {"ok": True})
            return

        if parsed.path == "/api/ingest-inventory":
            try:
                payload = self._read_json_body()
            except Exception:
                self._send_json(400, {"ok": False, "error": "잘못된 JSON body"})
                return
            key = payload.get("project_key")
            packages = payload.get("packages")
            if not key or not isinstance(packages, list):
                self._send_json(400, {"ok": False, "error": "project_key/packages 가 필요합니다."})
                return
            try:
                n = store.save_inventory(payload.get("project"), key, packages)
            except Exception as exc:  # noqa: BLE001
                self._send_json(200, {"ok": False, "error": str(exc)})
                return
            self._send_json(200, {"ok": True, "packages": n})
            return

        if parsed.path == "/api/install":
            try:
                payload = self._read_json_body()
            except Exception:
                self._send_json(400, {"ok": False, "error": "잘못된 JSON body"})
                return
            package = (payload.get("package") or "").strip()
            version = (payload.get("version") or "").strip()
            project = (payload.get("project") or "").strip()
            project_dir = Path(project) if project else DEFAULT_PROJECT_DIR
            if not package or not version:
                self._send_json(400, {"ok": False, "error": "package/version이 필요합니다."})
                return
            try:
                self._send_json(200, run_install(package, version, project_dir))
            except Exception as exc:  # noqa: BLE001
                traceback.print_exc()
                self._send_json(200, {"ok": False, "error": f"{exc.__class__.__name__}: {exc}"})
            return

        self.send_error(404)


def _int_param(qs: dict, name: str, default: int, low: int, high: int) -> int:
    """쿼리 파라미터를 안전하게 정수로 읽는다.

    ``?limit=abc`` 에 int()를 그냥 쓰면 ValueError가 핸들러 밖으로 나가
    요청이 응답 없이 끊긴다. 파싱 실패는 기본값으로 되돌리고 범위를 강제한다.
    """
    raw = (qs.get(name) or [""])[0].strip()
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(low, min(high, value))


class ConsoleHTTPServer(ThreadingHTTPServer):
    """동시 접속을 견디도록 조정 — 기본 accept 큐(5)는 너무 작다."""

    request_queue_size = 128
    daemon_threads = True
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=int(os.getenv("TRUSTGATE_PORT", "8000")))
    # 기본값은 루프백 — 개발자 PC에서 실행할 때 실수로 외부에 노출되지 않게 한다.
    # 컨테이너에서는 127.0.0.1에 묶으면 포트를 매핑해도 밖에서 닿지 않으므로
    # Dockerfile.console 이 --host 0.0.0.0 을 명시적으로 넘긴다.
    parser.add_argument("--host", default=os.getenv("TRUSTGATE_HOST", "127.0.0.1"))
    parser.add_argument("--project", default=os.getenv("TRUSTGATE_PROJECT_DIR", ""),
                        help="Installed Packages 기본 프로젝트 경로")
    args = parser.parse_args()

    global DEFAULT_PROJECT_DIR
    if args.project:
        DEFAULT_PROJECT_DIR = Path(args.project)

    if not os.getenv("GITHUB_TOKEN"):
        print("[경고] GITHUB_TOKEN이 설정되지 않았습니다 — GitHub 트랙 수집이 실패합니다.", file=sys.stderr)

    httpd = ConsoleHTTPServer((args.host, args.port), Handler)
    print(f"TrustGate Scan Console → http://{args.host}:{args.port}")
    print(f"  기본 프로젝트: {DEFAULT_PROJECT_DIR}")
    if args.host == "0.0.0.0":  # noqa: S104 — 컨테이너에서는 의도된 설정
        print("  [주의] 모든 인터페이스에 열려 있습니다. 이 콘솔은 인증이 없고")
        print("         패키지 설치를 실행할 수 있으므로 신뢰된 네트워크에서만 노출하세요.")
    # 포그라운드로 띄운 것도 기록해야 trustgate status가 "실행 중이 아님"이라고
    # 거짓말하지 않고, trustgate down 으로 끌 수 있다.
    background.write_record(args.host, args.port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        background.clear_record()
    return 0


if __name__ == "__main__":
    sys.exit(main())

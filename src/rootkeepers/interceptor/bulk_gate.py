"""인자 없는 ``npm install`` / ``npm ci``를 위한 lock 기준 일괄 점검.

`safe-npm install lodash`처럼 패키지를 지목한 설치는 계보(Track A/B/C) 수집과
쿨다운까지 거친다. 그러나 clone 직후나 팀원의 의존성 추가를 pull 받은 뒤에
실제로 더 자주 실행되는 것은 **인자 없는** ``npm install``과 ``npm ci``이고,
이때 깔리는 것은 직접 의존성이 아니라 lock에 적힌 전이 의존성 전체다.

전이 의존성 수백~수천 개에 계보 수집을 그대로 적용하면 설치가 사실상 멈춘다.
그래서 이 모듈은 **비용이 상수에 가까운 것만** 한다:

- lock 파일에서 실제로 깔릴 정확한 버전 전체를 읽고 (네트워크 없음)
- OSV querybatch로 알려진 취약 버전을 **요청 한 번**에 확인한다.

이것은 계보 검증의 대체물이 아니라 커버리지 0을 면하기 위한 하한선이다.
사용자에게도 그렇게 보여야 하므로 출력에서 "무엇을 확인하지 않았는지"를
반드시 함께 말한다.

기본 동작은 **차단이 아닌 경고**다. 알려진 CVE는 규모가 있는 프로젝트라면
대개 몇 개씩 걸리고, 그걸로 설치를 막으면 도구가 곧 우회당한다. 차단이 필요한
환경(CI 등)은 ``TRUSTGATE_BULK_STRICT=1``로 켠다.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import json
from rootkeepers.analysis.monitoring import scan_packages
from rootkeepers.interceptor.inventory import collect_lock_packages
from rootkeepers.interceptor.reporting import report_event
from rootkeepers.interceptor.scanning import scan_package

# lock 생성은 레지스트리를 타므로 무한정 기다리지 않는다. 설치 앞단이라
# 사용자가 체감하는 지연에 그대로 더해진다.
_LOCK_TIMEOUT_SEC = 120

# 상세 출력이 터미널을 덮어버리지 않게 하는 상한. 잘린 개수는 반드시 함께
# 알린다 — 조용한 절단은 "다 봤다"로 읽힌다.
_MAX_LISTED = 15

# 계보를 수집할 패키지 수의 기본 상한. ``scan_package()``는 모듈 전역 락으로
# 직렬화되어 있어(scanning._scan_lock) 동시 실행이 되지 않는다. 즉 소요 시간은
# 패키지 수에 그대로 비례하고, 그 시간은 설치 앞단에서 사용자가 기다리는
# 시간이다. 상한을 두지 않으면 clone 직후 첫 설치가 몇십 분이 된다.
_DEFAULT_LINEAGE_MAX = 10


def _strict_mode() -> bool:
    return os.getenv("TRUSTGATE_BULK_STRICT", "").strip().lower() in {"1", "true", "yes", "on"}


def _lineage_max() -> int:
    """계보 수집 상한. 0이면 이 단계를 끈다."""
    raw = os.getenv("TRUSTGATE_LINEAGE_MAX", "").strip()
    if not raw:
        return _DEFAULT_LINEAGE_MAX
    try:
        return max(0, int(raw))
    except ValueError:
        return _DEFAULT_LINEAGE_MAX


def ensure_lockfile(project_dir: Path, npm_path: str) -> tuple[bool, str | None]:
    """점검 대상을 알기 위해 lock 파일을 확보한다.

    lock이 이미 있으면 아무것도 하지 않는다. 없으면 ``npm install
    --package-lock-only``로 **설치 없이** lock만 만든다. 이 플래그는
    node_modules를 건드리지 않고 의존성 해석만 수행하므로, 이 시점에 패키지
    코드가 디스크에 놓이거나 install 스크립트가 도는 일은 없다
    (``--ignore-scripts``를 함께 넘겨 한 번 더 못 박는다).

    이렇게까지 하는 이유는 순서 때문이다. lock 없이 그냥 설치하면 무엇이
    깔렸는지는 설치가 끝난 뒤에야 알 수 있고, 그때의 점검은 사후 통보다.
    lock을 먼저 만들면 설치 **전에** 같은 목록을 볼 수 있다.

    Returns:
        (사용 가능 여부, 실패 사유). 성공하면 사유가 None.
    """
    if (project_dir / "package-lock.json").exists():
        return True, None
    if not (project_dir / "package.json").exists():
        return False, "package.json이 없습니다."

    try:
        proc = subprocess.run(
            [npm_path, "install", "--package-lock-only", "--ignore-scripts"],
            cwd=str(project_dir), capture_output=True, text=True,
            timeout=_LOCK_TIMEOUT_SEC, check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"lock 생성이 {_LOCK_TIMEOUT_SEC}초 내에 끝나지 않았습니다."
    except OSError as exc:
        return False, f"lock 생성 실행 실패: {exc}"

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        return False, f"lock 생성 실패: {detail[-1] if detail else f'종료코드 {proc.returncode}'}"
    if not (project_dir / "package-lock.json").exists():
        return False, "lock 생성 후에도 package-lock.json을 찾지 못했습니다."
    return True, None


def precheck_lock(project_dir: Path, npm_path: str) -> dict[str, Any]:
    """설치될 전체 패키지 집합을 알려진 취약점 기준으로 점검한다.

    Returns:
        ``scan_packages()`` 결과에 ``lock_ok``/``reason``/``direct_only`` 등
        표시용 필드를 더한 dict. 점검 자체가 불가능한 경우
        ``status == "SKIPPED"``.
    """
    lock_ok, lock_error = ensure_lockfile(project_dir, npm_path)
    if not lock_ok:
        return {
            "status": "SKIPPED", "reason": lock_error, "lock_ok": False,
            "package_count": 0, "vulnerable_count": 0, "packages": [],
        }

    packages = collect_lock_packages(project_dir)
    if not packages:
        return {
            "status": "SKIPPED", "reason": "lock 파일에서 패키지를 읽지 못했습니다.",
            "lock_ok": True, "package_count": 0, "vulnerable_count": 0, "packages": [],
        }

    result = scan_packages(packages)
    result["lock_ok"] = True
    # 계보 단계는 설치 위치(path)와 dev 표시가 필요하다. OSV 결과 행에는 없으므로
    # lock에서 읽은 원본을 그대로 실어 보낸다 (lock을 두 번 읽지 않도록).
    result["lock_packages"] = packages
    return result


def _report_vulnerable(rows: list[dict[str, Any]], command: str) -> None:
    """취약 판정된 패키지를 이력에 남긴다.

    계보 점수가 없는 경로이므로 ``score``는 0으로 두고, 무엇을 근거로 한
    판정인지 reason에 명시한다 — 나중에 History에서 이 기록을 계보 판정과
    혼동하지 않도록.
    """
    for row in rows:
        report_event("bulk_vulnerable", {
            "package": {"name": row.get("name"), "version": row.get("version")},
            "verdict": "UNVERIFIABLE (RISK)",
            "score": 0,
            "reason": f"알려진 취약 버전 {row.get('count', 0)}건 (OSV, 계보 미검증)",
            "rules": [],
        }, {"command": command, "advisory_only": not _strict_mode()})


def _print_vulnerable_rows(rows: list[dict[str, Any]]) -> None:
    """취약 목록을 출력한다. 잘린 개수는 반드시 함께 알린다 —
    조용한 절단은 "이게 전부"로 읽힌다."""
    for row in rows[:_MAX_LISTED]:
        fix = row.get("recommended_version") or "공식 권고 확인"
        print(f"  - {row['name']}@{row['version']} · {row.get('count', 0)}건 · 조치: {fix}")
    if len(rows) > _MAX_LISTED:
        print(f"  ... 외 {len(rows) - _MAX_LISTED}개 (전체 목록: trustgate monitor --json)")


def _package_key(package: dict[str, Any]) -> tuple[str, str]:
    return (str(package.get("name")), str(package.get("version")))


def review_new_packages(
    project_dir: Path, before: list[dict[str, Any]], *, command: str,
    already_verified: set[tuple[str, str]] | None = None,
) -> bool:
    """설치 후 lock을 다시 읽어, **새로 들어온 패키지만** 점검한다.

    ``safe-npm install express``는 express 하나의 계보만 검증한다. 그러나 npm이
    실제로 깐 것은 express와 그 서브트리 전체이고, 설치 스크립트는 그 전체가
    돌린다. 지목 설치 경로에도 같은 구멍이 있었던 셈이다.

    설치 **전에** 서브트리를 알려면 의존성 해석을 먼저 돌려야 하는데, 그건
    지목 설치의 응답 시간에 그대로 더해진다. 대신 설치가 끝난 직후 lock의
    변화분을 보면 같은 목록을 얻을 수 있다. 이미 깔린 뒤라 차단은 못 하지만,
    "무엇이 함께 들어왔는지"를 사용자가 아는 것과 모르는 것은 다르다.

    변화분만 보는 이유는 비용이 아니라 신호 대 잡음이다. 매번 lock 전체를
    다시 읽어 경고하면 늘 같은 목록이 나와서 곧 무시된다.

    Args:
        project_dir: package.json이 있는 디렉터리.
        before: 설치 **전** ``collect_lock_packages()`` 결과.
        command: 표시용 커맨드 문자열.
        already_verified: 이미 계보(Track A/B/C)까지 검증을 마친 (name, version)
            집합 — 지목 설치의 대상 자신. react처럼 전이 의존성이 0개인
            패키지는 "새로 들어온 것"이 곧 지목한 패키지 자신이 되어, 방금
            [PASS] 판정을 받은 패키지를 이 함수가 "계보 검증 안 됨"으로 다시
            보고하는 모순이 생겼다. 이미 검증된 것은 여기서 제외한다.

    Returns:
        strict 모드에서 새 취약 패키지가 들어왔으면 False. 그 외에는 True.
        설치는 이미 끝났으므로 이 값은 종료 코드에만 반영된다.
    """
    seen = {_package_key(item) for item in before} | (already_verified or set())
    added = [item for item in collect_lock_packages(project_dir)
             if _package_key(item) not in seen]
    if not added:
        return True

    print(f"[사후] 이번 설치로 패키지 {len(added)}개가 새로 들어왔습니다 "
          f"(전이 의존성 포함). 알려진 취약 버전을 확인합니다...")
    result = scan_packages(added)

    if result["status"] == "ERROR":
        print(f"[미검사] 취약점 조회에 실패했습니다: {result.get('reason')}")
        print(f"         새로 들어온 {len(added)}개가 점검되지 않았습니다.")
        return True

    rows = [row for row in result.get("packages") or [] if row.get("status") == "VULNERABLE"]
    if not rows:
        print(f"[확인] 새로 들어온 {len(added)}개 · 알려진 취약 버전 없음")
    else:
        print(f"[경고] 새로 들어온 {len(added)}개 중 {len(rows)}개가 알려진 취약 버전입니다.")
        _print_vulnerable_rows(rows)
        _report_vulnerable(rows, command)

    if result.get("error_count"):
        print(f"[주의] {result['error_count']}개는 조회에 실패해 판정하지 못했습니다.")

    print(f"[미검사] 새로 들어온 {len(added)}개에 대해 계보 검증(Track A/B/C)은 "
          f"수행되지 않았습니다. 지목한 패키지 하나만 검증됩니다.")

    if rows and _strict_mode():
        print("[STRICT] 설치는 이미 완료됐습니다. 종료 코드만 실패로 표시합니다.")
        return False
    return True


def _declared_names(project_dir: Path) -> set[str]:
    """package.json에 직접 선언된 의존성 이름."""
    try:
        with open(project_dir / "package.json", encoding="utf-8") as f:
            pkg_json = json.load(f)
    except (OSError, ValueError):
        return set()
    names: set[str] = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        names.update((pkg_json.get(section) or {}).keys())
    return names


def _already_on_disk(project_dir: Path, package: dict[str, Any]) -> bool:
    """이 버전이 이미 그 자리에 깔려 있는지 확인한다.

    같은 버전이 이미 디스크에 있으면 이번 설치로 **새 코드가 들어오지 않는다**.
    계보 수집은 비싸므로, 실제로 새로 들어오는 것에만 쓴다.

    lock의 키가 곧 설치 경로라 추측 없이 정확히 볼 수 있다. 중첩 설치로 같은
    (name, version)이 여러 경로에 있을 때는 처음 경로만 보는데, 어긋나면 이미
    있는 것을 한 번 더 검사할 뿐이라 안전한 쪽으로 틀린다.
    """
    path = package.get("path") or f"node_modules/{package['name']}"
    manifest = project_dir / path / "package.json"
    try:
        with open(manifest, encoding="utf-8") as f:
            return json.load(f).get("version") == package.get("version")
    except (OSError, ValueError):
        return False


def select_lineage_targets(
    project_dir: Path, packages: list[dict[str, Any]], limit: int
) -> tuple[list[dict[str, Any]], int]:
    """계보를 수집할 대상을 고른다.

    두 단계로 줄인다.

    1. **이미 같은 버전이 깔려 있는 것 제외** — 이번 설치로 새로 들어오는 코드가
       아니다. pull 이후의 `npm install`은 보통 여기서 한 자릿수로 줄어든다.
    2. **직접 의존성 우선, 그다음 상한** — 상한에 걸려야 한다면 내가 고른
       패키지를 먼저 본다. 전이 의존성이 더 위험하다는 것과는 별개로, 직접
       의존성은 사용자가 이름을 알고 있어 판정을 해석할 수 있다.

    Returns:
        (검사 대상, 상한 때문에 제외된 개수).
    """
    arriving = [item for item in packages if not _already_on_disk(project_dir, item)]
    declared = _declared_names(project_dir)
    arriving.sort(key=lambda item: (item["name"] not in declared, item["name"], item["version"]))
    if limit <= 0:
        return [], len(arriving)
    return arriving[:limit], max(0, len(arriving) - limit)


def scan_lineage(
    project_dir: Path, packages: list[dict[str, Any]], command: str
) -> tuple[bool, dict[str, Any]]:
    """새로 들어오는 패키지의 계보를 수집해 판정한다.

    지목 설치(`gate_install`)와 다른 점이 하나 있다. 거기서는 PASS가 아니면
    전부 차단하지만, 여기서는 **RISK만 차단하고 UNVERIFIABLE은 경고**한다.
    전이 의존성에는 GitHub 저장소가 아예 없거나 Sigstore 서명이 없는 패키지가
    흔해서, UNVERIFIABLE까지 막으면 정상 프로젝트의 첫 설치가 거의 항상
    멈춘다. 그러면 도구를 끄게 되고, 막아야 할 RISK도 같이 놓친다.

    Returns:
        (설치 진행 가능 여부, 요약 dict).
    """
    limit = _lineage_max()
    targets, dropped = select_lineage_targets(project_dir, packages, limit)
    summary = {
        "scanned": 0, "risk": [], "unverifiable": [], "failed": [],
        "dropped": dropped, "limit": limit,
    }
    if not targets:
        if dropped:
            # 상한이 0이거나 후보가 전부 잘린 경우 — 조용히 넘어가면 안 된다.
            print(f"[미검사] 새로 들어오는 {dropped}개의 계보를 검사하지 않았습니다 "
                  f"(TRUSTGATE_LINEAGE_MAX={limit}).")
        return True, summary

    print(f"[계보] 새로 들어오는 패키지 {len(targets)}개의 계보를 수집합니다 "
          f"(패키지당 수 초, 순차 실행)...")

    for index, item in enumerate(targets, 1):
        name, version = item["name"], item["version"]
        print(f"  ({index}/{len(targets)}) {name}@{version}", flush=True)
        try:
            scan = scan_package(name, version)
        except Exception as exc:  # noqa: BLE001 - 개별 실패가 전체를 막지 않는다
            summary["failed"].append({"name": name, "version": version, "error": str(exc)})
            print(f"    [ERROR] 계보 수집 실패: {exc}")
            continue

        summary["scanned"] += 1
        verdict = scan.get("verdict")
        report_event("scan", scan, {"command": command, "origin": "bulk_lineage"})
        if verdict == "RISK":
            summary["risk"].append(scan)
            print(f"    [BLOCKED] score={scan.get('score')} - {scan.get('reason')}")
            report_event("block", scan, {"command": command, "origin": "bulk_lineage"})
        elif verdict != "PASS":
            summary["unverifiable"].append(scan)
            print(f"    [WARN] 검증 불가 - {scan.get('reason')}")
        else:
            print(f"    [PASS] score={scan.get('score')}")

    if dropped:
        print(f"[미검사] 나머지 {dropped}개는 상한(TRUSTGATE_LINEAGE_MAX={limit})에 걸려 "
              f"계보를 보지 않았습니다.")
    if summary["unverifiable"]:
        print(f"[주의] {len(summary['unverifiable'])}개는 계보를 확인하지 못했습니다 "
              f"(차단하지 않음).")

    return not summary["risk"], summary


def gate_bulk_install(project_dir: Path, npm_path: str, command: str) -> bool:
    """일괄 점검을 수행하고 결과를 출력한다.

    Args:
        project_dir: package.json이 있는 디렉터리.
        npm_path: 실제 npm 실행 파일 경로.
        command: 사용자가 실행한 커맨드 표시용 문자열 ("npm install" 등).

    Returns:
        설치를 진행해도 되는지 여부. 계보 수집에서 RISK가 나오면 차단한다.
        알려진 취약 버전만으로는 차단하지 않는다(strict 모드 제외) — 판정
        근거의 성격이 다르기 때문이다. 모듈 docstring 참고.
    """
    print(f"[검사] {command}: lock 기준 일괄 점검을 시작합니다...")
    result = precheck_lock(project_dir, npm_path)

    if result["status"] == "SKIPPED":
        print(f"[미검사] 일괄 점검을 건너뜁니다: {result.get('reason')}")
        _print_coverage_notice(0, None)
        return True

    total = result.get("package_count", 0)
    rows: list[dict[str, Any]] = []

    # 1단계: 알려진 취약 버전 (요청 1회). 실패해도 2단계는 그대로 진행한다 —
    # 두 검사는 근거가 달라 서로를 대신하지 못한다.
    if result["status"] == "ERROR":
        print(f"[주의] 취약점 조회에 실패했습니다: {result.get('reason')}")
        print(f"       {total}개에 대해 알려진 취약 버전을 확인하지 못했습니다.")
    else:
        rows = [row for row in result.get("packages") or [] if row.get("status") == "VULNERABLE"]
        if not rows:
            print(f"[확인] 전이 의존성 포함 {total}개 · 알려진 취약 버전 없음")
        else:
            print(f"[경고] 전이 의존성 포함 {total}개 중 {len(rows)}개가 알려진 취약 버전입니다.")
            _print_vulnerable_rows(rows)
            _report_vulnerable(rows, command)
        if result.get("error_count"):
            print(f"[주의] {result['error_count']}개는 조회에 실패해 판정하지 못했습니다.")

    # 2단계: 새로 들어오는 것에 한해 계보 수집.
    allowed, lineage = scan_lineage(project_dir, result.get("lock_packages") or [], command)

    _print_coverage_notice(total, lineage)

    if not allowed:
        print(f"[HALTED] 계보 검증에서 RISK {len(lineage['risk'])}개가 나와 설치를 중단합니다.")
        return False
    if rows and _strict_mode():
        print("[HALTED] TRUSTGATE_BULK_STRICT=1 이므로 설치를 중단합니다.")
        return False
    return True


def _print_coverage_notice(total: int, lineage: dict[str, Any] | None) -> None:
    """검사한 것과 **하지 않은** 것을 숫자로 분명히 말한다.

    이 문구가 이 모듈에서 가장 중요한 출력이다. 일부만 검사하고 "검사 완료"처럼
    보이면, 사용자는 전체가 검증됐다고 믿은 채 설치하게 된다 — 원래의 커버리지
    0보다 오히려 나쁜 상태다. 그래서 분모를 항상 함께 적는다.
    """
    if not lineage or not total:
        scope = f"{total}개 패키지" if total else "이번 설치"
        print(f"[미검사] {scope}에 대해 계보 검증(Track A/B/C)은 수행되지 않았습니다.")
        print("         개별 패키지 계보까지 확인하려면: safe-npm install <패키지명>")
        return

    scanned = lineage["scanned"]
    if scanned:
        print(f"[범위] 계보 검증: {scanned}개 · 알려진 취약 버전만 확인: "
              f"{max(0, total - scanned)}개 (전체 {total}개)")
    else:
        print(f"[범위] 계보 검증: 0개 · 알려진 취약 버전만 확인: {total}개")
    print("         계보를 보는 대상은 이번 설치로 새로 들어오는 패키지뿐입니다. "
          "이미 깔려 있는 버전은 새 코드가 아니라 제외합니다.")


__all__ = [
    "ensure_lockfile", "precheck_lock", "gate_bulk_install",
    "review_new_packages", "select_lineage_targets", "scan_lineage",
]

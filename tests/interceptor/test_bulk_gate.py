"""인자 없는 npm install / npm ci 일괄 점검 테스트.

이 경로는 커버리지가 0이던 곳이라, "무엇을 검사했는가"보다 **"검사하지 않은
것을 사용자에게 말했는가"** 가 회귀의 핵심이다. 출력 문구도 함께 검증한다.

네트워크(OSV)와 npm 서브프로세스는 전부 가짜로 바꿔 끼운다.

실행: PYTHONPATH=src python3 -m pytest tests/interceptor/test_bulk_gate.py
"""

from __future__ import annotations

import json

import pytest

from rootkeepers.interceptor import bulk_gate
from rootkeepers.interceptor.inventory import collect_lock_packages


def _write_lock(tmp_path, payload: dict) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "demo", "dependencies": {"express": "^4.0.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(json.dumps(payload), encoding="utf-8")


def _fake_proc(returncode: int, stderr: str = "", stdout: str = ""):
    return type("P", (), {"returncode": returncode, "stdout": stdout, "stderr": stderr})()


@pytest.fixture(autouse=True)
def no_lineage_by_default(monkeypatch):
    """계보 수집은 네트워크를 탄다 — 명시적으로 켠 테스트에서만 돌게 한다.

    이 fixture가 없으면 게이트 테스트가 조용히 npm·GitHub·Sigstore를 호출해서,
    토큰이나 네트워크 상태에 따라 결과가 흔들린다.
    """
    monkeypatch.setenv("TRUSTGATE_LINEAGE_MAX", "0")
    monkeypatch.setattr(bulk_gate, "scan_package",
                        lambda *a, **k: pytest.fail("계보 수집이 예상치 못하게 실행됐다"))


# --------------------------------------------------------------------------
# collect_lock_packages: 전이 의존성 수집
# --------------------------------------------------------------------------

def test_collects_transitive_and_nested_packages(tmp_path):
    """직접 의존성만 보던 collect_inventory와 달리 lock 전체를 본다."""
    _write_lock(tmp_path, {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo"},
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/qs": {"version": "6.11.0", "dev": True},
            "node_modules/express/node_modules/qs": {"version": "6.9.7"},
        },
    })
    found = collect_lock_packages(tmp_path)
    assert {(p["name"], p["version"]) for p in found} == {
        ("express", "4.18.2"), ("qs", "6.11.0"), ("qs", "6.9.7"),
    }
    assert next(p for p in found if p["version"] == "6.11.0")["dev"] is True


def test_skips_project_root_and_workspace_links(tmp_path):
    """레지스트리에 없는 항목을 OSV에 물어봐야 무의미한 조회만 늘어난다."""
    _write_lock(tmp_path, {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo", "version": "1.0.0"},
            "packages/ui": {"version": "1.0.0"},
            "node_modules/ui": {"resolved": "packages/ui", "link": True},
            "node_modules/express": {"version": "4.18.2"},
        },
    })
    assert [p["name"] for p in collect_lock_packages(tmp_path)] == ["express"]


def test_deduplicates_identical_name_and_version(tmp_path):
    _write_lock(tmp_path, {
        "lockfileVersion": 3,
        "packages": {
            "node_modules/a/node_modules/ms": {"version": "2.1.3"},
            "node_modules/b/node_modules/ms": {"version": "2.1.3"},
        },
    })
    found = collect_lock_packages(tmp_path)
    assert [(p["name"], p["version"], p["dev"]) for p in found] == [("ms", "2.1.3", False)]
    # path는 "이 버전이 이미 디스크에 있는가"를 볼 때 쓴다 — 처음 만난 위치를 남긴다.
    assert found[0]["path"] == "node_modules/a/node_modules/ms"


def test_falls_back_to_lockfile_v1_tree(tmp_path):
    """npm 6 시절 lock을 그대로 쓰는 레포가 조용히 0개로 보이면 안 된다."""
    _write_lock(tmp_path, {
        "lockfileVersion": 1,
        "dependencies": {
            "express": {"version": "4.18.2", "dependencies": {"ms": {"version": "2.1.3"}}},
        },
    })
    assert {(p["name"], p["version"]) for p in collect_lock_packages(tmp_path)} == {
        ("express", "4.18.2"), ("ms", "2.1.3"),
    }


def test_returns_empty_without_lockfile(tmp_path):
    assert collect_lock_packages(tmp_path) == []


# --------------------------------------------------------------------------
# ensure_lockfile: lock이 없을 때만, 설치 없이 생성
# --------------------------------------------------------------------------

def test_existing_lock_is_not_regenerated(tmp_path, monkeypatch):
    _write_lock(tmp_path, {"lockfileVersion": 3, "packages": {}})
    monkeypatch.setattr(bulk_gate.subprocess, "run",
                        lambda *a, **k: pytest.fail("lock이 있는데 npm을 실행했다"))
    assert bulk_gate.ensure_lockfile(tmp_path, "npm") == (True, None)


def test_missing_lock_is_generated_without_installing(tmp_path, monkeypatch):
    """--package-lock-only 없이 만들면 점검 전에 코드가 먼저 깔린다."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
        return _fake_proc(0)

    monkeypatch.setattr(bulk_gate.subprocess, "run", fake_run)
    assert bulk_gate.ensure_lockfile(tmp_path, "npm") == (True, None)
    assert "--package-lock-only" in captured["cmd"]
    assert "--ignore-scripts" in captured["cmd"]


def test_lock_generation_failure_is_reported(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(bulk_gate.subprocess, "run",
                        lambda cmd, **kw: _fake_proc(1, stderr="ERR! 404 Not Found"))
    ok, reason = bulk_gate.ensure_lockfile(tmp_path, "npm")
    assert ok is False and "404" in reason


# --------------------------------------------------------------------------
# gate_bulk_install: 판정과 사용자 고지
# --------------------------------------------------------------------------

VULNERABLE_RESULT = {
    "status": "ACTION_REQUIRED", "package_count": 1, "vulnerable_count": 1,
    "error_count": 0,
    "packages": [{"name": "express", "version": "4.18.2", "status": "VULNERABLE",
                  "count": 2, "recommended_version": "4.19.2"}],
}


@pytest.fixture
def lock_project(tmp_path):
    _write_lock(tmp_path, {
        "lockfileVersion": 3,
        "packages": {"node_modules/express": {"version": "4.18.2"}},
    })
    return tmp_path


def test_clean_result_still_states_what_was_not_checked(lock_project, monkeypatch, capsys):
    """취약점이 없어도 계보 미검증 사실은 반드시 남아야 한다 — 이게 없으면
    '검사 완료'로 읽혀 원래의 커버리지 0보다 오히려 나쁘다."""
    monkeypatch.setattr(bulk_gate, "scan_packages", lambda pkgs, **kw: {
        "status": "CLEAN", "package_count": len(pkgs), "vulnerable_count": 0,
        "error_count": 0, "packages": [],
    })
    assert bulk_gate.gate_bulk_install(lock_project, "npm", "npm install") is True
    out = capsys.readouterr().out
    # 검사한 것과 안 한 것을 숫자로 말해야 한다. 분모가 빠지면 "전부 봤다"로 읽힌다.
    assert "계보 검증: 0개" in out
    assert "알려진 취약 버전만 확인: 1개" in out


def test_vulnerable_packages_warn_but_do_not_block(lock_project, monkeypatch, capsys):
    """알려진 CVE는 큰 레포라면 늘 몇 개씩 걸린다 — 기본 차단은 우회를 부른다."""
    monkeypatch.setattr(bulk_gate, "scan_packages", lambda pkgs, **kw: VULNERABLE_RESULT)
    monkeypatch.setattr(bulk_gate, "report_event", lambda *a, **k: None)
    assert bulk_gate.gate_bulk_install(lock_project, "npm", "npm install") is True
    out = capsys.readouterr().out
    assert "[경고]" in out and "express@4.18.2" in out and "4.19.2" in out


def test_strict_mode_blocks_when_vulnerable(lock_project, monkeypatch, capsys):
    monkeypatch.setenv("TRUSTGATE_BULK_STRICT", "1")
    monkeypatch.setattr(bulk_gate, "scan_packages", lambda pkgs, **kw: VULNERABLE_RESULT)
    monkeypatch.setattr(bulk_gate, "report_event", lambda *a, **k: None)
    assert bulk_gate.gate_bulk_install(lock_project, "npm", "npm install") is False
    assert "[HALTED]" in capsys.readouterr().out


def test_osv_failure_fails_open_and_says_so(lock_project, monkeypatch, capsys):
    """조회 실패로 설치를 막으면 OSV가 흔들릴 때마다 팀 전체가 멈춘다."""
    monkeypatch.setattr(bulk_gate, "scan_packages", lambda pkgs, **kw: {
        "status": "ERROR", "reason": "Timeout", "package_count": 1,
        "vulnerable_count": 0, "error_count": 1, "packages": [],
    })
    assert bulk_gate.gate_bulk_install(lock_project, "npm", "npm install") is True
    assert "확인하지 못했습니다" in capsys.readouterr().out


def test_unusable_lock_is_announced_not_silently_skipped(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(bulk_gate.subprocess, "run",
                        lambda cmd, **kw: _fake_proc(1, stderr="no package.json"))
    assert bulk_gate.gate_bulk_install(tmp_path, "npm", "npm ci") is True
    out = capsys.readouterr().out
    assert "[미검사]" in out and "package.json이 없습니다" in out


# --------------------------------------------------------------------------
# select_lineage_targets: 무엇의 계보를 볼지 고르기
# --------------------------------------------------------------------------

def _install_on_disk(project_dir, path: str, version: str) -> None:
    """node_modules에 해당 버전이 이미 깔려 있는 상태를 만든다."""
    manifest_dir = project_dir / path
    manifest_dir.mkdir(parents=True, exist_ok=True)
    (manifest_dir / "package.json").write_text(
        json.dumps({"version": version}), encoding="utf-8")


LOCK_THREE = [
    {"name": "express", "version": "4.18.2", "dev": False, "path": "node_modules/express"},
    {"name": "ms", "version": "2.1.3", "dev": False, "path": "node_modules/ms"},
    {"name": "qs", "version": "6.9.7", "dev": False, "path": "node_modules/qs"},
]


def test_skips_versions_already_present_on_disk(lock_project):
    """이미 같은 버전이 깔려 있으면 이번 설치로 새 코드가 들어오지 않는다.
    pull 이후의 npm install이 여기서 한 자릿수로 줄어든다."""
    _install_on_disk(lock_project, "node_modules/ms", "2.1.3")
    targets, dropped = bulk_gate.select_lineage_targets(lock_project, LOCK_THREE, 10)
    assert {t["name"] for t in targets} == {"express", "qs"}
    assert dropped == 0


def test_reinstalled_version_mismatch_is_treated_as_new(lock_project):
    """디스크에 다른 버전이 있으면 새 코드가 들어오는 것이다."""
    _install_on_disk(lock_project, "node_modules/ms", "2.0.0")
    targets, _ = bulk_gate.select_lineage_targets(lock_project, LOCK_THREE, 10)
    assert "ms" in {t["name"] for t in targets}


def test_direct_dependencies_are_checked_first(lock_project):
    """상한에 걸려야 한다면 사용자가 이름을 아는 것부터 본다.
    (lock_project의 package.json은 express만 선언한다.)"""
    targets, dropped = bulk_gate.select_lineage_targets(lock_project, LOCK_THREE, 1)
    assert [t["name"] for t in targets] == ["express"]
    assert dropped == 2


def test_limit_zero_disables_the_stage_but_counts_what_was_dropped(lock_project):
    targets, dropped = bulk_gate.select_lineage_targets(lock_project, LOCK_THREE, 0)
    assert targets == [] and dropped == 3


# --------------------------------------------------------------------------
# scan_lineage: 계보 판정과 차단
# --------------------------------------------------------------------------

def _scan_result(name, version, verdict, score=50):
    return {"package": {"name": name, "version": version}, "verdict": verdict,
            "score": score, "reason": f"{verdict} 사유", "rules": []}


def test_risk_blocks_the_install(lock_project, monkeypatch, capsys):
    """미지정 설치도 이제 실제로 막을 수 있다 — 이 경로의 핵심."""
    monkeypatch.setenv("TRUSTGATE_LINEAGE_MAX", "10")
    monkeypatch.setattr(bulk_gate, "scan_package",
                        lambda name, version: _scan_result(name, version, "RISK", 12))
    monkeypatch.setattr(bulk_gate, "report_event", lambda *a, **k: None)
    allowed, summary = bulk_gate.scan_lineage(lock_project, LOCK_THREE, "npm install")
    assert allowed is False
    assert len(summary["risk"]) == 3
    assert "[BLOCKED]" in capsys.readouterr().out


def test_unverifiable_warns_but_does_not_block(lock_project, monkeypatch, capsys):
    """전이 의존성은 GitHub 저장소나 서명이 없는 경우가 흔하다 — 여기서
    막으면 정상 프로젝트의 첫 설치가 거의 항상 멈춘다."""
    monkeypatch.setenv("TRUSTGATE_LINEAGE_MAX", "10")
    monkeypatch.setattr(bulk_gate, "scan_package",
                        lambda name, version: _scan_result(name, version, "UNVERIFIABLE (RISK)", 0))
    monkeypatch.setattr(bulk_gate, "report_event", lambda *a, **k: None)
    allowed, summary = bulk_gate.scan_lineage(lock_project, LOCK_THREE, "npm install")
    assert allowed is True
    assert len(summary["unverifiable"]) == 3
    assert "차단하지 않음" in capsys.readouterr().out


def test_one_failed_scan_does_not_abort_the_rest(lock_project, monkeypatch, capsys):
    monkeypatch.setenv("TRUSTGATE_LINEAGE_MAX", "10")

    def flaky(name, version):
        if name == "ms":
            raise RuntimeError("GitHub 429")
        return _scan_result(name, version, "PASS", 90)

    monkeypatch.setattr(bulk_gate, "scan_package", flaky)
    monkeypatch.setattr(bulk_gate, "report_event", lambda *a, **k: None)
    allowed, summary = bulk_gate.scan_lineage(lock_project, LOCK_THREE, "npm install")
    assert allowed is True
    assert summary["scanned"] == 2 and len(summary["failed"]) == 1


def test_capped_remainder_is_reported_not_hidden(lock_project, monkeypatch, capsys):
    """상한에 걸려 못 본 것을 조용히 넘어가면 '전부 봤다'로 읽힌다."""
    monkeypatch.setenv("TRUSTGATE_LINEAGE_MAX", "1")
    monkeypatch.setattr(bulk_gate, "scan_package",
                        lambda name, version: _scan_result(name, version, "PASS", 90))
    monkeypatch.setattr(bulk_gate, "report_event", lambda *a, **k: None)
    allowed, summary = bulk_gate.scan_lineage(lock_project, LOCK_THREE, "npm install")
    assert allowed is True and summary["dropped"] == 2
    assert "나머지 2개" in capsys.readouterr().out


def test_gate_blocks_when_lineage_finds_risk(lock_project, monkeypatch, capsys):
    """OSV가 깨끗해도 계보가 RISK면 막는다 — 두 검사는 서로를 대신하지 않는다."""
    monkeypatch.setenv("TRUSTGATE_LINEAGE_MAX", "10")
    monkeypatch.setattr(bulk_gate, "scan_packages", lambda pkgs, **kw: {
        "status": "CLEAN", "package_count": len(pkgs), "vulnerable_count": 0,
        "error_count": 0, "packages": [],
    })
    monkeypatch.setattr(bulk_gate, "scan_package",
                        lambda name, version: _scan_result(name, version, "RISK", 10))
    monkeypatch.setattr(bulk_gate, "report_event", lambda *a, **k: None)
    assert bulk_gate.gate_bulk_install(lock_project, "npm", "npm install") is False
    assert "[HALTED]" in capsys.readouterr().out


def test_osv_failure_does_not_skip_lineage(lock_project, monkeypatch, capsys):
    """근거가 다른 두 검사다 — 하나가 죽었다고 다른 하나를 건너뛰면 안 된다."""
    monkeypatch.setenv("TRUSTGATE_LINEAGE_MAX", "10")
    monkeypatch.setattr(bulk_gate, "scan_packages", lambda pkgs, **kw: {
        "status": "ERROR", "reason": "Timeout", "package_count": 1,
        "vulnerable_count": 0, "error_count": 1, "packages": [],
    })
    scanned = []
    monkeypatch.setattr(bulk_gate, "scan_package", lambda name, version: (
        scanned.append(name), _scan_result(name, version, "PASS", 90))[1])
    monkeypatch.setattr(bulk_gate, "report_event", lambda *a, **k: None)
    assert bulk_gate.gate_bulk_install(lock_project, "npm", "npm install") is True
    assert scanned == ["express"]


# --------------------------------------------------------------------------
# review_new_packages: 설치 후 lock 변화분 점검
# --------------------------------------------------------------------------

def test_reviews_only_the_subtree_that_arrived(lock_project, monkeypatch, capsys):
    """지목 설치는 패키지 하나만 계보 검증한다 — 함께 들어온 서브트리는
    여기서 처음 드러난다."""
    before = [{"name": "express", "version": "4.18.2", "dev": False}]
    _write_lock(lock_project, {
        "lockfileVersion": 3,
        "packages": {
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/ms": {"version": "2.1.3"},
        },
    })
    checked = []
    monkeypatch.setattr(bulk_gate, "scan_packages", lambda pkgs, **kw: (
        checked.extend(pkgs),
        {"status": "CLEAN", "package_count": len(pkgs), "vulnerable_count": 0,
         "error_count": 0, "packages": []},
    )[1])

    assert bulk_gate.review_new_packages(lock_project, before, command="npm install lodash") is True
    # 이미 있던 express는 다시 묻지 않는다 — 매번 같은 목록이 나오면 곧 무시된다.
    assert {p["name"] for p in checked} == {"lodash", "ms"}
    out = capsys.readouterr().out
    assert "새로 들어온 2개" in out
    assert "계보 검증(Track A/B/C)" in out


def test_already_verified_target_is_not_reported_as_unchecked(
    lock_project, monkeypatch, capsys
):
    """전이 의존성이 0개인 패키지(예: react)를 지목 설치하면, lock 변화분의
    전부가 그 패키지 자신이 된다. 그 패키지는 이미 위에서 Track A/B/C까지
    검증했으므로([PASS] 판정이 이미 찍혔다) 여기서 "계보 검증 안 됨"으로
    다시 보고하면 방금 찍힌 판정과 모순된다."""
    _write_lock(lock_project, {
        "lockfileVersion": 3,
        "packages": {
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/react": {"version": "19.2.8"},
        },
    })
    before = [{"name": "express", "version": "4.18.2", "dev": False}]
    monkeypatch.setattr(bulk_gate, "scan_packages",
                        lambda pkgs, **kw: pytest.fail("이미 검증된 패키지를 다시 OSV로 조회했다"))

    result = bulk_gate.review_new_packages(
        lock_project, before, command="npm install react",
        already_verified={("react", "19.2.8")},
    )
    assert result is True
    assert capsys.readouterr().out == ""


def test_no_new_packages_prints_nothing(lock_project, monkeypatch, capsys):
    """이미 최신인 프로젝트에서 install을 다시 쳤을 때 잡음을 만들지 않는다."""
    before = [{"name": "express", "version": "4.18.2", "dev": False}]
    monkeypatch.setattr(bulk_gate, "scan_packages",
                        lambda pkgs, **kw: pytest.fail("변화가 없는데 OSV를 호출했다"))
    assert bulk_gate.review_new_packages(lock_project, before, command="npm install") is True
    assert capsys.readouterr().out == ""


def test_new_vulnerable_package_warns_after_install(lock_project, monkeypatch, capsys):
    monkeypatch.setattr(bulk_gate, "scan_packages", lambda pkgs, **kw: VULNERABLE_RESULT)
    monkeypatch.setattr(bulk_gate, "report_event", lambda *a, **k: None)
    assert bulk_gate.review_new_packages(lock_project, [], command="npm install express") is True
    out = capsys.readouterr().out
    assert "[경고]" in out and "express@4.18.2" in out


def test_strict_mode_fails_exit_code_but_admits_install_happened(
    lock_project, monkeypatch, capsys
):
    """설치는 이미 끝났다 — 막았다고 표현하면 사실과 다르다."""
    monkeypatch.setenv("TRUSTGATE_BULK_STRICT", "1")
    monkeypatch.setattr(bulk_gate, "scan_packages", lambda pkgs, **kw: VULNERABLE_RESULT)
    monkeypatch.setattr(bulk_gate, "report_event", lambda *a, **k: None)
    assert bulk_gate.review_new_packages(lock_project, [], command="npm install express") is False
    out = capsys.readouterr().out
    assert "[STRICT]" in out and "이미 완료" in out
    assert "[HALTED]" not in out


def test_post_check_failure_does_not_hide_that_it_failed(lock_project, monkeypatch, capsys):
    monkeypatch.setattr(bulk_gate, "scan_packages", lambda pkgs, **kw: {
        "status": "ERROR", "reason": "Timeout", "package_count": 1,
        "vulnerable_count": 0, "error_count": 1, "packages": [],
    })
    assert bulk_gate.review_new_packages(lock_project, [], command="npm install express") is True
    assert "점검되지 않았습니다" in capsys.readouterr().out

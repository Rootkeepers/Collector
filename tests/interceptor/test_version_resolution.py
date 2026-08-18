"""#31(크래시)·#32(범위 resolve) 회귀 테스트.

네트워크와 npm 서브프로세스를 모두 가짜로 바꿔 끼운다 — 레지스트리 상태나
npm 설치 여부에 따라 결과가 흔들리면 회귀 테스트로 쓸 수 없다.

실행: PYTHONPATH=src python3 -m pytest tests/interceptor/test_version_resolution.py
"""

from __future__ import annotations

import pytest

from rootkeepers.interceptor import safe_npm
from rootkeepers.interceptor.cooldown import CooldownResult

META = {
    "dist-tags": {"latest": "4.17.21", "next": "5.0.0-rc.1", "beta": "5.0.0-beta.2"},
    "time": {"4.17.21": "2020-01-01T00:00:00.000Z"},
}


# --------------------------------------------------------------------------
# resolve_install_version: 명세 종류별 해석
# --------------------------------------------------------------------------

def test_none_spec_resolves_to_latest(monkeypatch):
    monkeypatch.setattr(safe_npm, "get_latest_version", lambda name: "4.17.21")
    assert safe_npm.resolve_install_version("lodash", None) == ("4.17.21", None)


def test_none_spec_reports_lookup_failure(monkeypatch):
    monkeypatch.setattr(safe_npm, "get_latest_version", lambda name: None)
    version, error = safe_npm.resolve_install_version("lodash", None)
    assert version is None
    assert "최신 버전" in error


@pytest.mark.parametrize("exact", ["4.17.21", "1.0.0-rc.1", "2.3.4+build.5"])
def test_exact_version_passes_through_without_network(monkeypatch, exact):
    """정확한 버전은 추가 조회 없이 그대로 쓴다 — 불필요한 왕복을 막는다."""
    def boom(*a, **k):
        raise AssertionError("정확한 버전인데 네트워크를 탔습니다")

    monkeypatch.setattr(safe_npm, "fetch_package_meta", boom)
    monkeypatch.setattr(safe_npm, "_resolve_range_with_npm", boom)
    assert safe_npm.resolve_install_version("lodash", exact) == (exact, None)


@pytest.mark.parametrize("tag,expected", [
    ("latest", "4.17.21"), ("next", "5.0.0-rc.1"), ("beta", "5.0.0-beta.2"),
])
def test_dist_tag_resolves_from_registry_without_npm(monkeypatch, tag, expected):
    """dist-tag는 레지스트리 문서만으로 끝나고 npm 서브프로세스를 쓰지 않는다."""
    def boom(*a, **k):
        raise AssertionError("dist-tag인데 npm 서브프로세스를 호출했습니다")

    monkeypatch.setattr(safe_npm, "fetch_package_meta", lambda name: META)
    monkeypatch.setattr(safe_npm, "_resolve_range_with_npm", boom)
    assert safe_npm.resolve_install_version("lodash", tag) == (expected, None)


def test_range_delegates_to_npm(monkeypatch):
    seen = {}

    def fake_range(name, spec):
        seen["args"] = (name, spec)
        return "18.3.1", None

    monkeypatch.setattr(safe_npm, "fetch_package_meta", lambda name: META)
    monkeypatch.setattr(safe_npm, "_resolve_range_with_npm", fake_range)
    assert safe_npm.resolve_install_version("react", "^18") == ("18.3.1", None)
    assert seen["args"] == ("react", "^18")


def test_range_falls_back_when_registry_unreachable(monkeypatch):
    """레지스트리 조회가 실패해도 범위 해석 경로는 살아 있어야 한다."""
    monkeypatch.setattr(safe_npm, "fetch_package_meta", lambda name: None)
    monkeypatch.setattr(safe_npm, "_resolve_range_with_npm", lambda n, s: ("18.3.1", None))
    assert safe_npm.resolve_install_version("react", "^18") == ("18.3.1", None)


# --------------------------------------------------------------------------
# _resolve_range_with_npm: npm 출력 형태별 처리
# --------------------------------------------------------------------------

class _Proc:
    def __init__(self, stdout="", returncode=0):
        self.stdout, self.returncode, self.stderr = stdout, returncode, ""


def _stub_npm(monkeypatch, proc):
    monkeypatch.setattr(safe_npm, "find_real_npm", lambda: "/usr/bin/npm")
    monkeypatch.setattr(safe_npm.subprocess, "run", lambda *a, **k: proc)


def test_npm_array_output_picks_newest(monkeypatch):
    """복수 매치는 오름차순 배열 — npm이 실제 설치할 최신 버전을 골라야 한다."""
    _stub_npm(monkeypatch, _Proc('["18.0.0","18.2.0","18.3.1"]'))
    assert safe_npm._resolve_range_with_npm("react", "^18") == ("18.3.1", None)


def test_npm_string_output(monkeypatch):
    _stub_npm(monkeypatch, _Proc('"4.17.21"'))
    assert safe_npm._resolve_range_with_npm("lodash", "^4") == ("4.17.21", None)


def test_npm_no_match_is_reported_not_crashed(monkeypatch):
    _stub_npm(monkeypatch, _Proc("", returncode=1))
    version, error = safe_npm._resolve_range_with_npm("react", "^999")
    assert version is None and "찾지 못했" in error


def test_npm_invalid_json_is_reported(monkeypatch):
    _stub_npm(monkeypatch, _Proc("not json at all"))
    version, error = safe_npm._resolve_range_with_npm("react", "^18")
    assert version is None and error


def test_npm_timeout_is_reported(monkeypatch):
    import subprocess as sp
    monkeypatch.setattr(safe_npm, "find_real_npm", lambda: "/usr/bin/npm")

    def timeout(*a, **k):
        raise sp.TimeoutExpired(cmd="npm", timeout=20)

    monkeypatch.setattr(safe_npm.subprocess, "run", timeout)
    version, error = safe_npm._resolve_range_with_npm("react", "^18")
    assert version is None and "끝나지 않았" in error


@pytest.mark.parametrize("hostile", ["-v", "--registry=http://evil", "; rm -rf /", "-"])
def test_hostile_spec_never_reaches_npm(monkeypatch, hostile):
    """`-`로 시작하는 값이 npm 인자로 들어가면 플래그로 해석된다 — 사전 차단."""
    monkeypatch.setattr(safe_npm, "find_real_npm", lambda: "/usr/bin/npm")
    monkeypatch.setattr(
        safe_npm.subprocess, "run",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("npm이 호출됨")),
    )
    version, error = safe_npm._resolve_range_with_npm("react", hostile)
    assert version is None and "해석할 수 없는" in error


def test_range_uses_find_real_npm_not_path_lookup(monkeypatch):
    """shim 재귀 방지 — shutil.which가 아니라 find_real_npm을 써야 한다."""
    monkeypatch.setattr(
        safe_npm.shutil, "which",
        lambda name: (_ for _ in ()).throw(AssertionError("shutil.which를 사용했습니다")),
    )
    monkeypatch.setattr(safe_npm, "find_real_npm", lambda: "/usr/bin/npm")
    monkeypatch.setattr(safe_npm.subprocess, "run", lambda *a, **k: _Proc('"18.3.1"'))
    assert safe_npm._resolve_range_with_npm("react", "^18")[0] == "18.3.1"


# --------------------------------------------------------------------------
# check_package: #31 크래시가 재발하지 않는지
# --------------------------------------------------------------------------

def test_unknown_publish_date_does_not_crash(monkeypatch):
    """remain_days=None이어도 TypeError 없이 판정 결과를 돌려줘야 한다."""
    monkeypatch.setattr(safe_npm, "resolve_install_version", lambda n, s: ("4.17.21", None))
    monkeypatch.setattr(
        safe_npm, "check_cooldown",
        lambda pkg, version: CooldownResult(False, None, None, None, "배포일 불명 → 미경과 처리(보수적)"),
    )
    monkeypatch.setattr(safe_npm, "report_event", lambda *a, **k: None)

    result = safe_npm.check_package("lodash@latest")
    assert result.verdict is safe_npm.Verdict.UNVERIFIABLE
    assert "배포일 불명" in result.reason


def test_normal_cooldown_hold_still_reports_days(monkeypatch):
    """정상 경로(남은 일수를 아는 경우)의 메시지는 그대로 유지되어야 한다."""
    monkeypatch.setattr(safe_npm, "resolve_install_version", lambda n, s: ("4.17.21", None))
    monkeypatch.setattr(
        safe_npm, "check_cooldown",
        lambda pkg, version: CooldownResult(False, None, 2.0, 5.0, "5일 대기"),
    )
    monkeypatch.setattr(safe_npm, "report_event", lambda *a, **k: None)

    result = safe_npm.check_package("lodash@4.17.21")
    assert "5.0일 대기" in result.reason


def test_resolution_failure_is_unverifiable_not_crash(monkeypatch):
    monkeypatch.setattr(safe_npm, "resolve_install_version", lambda n, s: (None, "찾지 못했습니다."))
    result = safe_npm.check_package("react@^999")
    assert result.verdict is safe_npm.Verdict.UNVERIFIABLE
    assert "찾지 못했" in result.reason


def test_resolved_version_is_what_gets_scanned(monkeypatch):
    """검사 대상은 명세가 아니라 resolve된 정확한 버전이어야 한다."""
    monkeypatch.setattr(safe_npm, "resolve_install_version", lambda n, s: ("18.3.1", None))
    monkeypatch.setattr(
        safe_npm, "check_cooldown",
        lambda pkg, version: CooldownResult(True, None, 30.0, 0.0, "통과"),
    )
    monkeypatch.setattr(safe_npm, "report_event", lambda *a, **k: None)
    seen = {}

    def fake_scan(name, version):
        seen["scanned"] = (name, version)
        return {"verdict": "PASS", "score": 0, "reason": "ok", "rules": []}

    monkeypatch.setattr(safe_npm, "scan_package", fake_scan)
    safe_npm.check_package("react@^18")
    assert seen["scanned"] == ("react", "18.3.1")

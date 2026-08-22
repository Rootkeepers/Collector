"""#34·#44·#45 회귀 테스트.

셋 다 "shim 이 PATH 앞단에 있을 때"와 "lock 이 없을 때"라는 실제 환경 조건에서만
드러나던 문제라, 그 조건을 파일시스템으로 직접 만들어 재현한다. 네트워크는 타지
않는다 — PATH 탐색과 분기만 본다.

실행: PYTHONPATH=src python3 -m pytest tests/interceptor/test_shim_recursion.py
"""

from __future__ import annotations

import os
import stat

import pytest

from rootkeepers.interceptor import bulk_gate, safe_npm
from rootkeepers.interceptor.shim_installer import SHIM_MARKER, real_npm_path


def _make_exe(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _shim(dir_path):
    return _make_exe(dir_path / "npm", f"#!/usr/bin/env bash\n{SHIM_MARKER}\nexit 0\n")


def _real(dir_path):
    return _make_exe(dir_path / "npm", "#!/usr/bin/env bash\necho real\n")


@pytest.fixture
def clean_env(monkeypatch):
    monkeypatch.delenv("ROOTKEEPERS_REAL_NPM", raising=False)


# --------------------------------------------------------------------------
# find_real_npm: shim 을 건너뛰고 진짜 npm 을 고른다 (#34, #45)
# --------------------------------------------------------------------------

def test_shim_first_on_path_is_skipped(tmp_path, monkeypatch, clean_env):
    """PATH 앞단이 shim 이어도 뒤의 진짜 npm 을 골라야 한다.

    예전에는 shutil.which() 결과를 그대로 써서 shim 을 실행했고, 그 shim 이
    safe-npm 을 다시 불러 같은 검사가 중복 실행됐다.
    """
    shim_dir, real_dir = tmp_path / "shim", tmp_path / "real"
    _shim(shim_dir)
    expected = _real(real_dir)
    monkeypatch.setenv("PATH", os.pathsep.join([str(shim_dir), str(real_dir)]))

    assert safe_npm.find_real_npm() == str(expected)


def test_multiple_shims_are_all_skipped(tmp_path, monkeypatch, clean_env):
    """shim 이 여러 디렉터리에 남아 있어도 서로를 진짜 npm 으로 착각하지 않는다."""
    a, b, real_dir = tmp_path / "a", tmp_path / "b", tmp_path / "real"
    _shim(a)
    _shim(b)
    expected = _real(real_dir)
    monkeypatch.setenv("PATH", os.pathsep.join([str(a), str(b), str(real_dir)]))

    assert safe_npm.find_real_npm() == str(expected)


def test_env_var_still_wins(tmp_path, monkeypatch):
    """shim 이 넘겨준 ROOTKEEPERS_REAL_NPM 이 있으면 PATH 를 훑지 않는다."""
    monkeypatch.setenv("ROOTKEEPERS_REAL_NPM", "/opt/node/bin/npm")
    monkeypatch.setenv("PATH", str(tmp_path))
    assert safe_npm.find_real_npm() == "/opt/node/bin/npm"


def test_only_shim_available_raises_instead_of_recursing(tmp_path, monkeypatch, clean_env):
    """shim 밖에 없으면 그 값을 돌려주지 않는다 — 돌려주면 재귀한다."""
    shim_dir = tmp_path / "only-shim"
    _shim(shim_dir)
    monkeypatch.setenv("PATH", str(shim_dir))

    with pytest.raises(safe_npm.CollectorError) as exc:
        safe_npm.find_real_npm()
    assert "shim" in str(exc.value)


def test_no_npm_at_all_raises(tmp_path, monkeypatch, clean_env):
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(safe_npm.CollectorError):
        safe_npm.find_real_npm()


def test_real_npm_path_returns_none_when_only_shims(tmp_path, monkeypatch):
    shim_dir = tmp_path / "s"
    _shim(shim_dir)
    monkeypatch.setenv("PATH", str(shim_dir))
    assert real_npm_path() is None


def test_non_executable_npm_is_not_selected(tmp_path, monkeypatch, clean_env):
    """실행 권한이 없는 파일은 후보가 아니다."""
    bad, real_dir = tmp_path / "bad", tmp_path / "real"
    bad.mkdir()
    (bad / "npm").write_text("not executable", encoding="utf-8")
    (bad / "npm").chmod(0o644)
    expected = _real(real_dir)
    monkeypatch.setenv("PATH", os.pathsep.join([str(bad), str(real_dir)]))

    assert safe_npm.find_real_npm() == str(expected)


# --------------------------------------------------------------------------
# ensure_lockfile: npm ci 는 lock 을 만들지 않는다 (#44)
# --------------------------------------------------------------------------

def test_ci_does_not_generate_lock(tmp_path, monkeypatch):
    """lock 이 없으면 만들지 말고 실패로 알린다 — npm ci 가 원래대로 실패해야 한다."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(bulk_gate.subprocess, "run",
                        lambda *a, **k: pytest.fail("npm ci 인데 lock 을 생성했다"))

    ok, reason = bulk_gate.ensure_lockfile(tmp_path, "npm", may_generate=False)
    assert ok is False
    assert "npm ci" in reason
    assert not (tmp_path / "package-lock.json").exists()


def test_install_still_generates_lock(tmp_path, monkeypatch):
    """인자 없는 npm install 의 기존 동작은 그대로다."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
        return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(bulk_gate.subprocess, "run", fake_run)
    assert bulk_gate.ensure_lockfile(tmp_path, "npm", may_generate=True) == (True, None)


def test_ci_with_existing_lock_is_unaffected(tmp_path, monkeypatch):
    """lock 이 이미 있으면 ci 도 평소대로 점검한다."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(bulk_gate.subprocess, "run",
                        lambda *a, **k: pytest.fail("lock 이 있는데 npm 을 실행했다"))

    assert bulk_gate.ensure_lockfile(tmp_path, "npm", may_generate=False) == (True, None)


def test_ci_without_lock_is_announced_and_not_blocked(tmp_path, capsys):
    """점검은 건너뛰되 그 사실을 말한다. 차단은 npm 자신이 한다."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")

    allowed = bulk_gate.gate_bulk_install(tmp_path, "npm", "npm ci", may_generate_lock=False)

    assert allowed is True
    out = capsys.readouterr().out
    assert "[미검사]" in out and "npm ci" in out

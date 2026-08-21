"""`trustgate up` 기동 판정 회귀 테스트.

포트가 이미 물려 있을 때 "떴다"고 거짓 보고하던 문제를 막는다. 실제 소켓이나
프로세스를 띄우지 않고, 기동 판정에 쓰이는 두 신호(_health_ok, Popen)만 바꿔
끼운다 — 포트 상태나 실행 환경에 따라 결과가 흔들리면 회귀 테스트로 못 쓴다.

실행: PYTHONPATH=src python3 -m pytest tests/dashboard/test_background.py
"""

from __future__ import annotations

import pytest

from rootkeepers.dashboard import background


class _FakeProc:
    """poll() 이 계속 None 이면 살아 있는 것, 정수면 그 코드로 끝난 것."""

    def __init__(self, pid=4242, exit_code=None):
        self.pid = pid
        self._exit_code = exit_code

    def poll(self):
        return self._exit_code


@pytest.fixture(autouse=True)
def _isolate_runtime(tmp_path, monkeypatch):
    """PID/로그 파일이 진짜 ~/.trustgate 를 건드리지 않게 격리한다."""
    monkeypatch.setattr(background, "RUNTIME_DIR", tmp_path)
    monkeypatch.setattr(background, "PID_FILE", tmp_path / "console.pid")
    monkeypatch.setattr(background, "LOG_FILE", tmp_path / "console.log")


def test_occupied_port_is_refused_before_spawning(monkeypatch, capsys):
    """이미 응답하는 서버가 있으면 띄우지 않고 실패로 보고한다.

    예전에는 그대로 자식을 띄웠고, 자식이 EADDRINUSE 로 즉사해도 _health_ok 가
    **남의 서버** 200 을 보고 성공(exit 0)이라고 말했다.
    """
    monkeypatch.setattr(background, "_health_ok", lambda host, port: True)

    def must_not_spawn(*a, **kw):
        pytest.fail("포트가 물려 있는데 프로세스를 띄웠다")

    monkeypatch.setattr(background.subprocess, "Popen", must_not_spawn)

    assert background.start("127.0.0.1", 8000) == 1
    assert "이미 다른 프로세스가 응답" in capsys.readouterr().err


def test_dead_child_is_not_reported_as_success(monkeypatch, capsys):
    """자식이 죽었으면 그 포트에 누가 응답하든 실패다.

    스폰 직후에 남이 포트를 잡는 경우 — 사전 점검은 통과하지만 자식은 죽는다.
    poll() 을 _health_ok 보다 먼저 보지 않으면 여기서 또 성공으로 오인한다.
    """
    health = iter([False, True, True, True])  # 사전 점검은 통과, 그 뒤로는 남이 응답
    monkeypatch.setattr(background, "_health_ok", lambda host, port: next(health, True))
    monkeypatch.setattr(background.subprocess, "Popen",
                        lambda *a, **kw: _FakeProc(exit_code=1))  # 즉사
    monkeypatch.setattr(background, "clear_record", lambda: None)

    assert background.start("127.0.0.1", 8000) == 1
    assert "실패" in capsys.readouterr().err


def test_healthy_start_reports_success(monkeypatch, capsys):
    """정상 기동은 그대로 성공으로 보고해야 한다 (위 두 방어가 막지 않는지)."""
    health = iter([False, True])  # 사전 점검 통과 → 기동 확인 성공
    monkeypatch.setattr(background, "_health_ok", lambda host, port: next(health, True))
    monkeypatch.setattr(background.subprocess, "Popen",
                        lambda *a, **kw: _FakeProc(pid=1234))  # 계속 살아 있음

    assert background.start("127.0.0.1", 8000) == 0
    assert "1234" in capsys.readouterr().out

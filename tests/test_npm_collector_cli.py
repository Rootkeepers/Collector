from __future__ import annotations

from rootkeepers.collectors.npm import __main__ as npm_cli
from rootkeepers.collectors.npm import crawler


def test_npm_collector_help_does_not_contact_registry(monkeypatch) -> None:
    contacted = False

    def fail_if_called(*_args, **_kwargs):
        nonlocal contacted
        contacted = True
        raise AssertionError("help must not contact npm")

    monkeypatch.setattr(npm_cli, "collect_npm_release", fail_if_called)
    try:
        npm_cli.main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
    assert contacted is False


def test_registry_fetch_encodes_scoped_name_and_sets_timeout(monkeypatch) -> None:
    captured = {}

    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"name": "@scope/name"}

    def fake_get(url, **kwargs):
        captured.update(url=url, kwargs=kwargs)
        return Response()

    monkeypatch.setattr(crawler.requests, "get", fake_get)
    result = crawler.fetch_package_data("@scope/name")

    assert result == {"name": "@scope/name"}
    assert captured["url"].endswith("/%40scope%2Fname")
    assert captured["kwargs"]["timeout"] == crawler.REGISTRY_TIMEOUT_SECONDS

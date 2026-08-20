import pytest

from rootkeepers.interceptor import __main__ as interceptor_cli
from rootkeepers.interceptor.safe_npm import parse_install_targets


def test_install_option_values_are_not_scanned_as_packages() -> None:
    assert parse_install_targets([
        "--workspace", "web-app",
        "--omit", "dev",
        "--registry=https://registry.npmjs.org",
        "lodash", "react@18",
    ]) == ["lodash", "react@18"]


def test_short_workspace_and_prefix_values_are_not_packages() -> None:
    assert parse_install_targets([
        "-w", "web-app", "-C", "C:/projects/demo", "lodash",
    ]) == ["lodash"]


def test_boolean_option_does_not_hide_following_package() -> None:
    assert parse_install_targets(["--ignore-scripts", "lodash"]) == ["lodash"]


def test_double_dash_switches_to_positional_arguments() -> None:
    assert parse_install_targets(["--", "lodash", "@scope/name@1.0.0"]) == [
        "lodash", "@scope/name@1.0.0",
    ]


@pytest.mark.parametrize("command", sorted(interceptor_cli.INSTALL_COMMANDS))
def test_every_official_install_alias_uses_the_gate(monkeypatch, command: str) -> None:
    captured = {}

    def fake_gate(targets):
        captured["targets"] = targets
        return True, []

    def fake_npm(args):
        captured["args"] = args
        return 0

    monkeypatch.setattr(interceptor_cli, "gate_install", fake_gate)
    monkeypatch.setattr(interceptor_cli, "collect_lock_packages", lambda _path: [])
    monkeypatch.setattr(interceptor_cli, "run_real_npm", fake_npm)
    monkeypatch.setattr(interceptor_cli, "_sync_after_install", lambda _path: None)
    monkeypatch.setattr(interceptor_cli, "review_new_packages", lambda *_args, **_kwargs: True)

    assert interceptor_cli._run([command, "lodash@4.17.21"]) == 0
    assert captured["targets"] == ["lodash@4.17.21"]
    assert captured["args"] == [command, "lodash@4.17.21"]

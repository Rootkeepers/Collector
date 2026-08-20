from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "src" / "rootkeepers" / "dashboard" / "static" / "console.html"
CSS = ROOT / "src" / "rootkeepers" / "dashboard" / "static" / "app.css"


def test_mobile_navigation_reaches_every_dashboard_view() -> None:
    source = HTML.read_text(encoding="utf-8")
    mobile = source.split('<nav class="mobile-nav"', 1)[1].split("</nav>", 1)[0]

    assert 'aria-label="주요 화면"' in mobile
    assert [mobile.count(f'data-view="{view}"') for view in (
        "dashboard", "explorer", "installed", "history"
    )] == [1, 1, 1, 1]


def test_mobile_layout_contains_scroll_and_safe_navigation_rules() -> None:
    source = CSS.read_text(encoding="utf-8")

    assert ".mobile-nav { display: none; }" in source
    assert "position: fixed; z-index: 50" in source
    assert "overflow-x: hidden" in source
    assert "table.pkg-table { min-width: 720px; }" in source

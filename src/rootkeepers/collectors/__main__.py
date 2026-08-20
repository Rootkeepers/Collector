"""Backward-compatible command for running the unified package scan.

The original collector entry point referenced ``rootkeepers.engine``, which was
removed when the authoritative scanner moved to ``rootkeepers.interceptor``.
Keep ``python -m rootkeepers.collectors`` useful for existing scripts while
directing new users to the documented ``trustgate scan`` command.
"""

from __future__ import annotations

import argparse

from rootkeepers.interceptor.reporting import flush_reports
from rootkeepers.interceptor.safe_npm import CollectorError, Verdict, check_package, report
from rootkeepers.paths import load_env


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m rootkeepers.collectors",
        description="npm 패키지를 설치하지 않고 공급망 계보를 검사합니다.",
        epilog="새 스크립트에서는 같은 기능의 `trustgate scan` 사용을 권장합니다.",
    )
    parser.add_argument("package", nargs="+", help="예: lodash react@18.2.0")
    args = parser.parse_args(argv)

    load_env()
    exit_code = 0
    try:
        for package_spec in args.package:
            try:
                result = check_package(package_spec)
            except CollectorError as exc:
                parser.error(str(exc))
            report(result)
            if result.verdict is not Verdict.PASS:
                exit_code = 1
    finally:
        flush_reports()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

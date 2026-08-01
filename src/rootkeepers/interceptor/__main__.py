"""safe-npm 실행 진입점."""

import sys

try:
    from .safe_npm import gate_install, parse_install_targets, run_real_npm
except ImportError:
    from safe_npm import gate_install, parse_install_targets, run_real_npm


def main() -> int:
    args = sys.argv[1:]

    if not args:
        return run_real_npm(args)

    if args[0] not in ("install", "i"):
        return run_real_npm(args)

    targets = parse_install_targets(args[1:])
    if not targets:
        print("[INFO] 개별 패키지 미지정 설치는 아직 검사 대상이 아닙니다. 그대로 진행합니다.")
        return run_real_npm(args)

    if not gate_install(targets):          # ← 인자 1개 (targets만)
        print("[HALTED] 위험 패키지가 감지되어 설치를 중단합니다.")
        return 1

    return run_real_npm(args)


if __name__ == "__main__":
    sys.exit(main())
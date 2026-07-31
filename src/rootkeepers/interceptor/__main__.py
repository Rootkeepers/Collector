"""safe-npm 실행 진입점.

사용법:
    $ python _main_.py install lodash react@18
    $ python _main_.py run build          # 검사 없이 그대로 npm run build 실행

install/i 서브커맨드만 검사 대상으로 가로채고, 그 외 서브커맨드는 그대로
npm에 통과시킨다. 실제 판정/차단 로직은 safe_npm.py에 있다.
"""

"""safe-npm 실행 진입점."""

import sys


def main() -> int:
    try:
        from .safe_npm import gate_install, parse_install_targets, run_real_npm
    except ImportError:
        from safe_npm import gate_install, parse_install_targets, run_real_npm

    args = sys.argv[1:]

    if not args:
        return run_real_npm(args)

    if args[0] not in ("install", "i"):
        return run_real_npm(args)

    targets = parse_install_targets(args[1:])
    if not targets:
        print("[INFO] 개별 패키지 미지정 설치는 아직 검사 대상이 아닙니다. 그대로 진행합니다.")
        return run_real_npm(args)

    ok, safe_args = gate_install(args, targets)
    if not ok:
        print("[HALTED] 위험 패키지가 감지되어 설치를 중단합니다.")
        return 1

    return run_real_npm(safe_args)


if __name__ == "__main__":
    sys.exit(main())
"""safe-npm 실행 진입점.

사용법:
    $ python _main_.py install lodash react@18
    $ python _main_.py run build          # 검사 없이 그대로 npm run build 실행

install/i 서브커맨드만 검사 대상으로 가로채고, 그 외 서브커맨드는 그대로
npm에 통과시킨다. 실제 판정/차단 로직은 safe_npm.py에 있다.
"""

import sys

try:
    from .safe_npm import gate_install, parse_install_targets, run_real_npm
except ImportError:  # pragma: no cover - supports direct execution from this folder
    from safe_npm import gate_install, parse_install_targets, run_real_npm


def main() -> int:
    args = sys.argv[1:]

    if not args:
        return run_real_npm(args)

    subcommand = args[0]

    # install/i가 아니면 검사 없이 그대로 통과 (npq-hero 방식)
    if subcommand not in ("install", "i"):
        return run_real_npm(args)

    targets = parse_install_targets(args[1:])

    # 대상 패키지가 없으면 (예: "npm install"만 실행 = package.json 기준 설치)
    # 현재는 개별 패키지 지정 케이스만 검사 대상으로 처리
    # TODO: package.json/lock 파일 기반 전체 설치 케이스 처리 (6.2/6.3 항목 연계)
    if not targets:
        print("[INFO] 개별 패키지 미지정 설치는 아직 검사 대상이 아닙니다. 그대로 진행합니다.")
        return run_real_npm(args)

    if not gate_install(targets):
        print("[HALTED] 위험 패키지가 감지되어 설치를 중단합니다.")
        return 1

    return run_real_npm(args)


if __name__ == "__main__":
    sys.exit(main())

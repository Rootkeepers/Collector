"""`python -m rootkeepers.dashboard` 진입점.

server.py 를 직접 실행해도 되지만, 패키지 안에 있으므로 -m 실행이 정식이다
(경로를 손으로 맞출 필요가 없다).
"""

import sys

from rootkeepers.dashboard.server import main

if __name__ == "__main__":
    sys.exit(main())

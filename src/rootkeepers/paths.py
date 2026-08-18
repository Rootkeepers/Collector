"""저장소 안의 경로를 계산하는 **유일한** 곳.

이 모듈이 생기기 전에는 진입점마다 루트를 따로 계산했고, 그 결과 서로 다른
`.env`를 읽었다. 콘솔은 ``collectors/.env``만, CLI는 루트 ``.env``만 읽어서
"토큰을 넣었는데 한쪽에서만 인식된다"는 상황이 생길 수 있었다. 경로를 한
군데로 모아 그런 어긋남이 애초에 생기지 않게 한다.

`.env`도 같은 이유로 **루트 하나만** 읽는다. 한동안은 옛 위치도 함께 읽었지만,
두 파일 중 어느 값이 이겼는지 알기 어려워 오히려 같은 혼란을 만들었다. 옛
파일이 남아 있으면 무시하지 않고 경고한다(``LEGACY_ENV_FILE``).

루트는 파일 개수를 세어 거슬러 올라가는 방식(``parents[4]`` 같은 고정 깊이)이
아니라 **표식 파일**로 찾는다. 폴더를 옮기거나 한 단계 더 감싸도 깨지지 않는다.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# 루트임을 알려 주는 표식. 어느 하나라도 있으면 그 폴더를 루트로 본다.
_ROOT_MARKERS = ("requirements.txt", "pyproject.toml", ".git")


def _find_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if any((candidate / marker).exists() for marker in _ROOT_MARKERS):
            return candidate
    return start


#: 저장소 루트 (pyproject.toml / requirements.txt 가 있는 곳)
PROJECT_ROOT: Path = _find_root(Path(__file__).resolve().parent)
#: 파이썬 패키지 루트 — ``PYTHONPATH`` 에 들어가야 하는 경로
SRC_ROOT: Path = PROJECT_ROOT / "src"
#: 대시보드 코드 (서버 + 화면). 패키지 안에 있으므로 이 파일 기준으로 찾는다.
DASHBOARD_DIR: Path = Path(__file__).resolve().parent / "dashboard"
#: 브라우저로 그대로 내보내는 파일들 (console.html, app.css, app.js, 폰트)
STATIC_DIR: Path = DASHBOARD_DIR / "static"
#: 검사 대상을 지정하지 않았을 때 쓰는 센티널 — 이 PC에 전역 설치된 npm 패키지.
#: **실제 디스크 경로가 아니다.** 전역 설치에는 이를 선언한 매니페스트 파일이
#: 없어서 폴더로 가리킬 수가 없고, npm 에게 직접 물어봐야 한다
#: (``interceptor/global_npm.py``). 값 비교로만 쓰이므로 존재하지 않는 이름을
#: 골라 실제 경로와 절대 겹치지 않게 했다.
GLOBAL_SCOPE: Path = Path("<global-npm>")

#: `.env`는 저장소 루트 한 곳뿐이다. 두 곳을 읽던 시절에는 어느 파일이 이겼는지
#: 알기 어려웠고, 그게 이 모듈이 생긴 이유이기도 하다.
ENV_FILE: Path = PROJECT_ROOT / ".env"

#: 예전 위치. 더 이상 읽지 않지만, 남아 있으면 조용히 무시하지 않고 알려 준다
#: — 토큰을 넣어 뒀는데 인식되지 않는 상황이 제일 찾기 어렵기 때문이다.
LEGACY_ENV_FILE: Path = SRC_ROOT / "rootkeepers" / "collectors" / ".env"


def load_env() -> list[Path]:
    """루트 `.env`를 읽는다. 어떤 진입점에서 불러도 결과가 같다.

    python-dotenv가 없어도(선택 의존성) 조용히 넘어간다 — 환경변수를 셸이나
    서비스 파일에서 직접 넣어 쓰는 경우에는 dotenv가 필요 없기 때문이다.

    Returns:
        실제로 읽은 파일 목록. 읽지 못했으면 빈 리스트.
    """
    if LEGACY_ENV_FILE.exists():
        sys.stderr.write(
            f"[경고] {LEGACY_ENV_FILE} 는 더 이상 읽지 않습니다. "
            f"내용을 {ENV_FILE} 로 옮기세요.\n")

    try:
        from dotenv import load_dotenv
    except ImportError:
        return []

    if not ENV_FILE.exists():
        return []
    # override=False: 이미 설정된 환경변수(셸 export 등)가 항상 이긴다.
    load_dotenv(ENV_FILE, override=False)
    return [ENV_FILE]


def project_dir() -> Path:
    """검사 대상.

    `TRUSTGATE_PROJECT_DIR`가 있으면 그 폴더, 없으면 이 PC에 전역 설치된 npm
    패키지(``GLOBAL_SCOPE``).

    전역을 기본값으로 두는 이유는 clone 직후 아무 설정 없이 실행해도
    "Installed Packages" 화면이 **실제 데이터**로 채워지게 하기 위해서다.
    한동안은 저장소에 함께 커밋한 예제 ``package.json``을 기본값으로 썼는데,
    그건 이 PC의 설치 상태가 아니라 고정된 샘플이라 화면에 보이는 값이 사실과
    달랐다. 게다가 그 안에 적어 둔 패키지에 취약점 알림이 붙기 시작하면서,
    검사 대상도 아닌 파일 때문에 저장소가 계속 경고를 받는 상태가 됐다.
    """
    configured = os.getenv("TRUSTGATE_PROJECT_DIR", "").strip()
    if configured:
        return Path(configured)
    return GLOBAL_SCOPE


#: .env.example 에 적어 둔 자리표시자. ``cp .env.example .env`` 를 실행하면
#: 기본으로 이 값이 들어간다. "비어있지 않다"는 검사만으로는 이 값도 "설정됨"
#: 으로 보이는데, GitHub API는 이 값을 그대로 401로 거부한다 — 실제로 겪은
#: 혼란이라(대시보드가 "TOKEN OK"라고 했는데 모든 판정이 UNVERIFIABLE로
#: 막힘), 네트워크 호출 없이도 잡을 수 있는 이 케이스만이라도 구분한다.
_GITHUB_TOKEN_PLACEHOLDER = "ghp_replace_with_your_token"


def github_token_status() -> str:
    """``"missing"`` | ``"placeholder"`` | ``"set"``.

    실제로 GitHub가 이 토큰을 받아 줄지(만료·오타·revoke)는 API를 불러야만
    알 수 있어 여기서는 검사하지 않는다 — 이 함수는 그것보다 훨씬 흔했던
    실수, ``.env.example`` 을 그대로 복사해 두고 잊는 것만 걸러낸다.
    """
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if not token:
        return "missing"
    if token == _GITHUB_TOKEN_PLACEHOLDER:
        return "placeholder"
    return "set"


__all__ = [
    "PROJECT_ROOT", "SRC_ROOT", "DASHBOARD_DIR", "STATIC_DIR", "GLOBAL_SCOPE",
    "ENV_FILE", "LEGACY_ENV_FILE", "load_env", "project_dir", "github_token_status",
]

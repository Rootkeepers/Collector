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
_ROOT_MARKERS = ("requirements.txt", "compose.yaml", ".git")


def _find_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if any((candidate / marker).exists() for marker in _ROOT_MARKERS):
            return candidate
    return start


#: 저장소 루트 (compose.yaml / requirements.txt 가 있는 곳)
PROJECT_ROOT: Path = _find_root(Path(__file__).resolve().parent)
#: 파이썬 패키지 루트 — ``PYTHONPATH`` 에 들어가야 하는 경로
SRC_ROOT: Path = PROJECT_ROOT / "src"
#: 대시보드 코드 (서버 + 화면). 패키지 안에 있으므로 이 파일 기준으로 찾는다.
DASHBOARD_DIR: Path = Path(__file__).resolve().parent / "dashboard"
#: 브라우저로 그대로 내보내는 파일들 (console.html, app.css, app.js, 폰트)
STATIC_DIR: Path = DASHBOARD_DIR / "static"
#: 검사 대상 기본 폴더. 저장소에 함께 커밋되므로 clone 직후에도 화면이 채워진다.
DEMO_PROJECT: Path = PROJECT_ROOT / "examples" / "demo-project"

#: `.env`는 저장소 루트 한 곳뿐이다. 두 곳을 읽던 시절에는 어느 파일이 이겼는지
#: 알기 어려웠고, 그게 이 모듈이 생긴 이유이기도 하다.
ENV_FILE: Path = PROJECT_ROOT / ".env"

#: 예전 위치. 더 이상 읽지 않지만, 남아 있으면 조용히 무시하지 않고 알려 준다
#: — 토큰을 넣어 뒀는데 인식되지 않는 상황이 제일 찾기 어렵기 때문이다.
LEGACY_ENV_FILE: Path = SRC_ROOT / "rootkeepers" / "collectors" / ".env"


def load_env() -> list[Path]:
    """루트 `.env`를 읽는다. 어떤 진입점에서 불러도 결과가 같다.

    python-dotenv가 없어도(선택 의존성) 조용히 넘어간다 — 환경변수를 직접
    넣어 쓰는 Docker 실행에서는 dotenv가 필요 없기 때문이다.

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
    # override=False: 이미 설정된 환경변수(Docker의 -e 등)가 항상 이긴다.
    load_dotenv(ENV_FILE, override=False)
    return [ENV_FILE]


def project_dir() -> Path:
    """검사 대상 프로젝트 폴더.

    `TRUSTGATE_PROJECT_DIR`가 있으면 그것, 없으면 저장소의 예제 프로젝트.
    예제를 기본값으로 두는 이유는 clone 직후 아무 설정 없이 실행해도
    "Installed Packages" 화면이 비어 있지 않게 하기 위해서다.
    """
    configured = os.getenv("TRUSTGATE_PROJECT_DIR", "").strip()
    if configured:
        return Path(configured)
    return DEMO_PROJECT if DEMO_PROJECT.exists() else SRC_ROOT


__all__ = [
    "PROJECT_ROOT", "SRC_ROOT", "DASHBOARD_DIR", "STATIC_DIR", "DEMO_PROJECT",
    "ENV_FILE", "LEGACY_ENV_FILE", "load_env", "project_dir",
]

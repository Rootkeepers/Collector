"""이 PC에 **전역 설치된** npm 패키지 목록을 읽는다.

프로젝트 폴더는 `package.json` / `package-lock.json` 이라는 파일이 곧 정답지지만,
전역 설치에는 그런 파일이 없다. npm 전역 prefix 아래에는 `node_modules/` 만 있고
그것을 선언한 매니페스트가 존재하지 않는다. 그래서 파일을 읽는 대신 npm 자신에게
물어본다 (`npm ls -g --depth=0 --json`).

`--depth=0` 인 이유는 전역 설치에서 의미 있는 단위가 "내가 직접 깐 것"이기
때문이다. 전이 의존성까지 펼치면 수백 줄이 나오는데, 그건 사용자가 설치를
결정한 대상이 아니라 그 결과물이다.

수집 결과는 `collect_inventory()` 와 **같은 형태**로 돌려준다. 그래야 하류의
검증 파이프라인(쿨다운·OSV·규칙 엔진)이 전역이든 프로젝트든 구분 없이 그대로
동작한다.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from rootkeepers.paths import GLOBAL_SCOPE

#: `npm ls -g` 가 끝나기를 기다리는 한계. 전역 패키지가 많으면 수 초 걸린다.
LS_TIMEOUT_SEC = 60

#: 화면에 보여 줄 이름. 절대경로(사용자 이름 포함)를 노출하지 않는다.
DISPLAY_NAME = "전역 npm 패키지"


def is_global_scope(project_dir: Path | str | None) -> bool:
    """이 대상이 '전역 npm'을 가리키는가.

    `project_dir()` 가 돌려주는 센티널과 비교한다. 실제 디스크 경로가 아니므로
    `exists()` 같은 파일시스템 질의로는 판별할 수 없다.
    """
    if project_dir is None:
        return False
    return str(project_dir) == str(GLOBAL_SCOPE)


def describe_scope(project_dir: Path | str | None) -> str:
    """사람에게 보여 줄 검사 대상 이름.

    센티널(``<global-npm>``)은 값 비교를 위한 내부 표현일 뿐이라 그대로 화면에
    나가면 경로처럼 보여 오해를 부른다. 출력하는 쪽은 전부 이 함수를 거친다.
    """
    if is_global_scope(project_dir):
        return DISPLAY_NAME
    return str(project_dir)


def list_global_packages(*, timeout: int = LS_TIMEOUT_SEC) -> dict[str, str]:
    """전역 설치된 패키지의 이름 → 설치 버전.

    Returns:
        `{"typescript": "5.9.2", ...}`. 하나도 없으면 빈 dict.

    Raises:
        CollectorError: npm 을 찾지 못했거나, 실행이 시간 안에 끝나지 않았거나,
            출력이 JSON 이 아닌 경우.
    """
    # 지연 import: safe_npm 은 이 모듈보다 무겁고, 순환 import 를 피한다.
    from rootkeepers.interceptor.safe_npm import CollectorError, find_real_npm

    npm_path = find_real_npm()
    try:
        proc = subprocess.run(
            [npm_path, "ls", "-g", "--depth=0", "--json"],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise CollectorError(f"npm ls -g 가 {timeout}초 안에 끝나지 않았습니다.") from None

    # npm ls 는 peer dep 경고 등이 있으면 종료코드가 0이 아니면서도 JSON 은
    # 정상적으로 뱉는다. 종료코드로 실패를 판단하면 멀쩡한 목록을 버리게 된다.
    if not (proc.stdout or "").strip():
        detail = (proc.stderr or "").strip()[-500:] or f"종료코드 {proc.returncode}"
        raise CollectorError(f"npm ls -g 가 아무것도 출력하지 않았습니다: {detail}")

    try:
        payload = json.loads(proc.stdout)
    except ValueError as exc:
        raise CollectorError(f"npm ls -g 출력을 JSON 으로 읽을 수 없습니다: {exc}") from exc

    found: dict[str, str] = {}
    for name, node in (payload.get("dependencies") or {}).items():
        if not isinstance(node, dict):
            continue
        version = node.get("version")
        # 로컬 폴더를 전역에 link 한 항목은 레지스트리 패키지가 아니다 —
        # 버전 조회도 취약점 조회도 대상이 아니므로 제외한다.
        if node.get("resolved", "").startswith("file:") or node.get("link"):
            continue
        if isinstance(version, str) and version:
            found[name] = version
    return found


def global_inventory() -> dict[str, Any]:
    """`collect_inventory()` 와 같은 형태로 전역 패키지를 돌려준다.

    전역 설치에는 "선언된 범위(spec)"라는 개념이 없다. 사용자가 `npm i -g pkg`
    라고 치면 그 순간 버전이 곧 전부다. 그래서 `spec` 에는 설치 버전을 그대로
    넣는다 — 범위를 지어내는 것보다 사실에 가깝다.

    Raises:
        CollectorError: 목록을 얻지 못한 경우. 조용히 빈 목록을 돌려주면
            "전역 패키지가 없다"와 "npm 을 못 찾았다"가 화면에서 구분되지 않는다.
    """
    installed = list_global_packages()
    key = hashlib.sha256(str(GLOBAL_SCOPE).encode("utf-8")).hexdigest()[:16]
    packages = [
        {"name": name, "version": version, "spec": version, "dev": False}
        for name, version in sorted(installed.items())
    ]
    return {"project": DISPLAY_NAME, "project_key": key, "packages": packages}


__all__ = [
    "DISPLAY_NAME", "GLOBAL_SCOPE", "describe_scope", "global_inventory",
    "is_global_scope", "list_global_packages",
]

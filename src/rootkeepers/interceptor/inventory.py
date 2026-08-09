"""PC에 실제로 설치된 npm 패키지 목록을 읽어 콘솔로 보낼 형태로 만든다.

컨테이너 안에서는 사용자의 PC를 볼 수 없다 — Docker는 자기만의 환경이라
그 안에서 `npm ls`를 해도 호스트에 깔린 패키지가 나오지 않는다. 그래서
"지금 이 PC에 뭐가 깔려 있나"는 반드시 **로컬에서 도는 이 코드**가 읽어서
콘솔에 알려주는 구조여야 한다.

네트워크를 타지 않는다 — package.json / package-lock.json 파일만 읽으므로
빠르고, 레지스트리 상태와 무관하게 항상 동작한다.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def _project_identity(project_dir: Path) -> tuple[str, str]:
    """(표시용 이름, 안정적인 키)를 만든다.

    절대경로를 그대로 서버에 보내면 사용자 이름·디렉터리 구조가 그대로
    노출된다. 화면에는 폴더 이름만 보내고, 서로 다른 프로젝트가 같은 이름을
    가질 때를 구분하기 위한 키는 경로의 해시로 만든다(경로 자체는 안 보냄).
    """
    resolved = project_dir.resolve()
    name = resolved.name or str(resolved)
    key = hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()[:16]
    return name, key


def collect_inventory(project_dir: Path) -> dict[str, Any] | None:
    """프로젝트에 설치된 직접 의존성 목록을 수집한다.

    package.json의 dependencies/devDependencies에 선언된 패키지에 대해,
    package-lock.json에 기록된 **실제 설치 버전**을 짝지어 준다.
    (선언된 범위 "^4.17.0"이 아니라 실제로 깔린 "4.17.21"이 알고 싶은 값이다.)

    Returns:
        전송용 dict. package.json이 없으면 None.
    """
    pkg_json_path = project_dir / "package.json"
    if not pkg_json_path.exists():
        return None

    try:
        with open(pkg_json_path, encoding="utf-8") as f:
            pkg_json = json.load(f)
    except (OSError, ValueError):
        return None

    declared: dict[str, str] = {}
    for section, is_dev in (("dependencies", False), ("devDependencies", True)):
        for name, spec in (pkg_json.get(section) or {}).items():
            declared[name] = {"spec": spec, "dev": is_dev}

    # 실제 설치 버전은 lock 파일에서 읽는다
    installed: dict[str, str] = {}
    lock_path = project_dir / "package-lock.json"
    if lock_path.exists():
        try:
            with open(lock_path, encoding="utf-8") as f:
                lock = json.load(f)
            for path, node in (lock.get("packages") or {}).items():
                if not path.startswith("node_modules/"):
                    continue
                # "node_modules/@scope/name" 같은 중첩 경로도 마지막 것이 패키지명
                name = path.split("node_modules/", 1)[1]
                if "/node_modules/" in path:  # 전이 의존성의 중첩 설치는 제외
                    continue
                if isinstance(node, dict) and node.get("version"):
                    installed[name] = node["version"]
        except (OSError, ValueError):
            pass

    name, key = _project_identity(project_dir)
    packages = [
        {
            "name": pkg,
            "version": installed.get(pkg),          # 미설치면 None
            "spec": meta["spec"],
            "dev": meta["dev"],
        }
        for pkg, meta in sorted(declared.items())
    ]
    return {"project": name, "project_key": key, "packages": packages}


__all__ = ["collect_inventory"]

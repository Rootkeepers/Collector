"""PC에 실제로 설치된 npm 패키지 목록을 읽어 콘솔로 보낼 형태로 만든다.

콘솔은 자기가 읽을 수 있는 폴더(`TRUSTGATE_PROJECT_DIR`)만 직접 본다. 그 밖의
프로젝트가 어떤 패키지를 쓰는지는 **그 폴더에서 도는 이 코드**가 읽어서 콘솔에
알려주는 수밖에 없다 (`safe-npm --trustgate-sync`).

네트워크를 타지 않는다 — package.json / package-lock.json 파일만 읽으므로
빠르고, 레지스트리 상태와 무관하게 항상 동작한다.

검사 대상이 특정 폴더가 아니라 **이 PC의 전역 설치**(``GLOBAL_SCOPE``)일 때는
읽을 매니페스트 파일 자체가 없으므로 ``global_npm`` 으로 넘긴다. 그쪽은 npm 을
직접 호출하지만, 돌려주는 형태는 여기와 동일해서 하류 코드는 차이를 모른다.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from rootkeepers.interceptor.global_npm import global_inventory, is_global_scope


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
    # 전역 설치에는 package.json 이 없다 — npm 에게 직접 물어보는 경로로 간다.
    if is_global_scope(project_dir):
        return global_inventory()

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


def _walk_lock_v1(deps: dict, out: dict[tuple[str, str], dict]) -> None:
    """lockfileVersion 1(npm 6)의 중첩 ``dependencies`` 트리를 훑는다.

    v2/v3의 평평한 ``packages`` 맵과 달리 v1은 트리로만 기록한다. 오래된
    레포를 clone한 경우가 실제로 있으므로 폴백으로 남긴다.
    """
    for name, node in (deps or {}).items():
        if not isinstance(node, dict):
            continue
        version = node.get("version")
        if isinstance(version, str) and version and not version.startswith(("file:", "link:")):
            # v1 트리는 설치 위치를 기록하지 않는다. 평평한 배치로 가정한다.
            out.setdefault((name, version), {
                "name": name, "version": version, "dev": bool(node.get("dev")),
                "path": f"node_modules/{name}",
            })
        _walk_lock_v1(node.get("dependencies") or {}, out)


def collect_lock_packages(project_dir: Path) -> list[dict[str, Any]]:
    """lock 파일에 기록된 **모든** 패키지를 (전이 의존성 포함) 수집한다.

    ``collect_inventory()``는 package.json에 선언된 직접 의존성만 돌려준다 —
    대시보드가 "이 프로젝트가 무엇을 쓰기로 했는가"를 보여주기 위한 목록이기
    때문이다. 반면 인자 없는 ``npm install`` / ``npm ci``에서 실제로 디스크에
    깔리는 것은 전이 의존성까지 포함한 lock 전체이고, event-stream 사건처럼
    문제가 되는 쪽도 대개 그쪽이다. 그 경로를 점검하려면 별도의 수집이 필요해
    함수를 나눴다 (기존 인벤토리 전송 형식은 건드리지 않는다).

    네트워크를 타지 않는다 — lock 파일만 읽는다.

    Returns:
        ``{"name", "version", "dev", "path"}`` 딕셔너리 목록. 같은 이름의 서로
        다른 버전이 여러 곳에 중첩 설치될 수 있으므로 (name, version) 쌍으로
        중복을 제거한다(``path``는 처음 만난 위치). lock이 없거나 읽을 수
        없으면 빈 목록.
    """
    # 전역 설치에는 lock 파일이 없다. 애초에 전이 의존성까지 훑는 이 함수는
    # 인자 없는 `npm install` / `npm ci` 를 감시하려고 만든 것이라 전역 범위와는
    # 상관이 없다 — 빈 목록이 정확한 답이다.
    if is_global_scope(project_dir):
        return []

    lock_path = project_dir / "package-lock.json"
    if not lock_path.exists():
        return []
    try:
        with open(lock_path, encoding="utf-8") as f:
            lock = json.load(f)
    except (OSError, ValueError):
        return []

    found: dict[tuple[str, str], dict[str, Any]] = {}

    for path, node in (lock.get("packages") or {}).items():
        # "" 는 프로젝트 자기 자신이다. node_modules 밖의 항목(workspaces 등)도
        # 레지스트리 패키지가 아니므로 OSV로 물어볼 대상이 아니다.
        if not path.startswith("node_modules/") or not isinstance(node, dict):
            continue
        # 중첩 경로("a/node_modules/b")는 마지막 node_modules 뒤가 패키지명이다.
        name = path.rsplit("node_modules/", 1)[1]
        version = node.get("version")
        # link 항목은 로컬 workspace를 가리키는 심볼릭 링크다 — 레지스트리에
        # 없는 코드이므로 취약점 조회 대상이 아니다.
        if node.get("link") or not isinstance(version, str) or not version:
            continue
        # path는 lock이 알려주는 정확한 설치 위치다. "이 버전이 이미 디스크에
        # 있는가"를 판단할 때 쓴다 (이미 있으면 새 코드가 들어오지 않는다).
        found.setdefault((name, version), {
            "name": name, "version": version, "dev": bool(node.get("dev")),
            "path": path,
        })

    if not found:
        _walk_lock_v1(lock.get("dependencies") or {}, found)

    return [found[key] for key in sorted(found)]


__all__ = ["collect_inventory", "collect_lock_packages"]

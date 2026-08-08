"""safe-npm-setup: `npm`을 이 인터셉터로 가로채는 PATH shim을 사용자 환경에 설치한다.

`pip install rootkeepers-collector`만으로는 아무 것도 가로채지 않는다. 시스템 `npm`을
조용히 shadow하는 건 다른 도구/CI를 예고 없이 깨뜨릴 수 있으므로, 사용자가 이 커맨드를
명시적으로 한 번 실행해야 shim이 설치된다 (`safe-npm-setup`). 되돌리려면
`safe-npm-setup --uninstall`.
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
from pathlib import Path

SHIM_MARKER = "# rootkeepers-npm-shim"

SHIM_TEMPLATE = f"""#!/usr/bin/env bash
{SHIM_MARKER} (safe-npm-setup으로 생성됨 — 수동 편집하지 말고 `safe-npm-setup --uninstall` 후 재설치하세요)
set -euo pipefail

SHIM_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"

# 실제 npm은 이 shim 디렉터리를 제외한 PATH에서 찾는다 (자기 자신 재귀 호출 방지).
STRIPPED_PATH="$(printf '%s' "$PATH" | tr ':' '\\n' | grep -vxF "$SHIM_DIR" | paste -sd: -)"
REAL_NPM="$(PATH="$STRIPPED_PATH" command -v npm || true)"

if [ -z "$REAL_NPM" ]; then
    echo "[ERROR] 실제 npm 바이너리를 찾을 수 없습니다." >&2
    exit 1
fi

SAFE_NPM="$(command -v safe-npm || true)"
if [ -z "$SAFE_NPM" ]; then
    echo "[ERROR] safe-npm 커맨드를 찾을 수 없습니다 (pip install rootkeepers-collector 필요). 실제 npm으로 통과시킵니다." >&2
    exec "$REAL_NPM" "$@"
fi

export ROOTKEEPERS_REAL_NPM="$REAL_NPM"
exec "$SAFE_NPM" "$@"
"""

RC_BLOCK_MARKER = "# >>> rootkeepers npm shim >>>"
RC_BLOCK_END = "# <<< rootkeepers npm shim <<<"


def _shell_rc_file() -> Path:
    """사용자의 로그인 셸에 맞는 rc 파일 경로를 고른다."""
    shell = os.environ.get("SHELL", "")
    home = Path.home()
    if "zsh" in shell:
        return home / ".zshrc"
    return home / ".bashrc"


def _path_dirs() -> list[Path]:
    return [Path(p) for p in os.environ.get("PATH", "").split(os.pathsep) if p]


def _is_our_shim(path: Path) -> bool:
    try:
        return SHIM_MARKER in path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False


def _real_npm_dir() -> Path | None:
    """PATH를 직접 훑어 '진짜' npm이 있는 디렉터리를 찾는다.

    ``shutil.which("npm")``은 이미 설치된 우리 shim을 그대로 찾아버릴 수 있다
    (재설치/업그레이드 시나리오). shim 파일은 내용으로 식별해 건너뛴다.
    """
    for directory in _path_dirs():
        candidate = directory / "npm"
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        if _is_our_shim(candidate):
            continue
        return directory
    return None


def _pick_shim_dir() -> tuple[Path, bool]:
    """설치에 쓸 디렉터리와, PATH에 이미 우선순위로 잡혀 있는지 여부를 반환한다.

    ``~/.local/bin``이 이미 존재하고 실제 npm 디렉터리보다 PATH 앞순위면 그대로
    재사용한다 (많은 리눅스/macOS 개발 환경에 이미 그렇게 설정돼 있다). 아니면
    전용 디렉터리(``~/.rootkeepers/bin``)를 새로 만들고, 셸 rc 파일에 PATH를
    추가해줘야 한다고 알린다.
    """
    candidate = Path.home() / ".local" / "bin"
    npm_dir = _real_npm_dir()
    dirs = _path_dirs()

    if candidate.is_dir() and npm_dir is not None:
        try:
            candidate_idx = dirs.index(candidate)
        except ValueError:
            candidate_idx = None
        try:
            npm_idx = next(i for i, d in enumerate(dirs) if d == npm_dir)
        except StopIteration:
            npm_idx = None
        if candidate_idx is not None and npm_idx is not None and candidate_idx < npm_idx:
            return candidate, True

    return Path.home() / ".rootkeepers" / "bin", False


def _ensure_path_in_rc(shim_dir: Path) -> bool:
    """rc 파일에 PATH 앞부분에 shim_dir를 추가하는 블록을 넣는다. 이미 있으면 건드리지 않는다.

    Returns:
        새로 추가했으면 True, 이미 있어서 건드리지 않았으면 False.
    """
    rc_path = _shell_rc_file()
    existing = rc_path.read_text(encoding="utf-8") if rc_path.exists() else ""
    if RC_BLOCK_MARKER in existing:
        return False

    block = (
        f"\n{RC_BLOCK_MARKER}\n"
        f'export PATH="{shim_dir}:$PATH"\n'
        f"{RC_BLOCK_END}\n"
    )
    with rc_path.open("a", encoding="utf-8") as f:
        f.write(block)
    return True


def _remove_path_from_rc() -> bool:
    rc_path = _shell_rc_file()
    if not rc_path.exists():
        return False
    text = rc_path.read_text(encoding="utf-8")
    if RC_BLOCK_MARKER not in text:
        return False

    start = text.index(RC_BLOCK_MARKER)
    end = text.index(RC_BLOCK_END, start) + len(RC_BLOCK_END)
    # Also eat one leading newline so repeated install/uninstall doesn't
    # accumulate blank lines in the rc file.
    while start > 0 and text[start - 1] == "\n":
        start -= 1
    new_text = text[:start] + text[end:]
    rc_path.write_text(new_text, encoding="utf-8")
    return True


def install() -> int:
    if shutil.which("safe-npm") is None:
        print(
            "[ERROR] safe-npm 커맨드를 찾을 수 없습니다. "
            "먼저 `pip install rootkeepers-collector`를 실행하세요.",
            file=sys.stderr,
        )
        return 1

    shim_dir, already_prioritized = _pick_shim_dir()
    shim_dir.mkdir(parents=True, exist_ok=True)
    shim_path = shim_dir / "npm"
    shim_path.write_text(SHIM_TEMPLATE, encoding="utf-8")
    shim_path.chmod(shim_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"[OK] npm shim 설치 완료: {shim_path}")

    if already_prioritized:
        print(f"[OK] {shim_dir}가 이미 PATH에서 실제 npm보다 앞순위입니다. 새 셸부터 바로 적용됩니다.")
        return 0

    added = _ensure_path_in_rc(shim_dir)
    rc_path = _shell_rc_file()
    if added:
        print(f"[OK] {rc_path}에 PATH 설정을 추가했습니다.")
    else:
        print(f"[INFO] {rc_path}에 이미 PATH 설정이 있습니다.")
    print(f"[ACTION REQUIRED] 적용하려면 새 터미널을 열거나 다음을 실행하세요: source {rc_path}")
    return 0


def uninstall() -> int:
    removed_any = False
    for shim_dir in (Path.home() / ".local" / "bin", Path.home() / ".rootkeepers" / "bin"):
        shim_path = shim_dir / "npm"
        if shim_path.is_file() and SHIM_MARKER in shim_path.read_text(encoding="utf-8"):
            shim_path.unlink()
            print(f"[OK] 제거됨: {shim_path}")
            removed_any = True

    if _remove_path_from_rc():
        print(f"[OK] {_shell_rc_file()}에서 PATH 설정을 제거했습니다.")
        removed_any = True

    if not removed_any:
        print("[INFO] 설치된 shim을 찾지 못했습니다 (이미 제거됐거나 설치된 적이 없습니다).")
    else:
        print("[ACTION REQUIRED] 적용하려면 새 터미널을 여세요.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if "--uninstall" in args:
        return uninstall()
    return install()


if __name__ == "__main__":
    sys.exit(main())

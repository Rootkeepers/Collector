#!/usr/bin/env bash
# npm shim 재귀 방지 회귀 테스트.
#
# 과거에 터미널 `npm install`이 무한 반복된 원인은 두 가지였다:
#   1) shim이 "자기 디렉터리"만 PATH에서 제외해서, 다른 디렉터리에 남은
#      낡은 shim을 진짜 npm으로 착각하고 서로를 계속 호출했다.
#   2) npm이 내부적으로 npm을 다시 부르면 그때마다 검사가 새로 돌았다.
#
# 이 테스트는 그 상황을 통째로 재현한다 — shim 두 개 + 자기 자신을 다시 부르는
# 가짜 npm. shim_installer.SHIM_TEMPLATE을 직접 렌더해서 쓰므로, 템플릿이
# 퇴행하면 여기서 잡힌다.
#
# 실행: bash tests/test_npm_shim_recursion.sh

set -uo pipefail

REPO_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../src" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PY="${PYTHON:-python}"

fail() { echo "[FAIL] $*" >&2; exit 1; }

# --- shim을 설치기에서 그대로 뽑아온다 (테스트가 실제 산출물을 검증하도록) ---
# Git Bash의 /c/... 경로는 Windows Python이 못 읽으므로 변환해서 넘긴다.
if command -v cygpath >/dev/null 2>&1; then
    REPO_SRC_PY="$(cygpath -w "$REPO_SRC")"
else
    REPO_SRC_PY="$REPO_SRC"
fi

# PYTHONIOENCODING: Windows 콘솔 기본 인코딩(cp949)이 shim 주석의 문자를 못 쓴다.
REPO_SRC_PY="$REPO_SRC_PY" PYTHONIOENCODING=utf-8 "$PY" -c "
import os, sys
sys.path.insert(0, os.environ['REPO_SRC_PY'])
from rootkeepers.interceptor.shim_installer import SHIM_TEMPLATE
sys.stdout.write(SHIM_TEMPLATE)
" > "$TMP/shim" || fail "SHIM_TEMPLATE 렌더 실패"

mkdir -p "$TMP/shim_new" "$TMP/shim_stale" "$TMP/realbin"

# 현재 shim과, 예전에 설치돼 남아 있는 shim — 둘 다 PATH에 있다.
install -m 755 "$TMP/shim" "$TMP/shim_new/npm"
install -m 755 "$TMP/shim" "$TMP/shim_stale/npm"

# --- 가짜 "진짜 npm": 호출을 기록하고, 라이프사이클처럼 npm을 다시 부른다 ---
cat > "$TMP/realbin/npm" <<'EOF'
#!/usr/bin/env bash
echo "REAL_NPM $*" >> "$COUNT_FILE"
if [ -z "${NESTED:-}" ]; then
    NESTED=1 npm --version >/dev/null 2>&1 || true
fi
EOF
chmod +x "$TMP/realbin/npm"

# --- 가짜 safe-npm: 호출을 기록하고 shim이 알려준 진짜 npm에 위임 ---
cat > "$TMP/realbin/safe-npm" <<'EOF'
#!/usr/bin/env bash
echo "SAFE_NPM $*" >> "$COUNT_FILE"
[ -n "${ROOTKEEPERS_REAL_NPM:-}" ] || { echo "ROOTKEEPERS_REAL_NPM 미설정" >&2; exit 1; }
exec "$ROOTKEEPERS_REAL_NPM" "$@"
EOF
chmod +x "$TMP/realbin/safe-npm"

export COUNT_FILE="$TMP/calls.log"

# shim이 PATH를 훑는 방식을 검증하므로, 진짜 npm의 **위치**를 바꿔가며 돌린다.
# 특히 맨 끝은 과거에 실제로 깨졌던 자리다(마지막 항목 누락 버그).
run_case() {
    local label="$1" search_path="$2"
    : > "$COUNT_FILE"

    # timeout은 축소된 PATH가 아니라 테스트 셸의 것으로 찾아야 한다.
    PATH="$search_path" "$TIMEOUT_ABS" 20 npm install lodash
    local status=$?

    [ "$status" -ne 124 ] || fail "[$label] 20초 안에 끝나지 않았다 — 재귀에 빠졌다"
    [ "$status" -eq 0 ] || fail "[$label] shim이 0이 아닌 코드로 끝났다 (exit=$status)"

    local safe_calls real_calls
    safe_calls=$(grep -c '^SAFE_NPM' "$COUNT_FILE" || true)
    real_calls=$(grep -c '^REAL_NPM' "$COUNT_FILE" || true)

    # 검사는 딱 한 번. npm이 자기를 다시 불러도 재검사하지 않는다.
    [ "$safe_calls" -eq 1 ] || fail "[$label] safe-npm이 ${safe_calls}번 불렸다 (기대: 1) — 중첩 검사 발생"
    # 최초 위임 1회 + 중첩 호출 1회가 그대로 진짜 npm에 도달해야 한다.
    [ "$real_calls" -eq 2 ] || fail "[$label] 진짜 npm이 ${real_calls}번 불렸다 (기대: 2)"

    echo "[PASS] $label — safe-npm=${safe_calls}회, real npm=${real_calls}회"
}

# shim은 bash/grep/tr을 PATH에서 찾아 쓴다. 그 시스템 경로를 그대로 쓰면 진짜
# npm이 딸려 들어와(Fedora는 /usr/bin에 grep과 npm이 함께 있다) "맨 끝" 경우를
# 검증할 수 없다. 그렇다고 npm이 있는 디렉터리를 빼면 grep까지 사라진다.
#
# 그래서 필요한 명령만 절대 경로로 위임하는 **얇은 래퍼**를 샌드박스에 둔다.
# 바이너리를 복사하지 않으므로 공유 라이브러리 의존성이 깨질 일도 없다.
TIMEOUT_ABS="$(command -v timeout)" || fail "timeout이 필요하다 (coreutils)"
BASH_ABS="$(command -v bash)" || fail "bash를 찾을 수 없다"
mkdir -p "$TMP/util"
for cmd in bash grep tr; do
    real="$(command -v "$cmd")" || fail "$cmd 을(를) 찾을 수 없다"
    { printf '#!%s\n' "$BASH_ABS"; printf 'exec %q "$@"\n' "$real"; } > "$TMP/util/$cmd"
    chmod +x "$TMP/util/$cmd"
done
UTIL_PATH="$TMP/util"

PATH="$UTIL_PATH" command -v grep >/dev/null 2>&1 || fail "샌드박스에 grep이 없다"
PATH="$UTIL_PATH" command -v npm  >/dev/null 2>&1 && fail "샌드박스에 npm이 섞여 테스트가 오염된다"

# 낡은 shim이 중간에 끼어 있는 상황.
run_case "진짜 npm이 PATH 중간" \
    "$TMP/shim_new:$TMP/shim_stale:$TMP/realbin:$UTIL_PATH"

# 진짜 npm이 PATH 맨 끝 — Fedora의 /usr/bin 처럼.
run_case "진짜 npm이 PATH 맨 끝" \
    "$TMP/shim_new:$TMP/shim_stale:$UTIL_PATH:$TMP/realbin"

echo "[OK] 모든 경우에서 shim이 낡은 shim을 건너뛰고 재검사하지 않는다"

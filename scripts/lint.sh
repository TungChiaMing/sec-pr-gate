#!/usr/bin/env bash
#
# lint.sh — 掃 pipeline 本身：actionlint（schema / expression / shellcheck）+ zizmor（安全稽核）
#
# 可調環境變數：
#   TARGET        repo 根目錄      (預設 /src)
#   ZIZMOR_ARGS   額外參數         (例：--persona=pedantic)
#
# argv 可直接指定要檢查的 workflow 檔；不給就掃 $TARGET/.github/workflows/
set -Eeuo pipefail

TARGET="${TARGET:-/src}"
WF_DIR="$TARGET/.github/workflows"
ZIZMOR_ARGS="${ZIZMOR_ARGS:-}"

log() { printf '\033[1;36m==>\033[0m %s\n' "$*" >&2; }

FILES=("$@")
if [ "${#FILES[@]}" -eq 0 ]; then
  if [ ! -d "$WF_DIR" ]; then
    echo "找不到 $WF_DIR —— 確認掛載的是 repo 根目錄（make lint-ci 會處理）" >&2
    exit 2
  fi
  while IFS= read -r -d '' f; do FILES+=("$f"); done \
    < <(find "$WF_DIR" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 | sort -z)
fi

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "$WF_DIR 底下沒有 workflow 檔" >&2
  exit 2
fi

log "檢查 ${#FILES[@]} 個 workflow：$(printf '%s ' "${FILES[@]##*/}")"

FAIL=0

# actionlint 1.7.10 的 github context schema 還沒收錄 job_workflow_ref / job_workflow_sha，
# 但 GitHub 確實提供（也是 reusable workflow 的標準 OIDC claim）。這是工具落後，不是我們寫錯。
ACTIONLINT_IGNORE='property "job_workflow_(ref|sha)" is not defined'

log "actionlint（schema + expression + shellcheck）"
if actionlint -ignore "$ACTIONLINT_IGNORE" "${FILES[@]}"; then
  printf '\033[1;32m[OK]\033[0m actionlint 無問題\n' >&2
else
  printf '\033[1;31m[FAIL]\033[0m actionlint 有發現\n' >&2
  FAIL=1
fi

log "zizmor --offline ${ZIZMOR_ARGS}"
# shellcheck disable=SC2086
if zizmor --offline ${ZIZMOR_ARGS} "${FILES[@]}"; then
  printf '\033[1;32m[OK]\033[0m zizmor 無 findings\n' >&2
else
  printf '\033[1;31m[FAIL]\033[0m zizmor 有 findings\n' >&2
  FAIL=1
fi

exit "$FAIL"

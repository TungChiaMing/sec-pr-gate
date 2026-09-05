#!/usr/bin/env bash
#
# pr-gate.sh — 針對一個 PR 做「只掃變更檔」的 semgrep + 全庫 trivy，
#              並把結果以固定錨點 comment 回寫到 PR（重複執行會更新同一則）。
#
# 用法：
#   pr-gate.sh <PR 編號或 PR URL>
#
# 必要環境變數：
#   GH_TOKEN     GitHub token（repo + pull_request write 權限）
# 選用：
#   GH_REPO          owner/repo；未給則從 /src 的 git remote 推斷
#   POST_COMMENT     1=回寫 PR comment（預設 1），0=只在本地輸出
#   TARGET/OUT_DIR/FAIL_ON_* 等同 scan.sh
set -Eeuo pipefail

TARGET="${TARGET:-/src}"
OUT_DIR="${OUT_DIR:-/out}"
POST_COMMENT="${POST_COMMENT:-1}"
MARKER='<!-- sec-pr-gate -->'

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 2; }

PR_REF="${1:-}"
[ -n "$PR_REF" ] || die "用法：pr-gate.sh <PR 編號或 URL>"
[ -n "${GH_TOKEN:-}" ] || die "缺少 GH_TOKEN。container 內無法用瀏覽器登入，請改用 token（見 README）。"

# ---------- 判斷 repo ----------
if [ -z "${GH_REPO:-}" ]; then
  if git -C "$TARGET" rev-parse --git-dir >/dev/null 2>&1; then
    GH_REPO="$(git -C "$TARGET" remote get-url origin 2>/dev/null \
      | sed -E 's#^git@github\.com:#|#; s#^https://github\.com/#|#' \
      | cut -d'|' -f2 | sed -E 's#\.git$##')"
  fi
fi
[ -n "${GH_REPO:-}" ] || die "無法判斷 repo，請設定 GH_REPO=owner/repo"
export GH_REPO
log "repo=$GH_REPO  pr=$PR_REF"

gh auth status >/dev/null 2>&1 || die "gh 認證失敗，請檢查 GH_TOKEN"

# ---------- 取變更檔 ----------
mapfile -t CHANGED < <(gh pr view "$PR_REF" --repo "$GH_REPO" --json files \
                        --jq '.files[].path' 2>/dev/null || true)
[ "${#CHANGED[@]}" -gt 0 ] || die "抓不到 PR 變更檔（PR 不存在或權限不足？）"
log "PR 變更檔 ${#CHANGED[@]} 個"

# 只留下工作目錄裡實際存在的（刪除的檔案掃不了）
SCAN_PATHS=()
for f in "${CHANGED[@]}"; do
  [ -f "$TARGET/$f" ] && SCAN_PATHS+=("$TARGET/$f")
done

if [ "${#SCAN_PATHS[@]}" -eq 0 ]; then
  log "沒有存在於工作目錄的變更檔，只跑 trivy"
  SKIP_SEMGREP=1 TARGET="$TARGET" OUT_DIR="$OUT_DIR" /usr/local/bin/scan.sh
  RC=$?
else
  set +e
  TARGET="$TARGET" OUT_DIR="$OUT_DIR" /usr/local/bin/scan.sh "${SCAN_PATHS[@]}"
  RC=$?
  set -e
fi

# ---------- 組 comment ----------
BODY_FILE="$OUT_DIR/comment.md"
{
  echo "$MARKER"
  cat "$OUT_DIR/summary.md"
  echo
  if [ "$RC" -eq 0 ]; then
    echo "**結果：✅ PASS** — 未達阻擋門檻。"
  else
    echo "**結果：❌ FAIL** — 已達阻擋門檻，請修正後重跑。"
  fi
  echo
  echo "<sub>由 \`sec-pr-gate\` 產生 · $(date -u '+%Y-%m-%d %H:%M UTC')</sub>"
} > "$BODY_FILE"

# ---------- 回寫（同一則 comment 更新） ----------
if [ "$POST_COMMENT" = "1" ]; then
  PR_NUM="$(gh pr view "$PR_REF" --repo "$GH_REPO" --json number --jq '.number')"
  EXISTING="$(gh api "repos/$GH_REPO/issues/$PR_NUM/comments" --paginate \
              --jq "[.[] | select(.body | contains(\"$MARKER\")) | .id] | first // empty" || true)"
  if [ -n "$EXISTING" ]; then
    log "更新既有 comment id=$EXISTING"
    gh api -X PATCH "repos/$GH_REPO/issues/comments/$EXISTING" \
      -F body=@"$BODY_FILE" >/dev/null
  else
    log "建立新 comment"
    gh api -X POST "repos/$GH_REPO/issues/$PR_NUM/comments" \
      -F body=@"$BODY_FILE" >/dev/null
  fi
fi

exit "$RC"

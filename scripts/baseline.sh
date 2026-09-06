#!/usr/bin/env bash
#
# baseline.sh — 在拋棄式 git worktree 裡掃 BASE_REF，輸出 *.base.json
#
#   TARGET        repo 根目錄        (預設 /src)
#   OUT_DIR       報告輸出           (預設 /src/out)
#   BASE_REF      基準 ref           (預設 main)
#   BASE_DIR      worktree 暫存路徑  (預設 /tmp/spg-base，容器內，不落在使用者 repo)
set -Eeuo pipefail

TARGET="${TARGET:-/src}"
OUT_DIR="${OUT_DIR:-/src/out}"
BASE_REF="${BASE_REF:-main}"
BASE_DIR="${BASE_DIR:-/tmp/spg-base}"
SEMGREP_RULES="${SEMGREP_RULES:-p/default p/secrets p/owasp-top-ten}"
TRIVY_SCANNERS="${TRIVY_SCANNERS:-vuln,secret,misconfig}"

log() { printf '\033[1;36m==>\033[0m %s\n' "$*" >&2; }

mkdir -p "$OUT_DIR"
cd "$TARGET"

BASE_SHA="$(git rev-parse "$BASE_REF")"
log "baseline ref=$BASE_REF sha=${BASE_SHA:0:7}"

cleanup() {
  cd "$TARGET" 2>/dev/null || return 0
  git worktree remove --force "$BASE_DIR" >/dev/null 2>&1 || true
  rm -rf "$BASE_DIR"
  git worktree prune >/dev/null 2>&1 || true
}
trap cleanup EXIT

git worktree prune
rm -rf "$BASE_DIR"
git worktree add --detach "$BASE_DIR" "$BASE_REF" >/dev/null

cd "$BASE_DIR"

CFG=()
for r in $SEMGREP_RULES; do CFG+=(--config "$r"); done

log "semgrep（base）"
set +e
semgrep scan "${CFG[@]}" --metrics=off --disable-version-check --quiet \
  --exclude out --exclude base --exclude reports --exclude node_modules \
  --json-output "$OUT_DIR/semgrep.base.json" .
rc=$?
set -e
[ "$rc" -ge 2 ] && echo "[warn] semgrep base 執行失敗 (exit=$rc)" >&2

log "trivy（base）"
trivy fs --scanners "$TRIVY_SCANNERS" --no-progress --exit-code 0 \
  --skip-dirs out --skip-dirs base --skip-dirs reports --skip-dirs node_modules \
  --skip-db-update --skip-check-update \
  --format json --output "$OUT_DIR/trivy.base.json" .

log "base 報告：$OUT_DIR/semgrep.base.json, $OUT_DIR/trivy.base.json"

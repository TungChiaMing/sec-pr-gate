#!/usr/bin/env bash
# 統一入口：scan / pr-gate / version / 任意指令
set -Eeuo pipefail

# 掛進來的 repo 擁有者 uid 與 container 內不同，git 會拒絕操作
git config --global --add safe.directory '*' >/dev/null 2>&1 || true

cmd="${1:-scan}"
[ $# -gt 0 ] && shift || true

case "$cmd" in
  scan)     exec /usr/local/bin/scan.sh "$@" ;;
  pr-gate)  exec /usr/local/bin/pr-gate.sh "$@" ;;
  count)    exec python3 /usr/local/bin/count.py "$@" ;;
  lint)     exec /usr/local/bin/lint.sh "$@" ;;
  version)
    echo "semgrep : $(semgrep --version 2>/dev/null)"
    echo "trivy   : $(trivy --version 2>/dev/null | head -1)"
    echo "gh      : $(gh --version 2>/dev/null | head -1)"
    echo "actionlint: $(actionlint --version 2>/dev/null | head -1)"
    echo "zizmor  : $(zizmor --version 2>/dev/null | head -1)"
    echo "python  : $(python --version 2>&1)"
    ;;
  sh|bash)  exec bash "$@" ;;
  *)        exec "$cmd" "$@" ;;
esac

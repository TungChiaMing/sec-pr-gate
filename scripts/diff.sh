#!/usr/bin/env bash
# diff.sh — ingest base + head 進 SQLite，印出這個分支相對 BASE_REF 新增了什麼
set -Eeuo pipefail

TARGET="${TARGET:-/src}"
OUT_DIR="${OUT_DIR:-/src/out}"
BASE_REF="${BASE_REF:-main}"
DB="${DB:-$OUT_DIR/findings.db}"
FP=/usr/local/bin/findings.py

cd "$TARGET"
for f in "$OUT_DIR/semgrep.json" "$OUT_DIR/trivy.json"; do
  [ -s "$f" ] || { echo "找不到 $f —— 先跑 make scan" >&2; exit 2; }
done
for f in "$OUT_DIR/semgrep.base.json" "$OUT_DIR/trivy.base.json"; do
  [ -s "$f" ] || { echo "找不到 $f —— 先跑 make baseline" >&2; exit 2; }
done

python3 "$FP" --db "$DB" ingest --run base --sha "$(git rev-parse "$BASE_REF")" \
  "$OUT_DIR/semgrep.base.json" "$OUT_DIR/trivy.base.json"
python3 "$FP" --db "$DB" ingest --run head --sha "$(git rev-parse HEAD)" \
  "$OUT_DIR/semgrep.json" "$OUT_DIR/trivy.json"
python3 "$FP" --db "$DB" new --base base --head head --json "$OUT_DIR/new.json" "$@"

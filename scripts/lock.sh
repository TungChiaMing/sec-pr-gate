#!/usr/bin/env bash
# lock.sh — 產生 package-lock.json（不安裝 node_modules）
set -Eeuo pipefail
TARGET="${TARGET:-/src}"
DIR="${LOCK_DIR:-$TARGET/samples/node-api}"
cd "$DIR"
npm install --package-lock-only --ignore-scripts --no-audit --no-fund
echo "lockfileVersion: $(python3 -c 'import json;print(json.load(open("package-lock.json"))["lockfileVersion"])')"
echo "packages: $(python3 -c 'import json;print(len(json.load(open("package-lock.json"))["packages"]))')"

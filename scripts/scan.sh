#!/usr/bin/env bash
#
# scan.sh — semgrep + trivy 掃描，輸出 JSON / SARIF / Markdown 摘要
#
# 可調環境變數：
#   TARGET            掃描根目錄            (預設 /src)
#   OUT_DIR           報告輸出目錄          (預設 /out)
#   SEMGREP_RULES     空白分隔的 ruleset    (預設 "p/default p/secrets p/owasp-top-ten")
#   TRIVY_SCANNERS    逗號分隔              (預設 "vuln,secret,misconfig")
#   FAIL_ON_SEMGREP   ERROR|WARNING|INFO|none (預設 ERROR)
#   FAIL_ON_TRIVY     逗號分隔 severity|none  (預設 HIGH,CRITICAL)
#   SKIP_SEMGREP / SKIP_TRIVY   設 1 可跳過
#
# argv 可指定要掃的路徑（pr-gate.sh 會用來只掃變更檔）
set -Eeuo pipefail

TARGET="${TARGET:-/src}"
OUT_DIR="${OUT_DIR:-/out}"
SEMGREP_RULES="${SEMGREP_RULES:-p/default p/secrets p/owasp-top-ten}"
TRIVY_SCANNERS="${TRIVY_SCANNERS:-vuln,secret,misconfig}"
FAIL_ON_SEMGREP="${FAIL_ON_SEMGREP:-ERROR}"
FAIL_ON_TRIVY="${FAIL_ON_TRIVY:-HIGH,CRITICAL}"
SKIP_SEMGREP="${SKIP_SEMGREP:-0}"
SKIP_TRIVY="${SKIP_TRIVY:-0}"

PATHS=("$@")
if [ "${#PATHS[@]}" -eq 0 ]; then PATHS=("$TARGET"); fi

log() { printf '\033[1;36m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }

mkdir -p "$OUT_DIR"
SEM_JSON="$OUT_DIR/semgrep.json"
TRIVY_JSON="$OUT_DIR/trivy.json"
SUMMARY="$OUT_DIR/summary.md"
: > "$SUMMARY"

########################################
# semgrep
########################################
SEM_ERROR=0; SEM_WARNING=0; SEM_INFO=0; SEM_RAN=0
if [ "$SKIP_SEMGREP" != "1" ]; then
  log "semgrep: $SEMGREP_RULES  →  ${PATHS[*]}"
  CFG=()
  for r in $SEMGREP_RULES; do CFG+=(--config "$r"); done

  if semgrep scan --help 2>/dev/null | grep -q -- '--sarif-output'; then
    OUTARGS=(--json-output "$SEM_JSON" --sarif-output "$OUT_DIR/semgrep.sarif")
  else
    warn "此 semgrep 版本不支援 --sarif-output，只產生 JSON"
    OUTARGS=(--json --output "$SEM_JSON")
  fi

  set +e
  semgrep scan "${CFG[@]}" \
    --metrics=off --disable-version-check --quiet \
    --exclude out --exclude base --exclude reports --exclude node_modules \
    "${OUTARGS[@]}" "${PATHS[@]}"
  rc=$?
  set -e
  # semgrep: 0=乾淨 1=有 finding(僅 --error 時) >=2=執行錯誤
  if [ "$rc" -ge 2 ]; then
    warn "semgrep 執行失敗 (exit=$rc)"
  fi

  if [ -s "$SEM_JSON" ]; then
    SEM_RAN=1
    SEM_ERROR=$(jq '[.results[]? | select(.extra.severity=="ERROR")]   | length' "$SEM_JSON")
    SEM_WARNING=$(jq '[.results[]? | select(.extra.severity=="WARNING")] | length' "$SEM_JSON")
    SEM_INFO=$(jq '[.results[]? | select(.extra.severity=="INFO")]      | length' "$SEM_JSON")
  fi
fi

########################################
# trivy
########################################
declare -A TV=( [CRITICAL]=0 [HIGH]=0 [MEDIUM]=0 [LOW]=0 [UNKNOWN]=0 )
TRIVY_RAN=0
if [ "$SKIP_TRIVY" != "1" ]; then
  log "trivy fs --scanners $TRIVY_SCANNERS  →  $TARGET"
  set +e
  trivy fs --scanners "$TRIVY_SCANNERS" --no-progress --exit-code 0 \
       --skip-dirs out --skip-dirs base --skip-dirs reports --skip-dirs node_modules \
       --format json --output "$TRIVY_JSON" "$TARGET"
  rc=$?
  set -e
  [ "$rc" -ne 0 ] && warn "trivy 執行失敗 (exit=$rc)"

  if [ -s "$TRIVY_JSON" ]; then
    TRIVY_RAN=1
    trivy convert --format sarif --output "$OUT_DIR/trivy.sarif" "$TRIVY_JSON" >/dev/null 2>&1 \
      || warn "trivy convert → SARIF 失敗（不影響門檻判斷）"
    for s in CRITICAL HIGH MEDIUM LOW UNKNOWN; do
      TV[$s]=$(jq --arg sev "$s" \
        '[ .Results[]? | (.Vulnerabilities[]?, .Secrets[]?, .Misconfigurations[]?) | select(.Severity==$sev) ] | length' \
        "$TRIVY_JSON")
    done
  fi
fi

########################################
# 摘要
########################################
{
  echo "## 🔒 sec-pr-gate 掃描結果"
  echo
  echo "掃描範圍：\`${PATHS[*]}\`"
  echo
  echo "| 工具 | CRITICAL / ERROR | HIGH / WARNING | MEDIUM / INFO | LOW | UNKNOWN |"
  echo "|---|---|---|---|---|---|"
  if [ "$SEM_RAN" = "1" ]; then
    echo "| semgrep | $SEM_ERROR | $SEM_WARNING | $SEM_INFO | - | - |"
  else
    echo "| semgrep | _skipped_ | | | | |"
  fi
  if [ "$TRIVY_RAN" = "1" ]; then
    echo "| trivy | ${TV[CRITICAL]} | ${TV[HIGH]} | ${TV[MEDIUM]} | ${TV[LOW]} | ${TV[UNKNOWN]} |"
  else
    echo "| trivy | _skipped_ | | | | |"
  fi
  echo
  if [ "$SEM_RAN" = "1" ] && [ "$((SEM_ERROR + SEM_WARNING))" -gt 0 ]; then
    echo "<details><summary>semgrep 前 20 筆</summary>"
    echo
    echo '```'
    jq -r '.results[]? | select(.extra.severity=="ERROR" or .extra.severity=="WARNING")
           | "\(.extra.severity)\t\(.path):\(.start.line)\t\(.check_id)"' "$SEM_JSON" | head -20
    echo '```'
    echo
    echo "</details>"
    echo
  fi
  if [ "$TRIVY_RAN" = "1" ] && [ "$(( ${TV[CRITICAL]} + ${TV[HIGH]} ))" -gt 0 ]; then
    echo "<details><summary>trivy HIGH/CRITICAL 前 20 筆</summary>"
    echo
    echo '```'
    jq -r '.Results[]? | .Target as $t
           | (.Vulnerabilities[]?, .Secrets[]?, .Misconfigurations[]?)
           | select(.Severity=="HIGH" or .Severity=="CRITICAL")
           | "\(.Severity)\t\($t)\t\(.VulnerabilityID // .RuleID // .ID // .Title)"' "$TRIVY_JSON" | head -20
    echo '```'
    echo
    echo "</details>"
  fi
} >> "$SUMMARY"

cat "$SUMMARY"

########################################
# 門檻判定
########################################
FAIL=0
if [ "$SEM_RAN" = "1" ] && [ "$FAIL_ON_SEMGREP" != "none" ]; then
  case "$FAIL_ON_SEMGREP" in
    ERROR)   n=$SEM_ERROR ;;
    WARNING) n=$((SEM_ERROR + SEM_WARNING)) ;;
    INFO)    n=$((SEM_ERROR + SEM_WARNING + SEM_INFO)) ;;
    *)       n=0; warn "未知的 FAIL_ON_SEMGREP=$FAIL_ON_SEMGREP，略過" ;;
  esac
  if [ "$n" -gt 0 ]; then
    printf '\033[1;31m[FAIL]\033[0m semgrep %s 以上 %d 筆\n' "$FAIL_ON_SEMGREP" "$n" >&2
    FAIL=1
  fi
fi

if [ "$TRIVY_RAN" = "1" ] && [ "$FAIL_ON_TRIVY" != "none" ]; then
  n=0
  IFS=',' read -ra SEVS <<< "$FAIL_ON_TRIVY"
  for s in "${SEVS[@]}"; do
    s="$(echo "$s" | tr '[:lower:]' '[:upper:]' | xargs)"
    n=$(( n + ${TV[$s]:-0} ))
  done
  if [ "$n" -gt 0 ]; then
    printf '\033[1;31m[FAIL]\033[0m trivy %s 共 %d 筆\n' "$FAIL_ON_TRIVY" "$n" >&2
    FAIL=1
  fi
fi

if [ "$FAIL" -eq 0 ]; then
  printf '\033[1;32m[PASS]\033[0m 未達阻擋門檻\n' >&2
fi
log "報告輸出於 $OUT_DIR (semgrep.json/sarif, trivy.json/sarif, summary.md)"
exit "$FAIL"

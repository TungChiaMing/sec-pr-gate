#!/usr/bin/env python3
"""policy.py — sec-pr-gate 的 merge gate 判定（純規則，不需要 LLM）。

輸入：findings JSON（out/new.json 或 head 全量）、可選的 triage.json（D4 產物）。
輸出：out/gate.json + 人看的摘要；exit 1 = 擋 merge，exit 0 = 放行。

規則只有兩條，刻意簡單且可解釋（D6 要評估的就是這個）：
  1. severity >= threshold 的 finding 會擋。
  2. 若 triage 判為 FP 且 confidence >= GATE_FP_MIN_CONF 則豁免。

fail-closed：NEEDS_REVIEW、低信心 FP、沒有 triage 的，一律當 TP 擋。
"""
import argparse
import json
import os
import sys

RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNKNOWN": 2}
FP_MIN_CONF = float(os.environ.get("GATE_FP_MIN_CONF", "0.8"))


def _extract_list(obj, keys=("new", "findings", "items", "results", "verdicts")):
    """接受 list，或 dict 內第一個命中的 list 欄位（相容 D3 / D4 的輸出形狀）。"""
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for k in keys:
            if isinstance(obj.get(k), list):
                return obj[k]
    raise SystemExit("policy: 無法從 JSON 取出 findings 清單，請確認欄位名稱")


def _triage_of(row):
    """D4 的 triage.json 把裁決放在巢狀的 row["triage"]；也接受扁平的形狀。"""
    if isinstance(row.get("triage"), dict):
        return row["triage"]
    if "verdict" in row:
        return row
    return {}


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def sev(f):
    return str(f.get("severity", "UNKNOWN")).upper()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", required=True,
                    help="out/new.json（fail_on=new）或 head 全量 JSON（fail_on=all）")
    ap.add_argument("--triage", default="", help="out/triage.json（可省略；不存在就純規則）")
    ap.add_argument("--threshold", default="HIGH", help="CRITICAL|HIGH|MEDIUM|LOW")
    ap.add_argument("--out", default="out/gate.json")
    a = ap.parse_args()

    findings = _extract_list(load_json(a.findings))

    verdicts = {}
    if a.triage and os.path.exists(a.triage):
        for row in _extract_list(load_json(a.triage)):
            fp = row.get("fingerprint")
            t = _triage_of(row)
            if fp and t.get("verdict"):
                verdicts[fp] = t
        print(f"policy: 載入 {len(verdicts)} 筆 triage 裁決（{a.triage}）")
    else:
        print("policy: 沒有 triage 輸入 —— 純規則模式（所有達門檻的 finding 都會擋）")

    thr = RANK[a.threshold.upper()]
    blocking, exempted, below = [], [], []
    for f in findings:
        v = verdicts.get(f.get("fingerprint"))
        f = dict(f)
        f.pop("raw", None)
        f.pop("triage", None)
        if v:
            f["verdict"] = v.get("verdict")
            f["confidence"] = v.get("confidence")
            f["triage_reason"] = v.get("reason")
        if RANK.get(sev(f), 2) < thr:
            below.append(f)
            continue
        if v and str(v.get("verdict", "")).upper() == "FP" and float(v.get("confidence") or 0) >= FP_MIN_CONF:
            exempted.append(f)
            continue
        blocking.append(f)

    result = {
        "threshold": a.threshold.upper(),
        "fp_min_conf": FP_MIN_CONF,
        "triage_used": bool(verdicts),
        "counts": {"total": len(findings), "blocking": len(blocking),
                   "exempted_fp": len(exempted), "below_threshold": len(below)},
        "blocking": blocking, "exempted_fp": exempted, "below_threshold": below,
        "decision": "BLOCK" if blocking else "PASS",
    }
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)

    print(f"gate: decision={result['decision']} threshold={a.threshold.upper()} "
          f"blocking={len(blocking)} exempted_fp={len(exempted)} below={len(below)}")
    for f in blocking:
        print(f"  BLOCK {sev(f):8} {f.get('tool')}:{f.get('rule_id') or f.get('cve')} "
              f"{f.get('path')}:{f.get('line')}")
    for f in exempted:
        print(f"  EXEMPT{'':2} {sev(f):8} {f.get('rule_id') or f.get('cve')} "
              f"{f.get('path')}:{f.get('line')}  (FP conf={f.get('confidence')})")

    # GitHub Actions 錯誤註記（會在 PR Files changed 顯示）
    if os.environ.get("GITHUB_ACTIONS") == "true":
        for f in blocking:
            print(f"::error file={f.get('path')},line={f.get('line') or 1}::"
                  f"[{sev(f)}] {f.get('tool')} {f.get('rule_id') or f.get('cve')}")
    sys.exit(1 if blocking else 0)


if __name__ == "__main__":
    main()

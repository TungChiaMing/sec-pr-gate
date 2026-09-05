#!/usr/bin/env python3
"""count.py — 把 semgrep.json 與 trivy.json 的 findings 統一列印。

讀 OUT_DIR（預設 /out）底下的報告，不重新掃描。
用法：make count  /  docker run ... sec-pr-gate:latest count
"""
import collections
import json
import os
import sys

OUT_DIR = os.environ.get("OUT_DIR", "/out")
SEM = os.path.join(OUT_DIR, "semgrep.json")
TRI = os.path.join(OUT_DIR, "trivy.json")


def load(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        print(f"[warn] 找不到或為空：{path}（先跑 make sast / make sca / make scan）",
              file=sys.stderr)
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main() -> int:
    sem, tri = load(SEM), load(TRI)
    if sem is None and tri is None:
        return 1

    total = 0

    if sem is not None:
        print("== Semgrep (SAST) ==")
        sev = collections.Counter()
        rules = collections.Counter()
        for r in sem.get("results", []):
            s = r["extra"]["severity"]
            sev[s] += 1
            rules[r["check_id"]] += 1
            print(f'{s:8} {r["path"]}:{r["start"]["line"]:<4} {r["check_id"]}')
        print("by severity:", dict(sev))
        # 同一 file:line 被多條 rule 打中 -> 真實漏洞點數量
        spots = {(r["path"], r["start"]["line"]) for r in sem.get("results", [])}
        print(f"findings: {sum(sev.values())}  unique file:line: {len(spots)}  "
              f"unique rules: {len(rules)}")
        total += sum(sev.values())

    if tri is not None:
        print("\n== Trivy (SCA + secrets + misconfig) ==")
        n = 0
        sev = collections.Counter()
        for res in tri.get("Results", []):
            for v in res.get("Vulnerabilities") or []:
                n += 1
                sev[v["Severity"]] += 1
                print(f'{v["Severity"]:8} {res["Target"]}  '
                      f'{v["PkgName"]}@{v["InstalledVersion"]}  '
                      f'{v["VulnerabilityID"]}  fixed={v.get("FixedVersion", "-")}')
            for s in res.get("Secrets") or []:
                n += 1
                sev[s["Severity"]] += 1
                print(f'{s["Severity"]:8} {res["Target"]}:{s["StartLine"]:<4} '
                      f'SECRET {s["RuleID"]} ({s["Category"]})')
            for m in res.get("Misconfigurations") or []:
                n += 1
                sev[m["Severity"]] += 1
                print(f'{m["Severity"]:8} {res["Target"]}  MISCONF {m["ID"]}  {m["Title"]}')
        print("by severity:", dict(sev))
        print("total trivy findings:", n)
        total += n

    print(f"\n== TOTAL: {total} findings ==")
    return 0


if __name__ == "__main__":
    sys.exit(main())

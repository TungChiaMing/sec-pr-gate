"""Render a Markdown summary of Semgrep + Trivy JSON results (for $GITHUB_STEP_SUMMARY)."""
import collections
import json
import sys

sem_path, tri_path = sys.argv[1], sys.argv[2]
with open(sem_path, encoding="utf-8") as fh:
    sem = json.load(fh)
with open(tri_path, encoding="utf-8") as fh:
    tri = json.load(fh)

print("## sec-pr-gate scan summary\n")

sev = collections.Counter(r["extra"]["severity"] for r in sem["results"])
print(f"### Semgrep (SAST) — {len(sem['results'])} findings  "
      f"(ERROR {sev.get('ERROR', 0)} / WARNING {sev.get('WARNING', 0)} / INFO {sev.get('INFO', 0)})\n")
print("| Severity | Location | Rule |")
print("|---|---|---|")
for r in sorted(sem["results"], key=lambda r: (r["path"], r["start"]["line"])):
    print(f"| {r['extra']['severity']} | `{r['path']}:{r['start']['line']}` | `{r['check_id']}` |")

vulns, secrets = [], []
for res in tri.get("Results", []):
    for v in res.get("Vulnerabilities") or []:
        vulns.append((v["Severity"], res["Target"], f"{v['PkgName']}@{v['InstalledVersion']}",
                      v["VulnerabilityID"], v.get("FixedVersion", "-")))
    for s in res.get("Secrets") or []:
        secrets.append((s["Severity"], f"{res['Target']}:{s['StartLine']}", s["RuleID"], s["Category"]))

print(f"\n### Trivy (SCA) — {len(vulns)} vulnerabilities\n")
print("| Severity | Target | Package | CVE | Fixed in |")
print("|---|---|---|---|---|")
order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
for row in sorted(vulns, key=lambda x: (order.get(x[0], 9), x[2])):
    print("| " + " | ".join(row) + " |")

print(f"\n### Trivy (Secrets) — {len(secrets)} secrets\n")
print("| Severity | Location | Rule | Category |")
print("|---|---|---|---|")
for row in secrets:
    print("| " + " | ".join(f"`{c}`" if i == 1 else c for i, c in enumerate(row)) + " |")

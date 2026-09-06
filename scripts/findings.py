#!/usr/bin/env python3
"""sec-pr-gate findings store: normalize Semgrep + Trivy JSON into one language-agnostic
schema, dedupe by fingerprint, store in SQLite, and diff a PR run against a baseline run.

Usage:
  findings.py ingest --run head  --sha <git sha> out/semgrep.json out/trivy.json
  findings.py ingest --run base  --sha <git sha> out/semgrep.base.json out/trivy.base.json
  findings.py new    --base base --head head --json out/new.json --md >> "$GITHUB_STEP_SUMMARY"
  findings.py show   --run head [--category sast|sca|secret|misconfig]

The tool type is auto-detected from the JSON ("results" key = Semgrep, "SchemaVersion" = Trivy).
Only the standard library is used (json, sqlite3, hashlib, argparse).
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import sys
from collections import Counter, defaultdict

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  label      TEXT PRIMARY KEY,
  git_sha    TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  run_label         TEXT NOT NULL,
  fingerprint       TEXT NOT NULL,
  tool              TEXT NOT NULL,   -- semgrep | trivy
  category          TEXT NOT NULL,   -- sast | sca | secret | misconfig
  rule_id           TEXT NOT NULL,   -- semgrep check_id | trivy RuleID / check ID
  severity          TEXT NOT NULL,   -- CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
  path              TEXT NOT NULL,
  line              INTEGER,
  end_line          INTEGER,
  snippet           TEXT,
  pkg               TEXT,
  installed_version TEXT,
  cve               TEXT,
  fixed_version     TEXT,
  title             TEXT,
  message           TEXT,
  raw               TEXT,            -- original JSON object (for the triage agent)
  PRIMARY KEY (run_label, fingerprint),
  FOREIGN KEY (run_label) REFERENCES runs(label)
);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);
"""

SEMGREP_SEV = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
_WS = re.compile(r"\s+")


def norm_snippet(text: str | None) -> str:
    """Whitespace-insensitive snippet so re-indentation does not create a 'new' finding."""
    return _WS.sub(" ", (text or "")).strip()


def normalize_path(path: str) -> str:
    """Make paths comparable across head (/src) and base (/src/base or a worktree)."""
    p = (path or "").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    # base scans run inside ./base or a worktree; strip that prefix so fingerprints match head
    for prefix in ("base/", "src/"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    return p


# ---------------------------------------------------------------- normalizers
def from_semgrep(doc: dict) -> list[dict]:
    out = []
    for r in doc.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        cwe = meta.get("cwe")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else ""
        # p/secrets rules live under generic.secrets.*; everything else is SAST
        category = "secret" if "generic.secrets" in r["check_id"] else "sast"
        out.append({
            "tool": "semgrep",
            "category": category,
            "rule_id": r["check_id"],
            "severity": SEMGREP_SEV.get(extra.get("severity", ""), "UNKNOWN"),
            "path": normalize_path(r["path"]),
            "line": r["start"]["line"],
            "end_line": r["end"]["line"],
            "snippet": extra.get("lines", ""),
            "pkg": None, "installed_version": None, "cve": None, "fixed_version": None,
            "title": cwe or "",
            "message": extra.get("message", ""),
            "raw": r,
        })
    return out


def from_trivy(doc: dict) -> list[dict]:
    out = []
    for res in doc.get("Results", []) or []:
        target = normalize_path(res.get("Target", ""))
        for v in res.get("Vulnerabilities") or []:
            out.append({
                "tool": "trivy", "category": "sca",
                "rule_id": v["VulnerabilityID"],
                "severity": v.get("Severity", "UNKNOWN"),
                "path": target, "line": None, "end_line": None,
                "snippet": "",
                "pkg": v.get("PkgName"), "installed_version": v.get("InstalledVersion"),
                "cve": v["VulnerabilityID"], "fixed_version": v.get("FixedVersion") or None,
                "title": v.get("Title", ""), "message": v.get("PrimaryURL", ""),
                "raw": v,
            })
        for s in res.get("Secrets") or []:
            out.append({
                "tool": "trivy", "category": "secret",
                "rule_id": s["RuleID"],
                "severity": s.get("Severity", "UNKNOWN"),
                "path": target, "line": s.get("StartLine"), "end_line": s.get("EndLine"),
                "snippet": s.get("Match", ""),          # Trivy masks the secret value itself
                "pkg": None, "installed_version": None, "cve": None, "fixed_version": None,
                "title": s.get("Title", ""), "message": s.get("Category", ""),
                "raw": s,
            })
        for m in res.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            cause = m.get("CauseMetadata") or {}
            out.append({
                "tool": "trivy", "category": "misconfig",
                "rule_id": m.get("AVDID") or m["ID"],
                "severity": m.get("Severity", "UNKNOWN"),
                "path": target, "line": cause.get("StartLine"), "end_line": cause.get("EndLine"),
                "snippet": m.get("Title", ""),          # many Dockerfile checks have no line (e.g. missing USER)
                "pkg": None, "installed_version": None, "cve": None, "fixed_version": None,
                "title": m.get("Title", ""), "message": m.get("Resolution", ""),
                "raw": m,
            })
    return out


def detect_and_normalize(path: str) -> tuple[str, list[dict]]:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if "results" in doc:
        return "semgrep", from_semgrep(doc)
    if "SchemaVersion" in doc:
        return "trivy", from_trivy(doc)
    sys.exit(f"{path}: unknown format (expected Semgrep --json or Trivy --format json)")


# ---------------------------------------------------------------- fingerprint
def assign_fingerprints(records: list[dict]) -> None:
    """fingerprint = sha256(tool|category|rule_id|path|pkg|cve|normalized snippet|ordinal)[:16]

    Line numbers are deliberately NOT part of it: inserting code above a finding must not
    make it look new. 'ordinal' disambiguates identical snippets in the same file."""
    seen: Counter = Counter()
    for r in sorted(records, key=lambda r: (r["path"], r["line"] or 0, r["rule_id"])):
        key = (r["tool"], r["category"], r["rule_id"], r["path"],
               r["pkg"] or "", r["cve"] or "", norm_snippet(r["snippet"]))
        ordinal = seen[key]
        seen[key] += 1
        r["fingerprint"] = hashlib.sha256("|".join([*key, str(ordinal)]).encode()).hexdigest()[:16]


# ---------------------------------------------------------------- db
def connect(db_path: str) -> sqlite3.Connection:
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    return conn


def cmd_ingest(args: argparse.Namespace) -> None:
    conn = connect(args.db)
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    conn.execute("INSERT OR REPLACE INTO runs(label, git_sha, created_at) VALUES (?, ?, ?)",
                 (args.run, args.sha, now))
    conn.execute("DELETE FROM findings WHERE run_label = ?", (args.run,))   # re-ingest is idempotent
    records: list[dict] = []
    for f in args.files:
        tool, recs = detect_and_normalize(f)
        print(f"[ingest] {f}: {tool} -> {len(recs)} raw findings")
        records.extend(recs)
    assign_fingerprints(records)
    inserted = 0
    for r in records:
        cur = conn.execute(
            """INSERT OR IGNORE INTO findings(run_label, fingerprint, tool, category, rule_id, severity, path,
               line, end_line, snippet, pkg, installed_version, cve, fixed_version, title, message, raw)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (args.run, r["fingerprint"], r["tool"], r["category"], r["rule_id"], r["severity"], r["path"],
             r["line"], r["end_line"], r["snippet"], r["pkg"], r["installed_version"], r["cve"],
             r["fixed_version"], r["title"], r["message"], json.dumps(r["raw"], ensure_ascii=False)))
        inserted += cur.rowcount
    conn.commit()
    by_cat = Counter(r["category"] for r in records)
    print(f"[ingest] run={args.run} sha={args.sha or '-'}: {len(records)} raw -> {inserted} unique "
          f"({len(records) - inserted} duplicates dropped) {dict(by_cat)}")


def load_run(conn: sqlite3.Connection, label: str) -> dict[str, dict]:
    if conn.execute("SELECT 1 FROM runs WHERE label = ?", (label,)).fetchone() is None:
        sys.exit(f"run '{label}' not found in db (did you ingest it?)")
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM findings WHERE run_label = ?", (label,)).fetchall()
    return {row["fingerprint"]: dict(row) for row in rows}


def fmt_row(r: dict) -> str:
    loc = f"{r['path']}:{r['line']}" if r["line"] else r["path"]
    what = r["cve"] or r["rule_id"]
    pkg = f"{r['pkg']}@{r['installed_version']}" if r["pkg"] else "-"
    return (f"| {r['category']} | {r['severity']} | `{loc}` | `{what}` | {pkg} | "
            f"{r['fixed_version'] or '-'} | `{r['fingerprint']}` |")


def cmd_new(args: argparse.Namespace) -> None:
    conn = connect(args.db)
    head = load_run(conn, args.head)
    base = load_run(conn, args.base) if args.base else {}
    new = [head[fp] for fp in head if fp not in base]
    fixed = [base[fp] for fp in base if fp not in head]
    unchanged = len(head) - len(new)
    new.sort(key=lambda r: (SEV_ORDER.get(r["severity"], 9), r["path"], r["line"] or 0))
    sha = {row[0]: row[1] for row in conn.execute("SELECT label, git_sha FROM runs")}

    if args.json:
        parent = os.path.dirname(args.json)
        if parent:
            os.makedirs(parent, exist_ok=True)
        payload = {
            "base": {"label": args.base, "git_sha": sha.get(args.base)} if args.base else None,
            "head": {"label": args.head, "git_sha": sha.get(args.head)},
            "counts": {"head_total": len(head), "new": len(new), "fixed": len(fixed), "unchanged": unchanged},
            "new": [{k: v for k, v in r.items() if k != "raw"} for r in new],
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)

    title = (f"vs baseline `{args.base}` ({(sha.get(args.base) or '')[:7]})"
             if args.base else "(no baseline: everything is new)")
    lines = [f"### New findings in `{args.head}` {title}", "",
             f"head total **{len(head)}** · new **{len(new)}** · fixed **{len(fixed)}** · "
             f"unchanged **{unchanged}**", ""]
    if new:
        lines += ["| Category | Severity | Location | Rule / CVE | Package | Fixed in | Fingerprint |",
                  "|---|---|---|---|---|---|---|"] + [fmt_row(r) for r in new]
    else:
        lines.append("_No new findings._")
    text = "\n".join(lines)

    if args.md:
        print(text)
    else:
        print(f"new={len(new)} fixed={len(fixed)} unchanged={unchanged}")
        for r in new:
            loc = f"{r['path']}:{r['line']}" if r["line"] else r["path"]
            print(f"  {r['severity']:8} {r['category']:9} {loc}  {r['cve'] or r['rule_id']}")
    sys.exit(1 if (new and args.fail_on_new) else 0)


def cmd_show(args: argparse.Namespace) -> None:
    conn = connect(args.db)
    rows = load_run(conn, args.run).values()
    if args.category:
        rows = [r for r in rows if r["category"] == args.category]
    by = defaultdict(list)
    for r in rows:
        by[r["category"]].append(r)
    for cat, items in sorted(by.items()):
        print(f"== {cat} ({len(items)})")
        for r in sorted(items, key=lambda r: (SEV_ORDER.get(r["severity"], 9), r["path"], r["line"] or 0)):
            loc = f"{r['path']}:{r['line']}" if r["line"] else r["path"]
            extra = (f"{r['pkg']}@{r['installed_version']} -> {r['fixed_version'] or '?'}"
                     if r["pkg"] else "")
            print(f"  {r['fingerprint']}  {r['severity']:8} {loc:45} {r['cve'] or r['rule_id']} {extra}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default="out/findings.db")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("ingest", help="normalize + store one run")
    s.add_argument("--run", required=True, help="run label, e.g. head / base / main-<sha7>")
    s.add_argument("--sha", default=None)
    s.add_argument("files", nargs="+", help="Semgrep and/or Trivy JSON files")
    s.set_defaults(func=cmd_ingest)

    n = sub.add_parser("new", help="findings present in head but not in base")
    n.add_argument("--head", required=True)
    n.add_argument("--base", default=None)
    n.add_argument("--json", default=None, help="write diff result to this file")
    n.add_argument("--md", action="store_true", help="print Markdown (for $GITHUB_STEP_SUMMARY)")
    n.add_argument("--fail-on-new", action="store_true",
                   help="exit 1 if any new finding (used by Day 5 policy)")
    n.set_defaults(func=cmd_new)

    w = sub.add_parser("show", help="list a run")
    w.add_argument("--run", required=True)
    w.add_argument("--category", choices=["sast", "sca", "secret", "misconfig"])
    w.set_defaults(func=cmd_show)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

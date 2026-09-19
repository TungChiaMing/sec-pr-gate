#!/usr/bin/env python3
"""review_comment.py — 把 gate.json 的 blocking findings 以 PR review 逐行評論回寫。

只用 stdlib。行號必須落在 PR diff 的可評論行上，否則 GitHub 回 422
(Line could not be mapped to a line in the diff)，所以先抓 /pulls/{n}/files 的 patch、
解析 @@ hunk 算出每個檔案在「新檔」側可評論的行號集合；落不進 diff 的寫進 review body。

需要 GITHUB_TOKEN 具 pull-requests: write。
fork 來的 PR 其 GITHUB_TOKEN 是唯讀 -> 這支會失敗，所以上層 step 要 continue-on-error，
gate 的結果不能依賴留言成功。
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
REPO = os.environ["GITHUB_REPOSITORY"]      # caller repo（reusable workflow 內的 github.* 都是 caller 的）
TOKEN = os.environ["GITHUB_TOKEN"]
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
MAX_INLINE = int(os.environ.get("REVIEW_MAX_INLINE", "25"))


def gh(method, path, body=None):
    req = urllib.request.Request(f"{API}{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Authorization", f"Bearer {TOKEN}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read() or b"{}")


def commentable_lines(patch):
    """patch 內在『新檔』側可評論的行號集合（'+' 新增行與 ' ' context 行都算）。"""
    lines, cur = set(), None
    for ln in (patch or "").splitlines():
        m = HUNK.match(ln)
        if m:
            cur = int(m.group(1))
            continue
        if cur is None or ln.startswith("\\"):
            continue
        if ln.startswith("-"):
            continue
        lines.add(cur)
        cur += 1
    return lines


def body_for(f):
    out = (f"**[{f.get('severity')}] {f.get('tool')} `{f.get('rule_id') or f.get('cve')}`**\n\n"
           f"{(f.get('message') or f.get('title') or '')[:400]}\n")
    if f.get("pkg"):
        out += f"\n`{f['pkg']}@{f.get('installed_version')}` → fixed in `{f.get('fixed_version') or '?'}`\n"
    if f.get("verdict"):
        out += f"\ntriage: **{f['verdict']}** ({f.get('confidence')}) — {(f.get('triage_reason') or '')[:200]}\n"
    out += f"\n<sub>fingerprint `{f.get('fingerprint')}`</sub>"
    return out


def main():
    gate_path, pr = sys.argv[1], int(sys.argv[2])
    with open(gate_path, encoding="utf-8") as fh:
        gate = json.load(fh)
    blocking = gate.get("blocking", [])
    if not blocking:
        print("review: 沒有 blocking findings，不留 review")
        return

    files, page = {}, 1
    while True:
        batch = gh("GET", f"/repos/{REPO}/pulls/{pr}/files?per_page=100&page={page}")
        if not batch:
            break
        for f in batch:
            files[f["filename"]] = commentable_lines(f.get("patch"))
        page += 1
    print(f"review: PR #{pr} 有 {len(files)} 個變更檔")

    comments, leftovers, seen = [], [], set()
    for f in blocking:
        path, line = f.get("path"), f.get("line")
        key = (path, line, f.get("rule_id") or f.get("cve"))
        if key in seen:
            continue
        seen.add(key)
        if path in files and isinstance(line, int) and line in files[path] and len(comments) < MAX_INLINE:
            comments.append({"path": path, "line": line, "side": "RIGHT", "body": body_for(f)})
        else:
            leftovers.append(f"- `{path}:{line or '-'}` **[{f.get('severity')}]** "
                             f"`{f.get('rule_id') or f.get('cve')}`")

    c = gate["counts"]
    body = (f"### 🔒 sec-pr-gate: **{gate['decision']}**  (threshold `{gate['threshold']}`)\n\n"
            f"blocking **{c['blocking']}** · exempted_fp **{c['exempted_fp']}** · "
            f"below_threshold **{c['below_threshold']}** · total {c['total']}\n")
    if not gate.get("triage_used"):
        body += "\n_純規則模式：沒有 triage 輸入，所有達門檻的 finding 都會擋。_\n"
    if leftovers:
        body += ("\n<details><summary>不在此 PR diff 內（既有問題或非程式檔），共 "
                 f"{len(leftovers)} 筆</summary>\n\n" + "\n".join(leftovers[:100]) + "\n\n</details>\n")

    payload = {"event": "REQUEST_CHANGES", "body": body, "comments": comments}
    head_sha = os.environ.get("PR_HEAD_SHA")
    if head_sha:
        payload["commit_id"] = head_sha
    try:
        r = gh("POST", f"/repos/{REPO}/pulls/{pr}/reviews", payload)
        print(f"review: id={r.get('id')} state={r.get('state')} "
              f"inline={len(comments)} leftovers={len(leftovers)}")
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:400]
        print(f"review: HTTP {e.code} — {detail}", file=sys.stderr)
        if e.code in (403, 404):
            print("review: token 可能是唯讀（fork PR）或缺 pull-requests: write —— "
                  "gate 結果不受影響", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()

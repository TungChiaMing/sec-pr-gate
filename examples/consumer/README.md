# 接上 sec-pr-gate

任何 repo（任何語言）只要加一個 workflow 檔就能套用同一套掃描與 merge gate。

## 1. 複製 caller

```bash
mkdir -p .github/workflows
cp security.yml .github/workflows/security.yml
# 換掉 <OWNER> 與 <SEC_PR_GATE_SHA>
gh api repos/<OWNER>/sec-pr-gate/commits/main --jq .sha
```

**用 commit SHA，不要用 `@main`。** tag 與 branch 都是可變指標 —— 2026-03 的 Trivy 事件就是
76 個 tag 被一次覆寫。升版由 gate 團隊主導：換 SHA、送 PR、被 review。

## 2. inputs

| input | 預設 | 說明 |
|---|---|---|
| `severity_threshold` | `HIGH` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| `fail_on` | `new` | `new` 只擋這個 PR 新增的；`all` 擋 head 全量 |
| `semgrep_rulesets` | `p/default p/secrets p/owasp-top-ten` | 加語言包就在這裡追加 |
| `trivy_scanners` | `vuln,secret,misconfig` | |
| `target_path` | `.` | monorepo 可指到子目錄 |
| `agent_enabled` | `false` | LLM triage，預設關；關掉時 gate 是純規則 |
| `review_comments` | `true` | PR 逐行留言 |
| `gate_ref` | `""` | 覆寫 gate repo 版本推導（正常不需要） |

**`fail_on: new` 是 legacy repo 能接上的關鍵** —— 既有的幾百筆 finding 不會讓 check 永遠紅，
只有這次 PR 帶進來的才擋。

## 3. 設成 required check

```bash
gh api -X POST repos/<OWNER>/<REPO>/rulesets --input ruleset.json
```

`ruleset.json` 裡的 `context` 必須是 **check 的實名**。reusable workflow 產生的名字是
`<caller job id> / <called job name>`，以本範本就是 `security / gate`。**不要用猜的**：

```bash
gh api repos/<OWNER>/<REPO>/commits/<PR head sha>/check-runs --jq '.check_runs[].name'
```

`bypass_actors` 留空 = 連 admin 也不能繞過。這是刻意的。

> GitHub Free 的 ruleset 只對 **public** repo 生效。gate repo 本身也要 public，
> 不然 consumer 的 `uses:` 拿不到它。

## 4. 權限

caller 給的 `permissions` 是**上限**，reusable workflow 只能維持或縮小，不能提升。
最小組合是 `contents: read` + `pull-requests: write`。

fork 來的 PR 其 `GITHUB_TOKEN` 是唯讀 → review comment 會 403。
留言 step 設了 `continue-on-error`，**gate 的判定不依賴留言成功**。

## 5. demo 檔案

- `route.ts` — 故意含三個漏洞（hardcoded secret / eval RCE / command injection）
- `route.fixed.ts` — 修好的版本，gate 會轉綠

# D2 Runbook — Step 4 / 5 / 6

> Step 1–3 已完成（見下方「已完成狀態」）。這份文件是 Step 4–6 的執行手冊：
> 每一步都有「工作項目 → 指令 → 驗收條件 → 卡關排除」。
> 建立日期 2026-09-05。

---

## 已完成狀態（Step 1–3）

| 項目 | 檔案 | 狀態 |
|---|---|---|
| Step 1 workflow | `.github/workflows/pr-security.yml` | ✅ 10 個 `uses:` 全部 pin 40 位 SHA |
| Step 2 summary | `scripts/summary.py` | ✅ 已用 `reports/*.json` 實跑，輸出 55 行 Markdown |
| Step 3 lint | `make lint-ci` / `scripts/lint.sh` | ✅ actionlint 無輸出、zizmor `No findings`（pedantic 亦通過）；工具已打包進 image |

**六個 action SHA 已於 2026-09-05 用 `git ls-remote` 逐一查證：**

| Action | 版本 | Commit SHA |
|---|---|---|
| actions/checkout | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| actions/setup-python | v7.0.0 | `5fda3b95a4ea91299a34e894583c3862153e4b97` |
| github/codeql-action | v4.37.9 | `cdf488f595d80d6e07e03d4674febd5ab45fa938` ← annotated tag，取 `^{}` |
| actions/upload-artifact | v7.0.1 | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| actions/cache | v6.1.0 | `55cc8345863c7cc4c66a329aec7e433d2d1c52a9` |
| actions/download-artifact | v8.0.1 | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` |

**Trivy checksum 已對 upstream `trivy_0.74.0_checksums.txt` 驗證：**
`2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a`

之後升版自己取 SHA（annotated tag 要看 `^{}` 那一行才是 commit）：

```bash
git ls-remote --tags https://github.com/github/codeql-action 'refs/tags/v4.37.9*'
# a35ac6e6...  refs/tags/v4.37.9        ← tag object，不要用這個
# cdf488f5...  refs/tags/v4.37.9^{}     ← commit SHA，用這個
```

---

## Step 0　前置（約 10 分鐘，必做）

### 0-1　跑 pipeline 自我檢查（不需要在 Mac 上裝任何東西）

actionlint 與 zizmor 已經打包進 image，跟 semgrep / trivy 一樣：

```bash
cd ~/Desktop/sec-pr-gate
make lint-ci              # actionlint + zizmor，跑在 container 裡
make lint-ci-pedantic     # 額外開 zizmor pedantic
```

**驗收**：actionlint `[OK] 無問題`；zizmor `No findings to report. Good job!`；`make lint-ci` exit 0。

**負面測試**（確認 lint 真的在做事）：把任一 `uses:` 的 SHA 改成 `@v7` 再跑一次，應出現 `error[unpinned-uses]`。看完改回來。

image 裡的三個新東西：

| 工具 | 版本 | 安裝方式 |
|---|---|---|
| actionlint | 1.7.10 | 下載 release tarball + **驗 sha256**（amd64 / arm64 各一組），跟 CI 裡裝 trivy 同一套做法 |
| zizmor | 1.30.0 | pip 釘死版本 |
| shellcheck | apt | actionlint 用它檢查 `run:` 區塊裡的 shell |

`make version` 現在會一次印出六個工具的版本。

### 0-2　處理舊的 `sec-pr-gate.yml`（必做決策）

repo 裡還有 D1 留下的 `.github/workflows/sec-pr-gate.yml`，它會和今天的 workflow **同時**在 PR 上跑，而且有三個問題：

- `uses:` 全部沒 pin（`actions/checkout@v4`、`upload-sarif@v3`、`upload-artifact@v4`）→ zizmor 給 **3 筆 high**，`make lint-ci` 會直接失敗
- 沒有 `persist-credentials: false` → zizmor **1 筆 medium**（`artipacked`，token 留在 `.git/config`）
- 它有 `FAIL_ON_SEMGREP=ERROR` 門檻會 **exit 1**，跟 Step 5「今天不擋 merge」的驗收條件直接衝突
- `upload-sarif@v3` 已排定 2026-12 淘汰

**建議做法：把它降級成手動觸發**，保留程式碼供 Day 5 參考，但不再自動跑：

```bash
python3 - <<'PY'
p = '.github/workflows/sec-pr-gate.yml'
s = open(p, encoding='utf-8').read()
s = s.replace("""on:
  pull_request:
    types: [opened, synchronize, reopened]""", """# D2: 降級為手動觸發。自動 PR 掃描改由 pr-security.yml 負責；
# 這個 docker 版 gate 留給 Day 5 的 policy gate 參考。
on:
  workflow_dispatch:""", 1)
open(p, 'w', encoding='utf-8').write(s)
PY
make lint-ci
```

改成 `workflow_dispatch` 之後 zizmor 仍會報那 4 筆（檔案還在），所以 `make lint-ci` 還是紅的。兩個選擇：

- **A（建議）** 直接刪掉：`git rm .github/workflows/sec-pr-gate.yml` —— 功能已被 `pr-security.yml` + Day 5 policy gate 取代，留著只是技術債
- **B** 保留但一起 pin SHA 修乾淨（多花 15 分鐘，但你會多一個「把既有 workflow 補強」的實作例子）

沒處理完 `make lint-ci` 不會綠，Step 4 前請先做完。

### 0-3　確認 secret push protection 的 bypass 仍有效

D1 的 push 被 `app/app.py:15` 那把假 Stripe key 擋下。bypass 的效期是**三小時**，若已過期要重開一次：

```
https://github.com/TungChiaMing/sec-pr-gate/security/secret-scanning/unblock-secret/3IuU7NWL2mFilTvezfLH5Eqhcbu
```

選 **It's used in tests** → **Allow me to push this secret**。

repo 內含完整 key 的檔案只有 `app/app.py`（`README.md` 只有 `sk_live_` 前綴字串，不會觸發），所以放行一次就夠。

---

## Step 4　Push 到 main，跑第一次 baseline（約 15 分鐘）

**工作項目**：把 D2 的 workflow 推上 main，讓它跑一次完整 baseline。
**產出**：一次 success 的 run、Code scanning 兩種 tool 的 alert、兩個 artifact、一張 Job Summary 表。

```bash
cd ~/Desktop/sec-pr-gate
git add -A
git commit -m "D2: PR-gated Semgrep+Trivy workflow (SHA-pinned, SARIF upload, job summary)"
git push -u origin main

gh run watch                 # 選最新的 pr-security run，看三個 job
gh run view --log-failed     # 有紅燈時只印失敗步驟的 log
```

### 驗收條件

1. `gh run list --workflow pr-security --limit 1` → `completed` / `success`
2. repo → **Security → Code scanning** 出現兩種 tool 的 alert：`Semgrep OSS` 與 `Trivy`
3. run 頁面最上方有 Job Summary 表格（三段：Semgrep / Trivy SCA / Trivy Secrets）
4. run 頁面 Artifacts 區有 `semgrep-results` 與 `trivy-results`

```bash
gh run list --workflow pr-security --limit 1
gh run view --json jobs --jq '.jobs[] | "\(.name): \(.conclusion)"'
```

### ⚠️ 數字不會跟本機一樣，這是正常的

| | 本機 `make scan` | CI `pr-security.yml` |
|---|---|---|
| Semgrep ruleset | `p/default p/secrets p/owasp-top-ten` | `p/python p/flask p/secrets` |
| Semgrep 標的 | `app/` | `app/` |
| Trivy 標的 | `app/` | `.`（整個 repo） |
| Trivy scanners | `vuln,secret,misconfig` | `vuln,secret` |

所以本機的 13 筆 Semgrep 在 CI 大概會落在 **8–11 筆**（教材給的預期區間），Trivy 則因為掃整個 repo 可能比本機的 26 筆多。**只要五個 TP 都還在就算對**：stripe key、SQLi、subprocess `shell=True`、SSRF，以及 `requirements.txt` 的 CVE。

不要花時間去湊數字一致——ruleset 不同本來就不該一樣。要對齊的話 Day 3 會做正規化。

### 卡關排除

| 症狀 | 原因 / 處理 |
|---|---|
| `upload-sarif` 回 **403** | 該 job 的 `permissions` 少了 `security-events: write`，或 repo 是 private 且未啟用 Code Scanning（Settings → Code security → Code scanning） |
| Semgrep 卡在下載 `p/python` | runner 連不到 semgrep.dev，`gh run rerun` 重跑即可 |
| Trivy 報 DB download 失敗 | 看 log 是哪個 registry 掛了，在 `trivy fs` 加 `--db-repository ghcr.io/aquasecurity/trivy-db:2` 指定來源 |
| `summary` job 失敗、找不到 `out/semgrep.json` | `download-artifact` 的 `merge-multiple: true` 沒生效，或前面 job 沒產出檔案；先看 `sast` / `sca` 是不是真的綠 |
| push 又被 secret scanning 擋 | 回 Step 0-3 重做 bypass（三小時效期） |

---

## Step 5　開一個「帶新漏洞」的 PR（約 30 分鐘）

**工作項目**：模擬「PR 引入新漏洞」，看 pipeline 在 PR 上的反應。
**產出**：一個開著的 PR、PR 上的三個綠勾、Files changed 的 code scanning 標註、以及「PR 比 main 多出來的 rule 集合」。

在 `app/app.py` 的 `@app.route("/health")` **之前**插入：

```python
@app.route("/debug/eval")
def debug_eval():
    expr = request.args.get("expr", "1+1")
    # intentional TP (added in PR #1): eval() on user input -> RCE
    return str(eval(expr))
```

```bash
git switch -c feat/debug-eval
git add app/app.py
git commit -m "feat: add /debug/eval endpoint"
git push -u origin feat/debug-eval
gh pr create --fill --base main

gh pr checks --watch
gh run download --name semgrep-results --dir out/pr
python3 -c "import json;print(*sorted({r['check_id'] for r in json.load(open('out/pr/semgrep.json'))['results']}),sep='\n')"
```

### 驗收條件

1. PR 頁面 Checks 區有 `SAST (Semgrep)`、`SCA + Secrets (Trivy)`、`Job Summary` 三個**綠勾**（今天不擋，所以是綠的）
2. **Files changed** 分頁在 `eval(expr)` 那行出現 Code scanning 標註
3. 上面那行 python 印出的 rule 清單，比 main 多了：
   - `python.flask.security.injection.eval-injection`
   - `python.lang.security.audit.eval-detected`

第 3 點的「差集」就是 Day 3 要用程式算出來的東西——今天先用肉眼確認它存在。

### 注意事項

- **這個 PR 不要 merge**，Day 3–5 都要用它
- 如果 Step 0-2 選了保留舊 workflow 又沒改觸發條件，你會看到第四個 check 而且**是紅的**（舊 gate 的 `FAIL_ON_SEMGREP=ERROR` 會 exit 1）。那不是這一步做錯，是 Step 0-2 沒做完
- `eval()` 這個 endpoint 是**真的 RCE**，這個 repo 永遠不要部署到任何可連線的地方

---

## Step 6　演練供應鏈防線：故意弄壞 checksum（約 10 分鐘）

**工作項目**：證明「checksum 驗證真的會擋下被替換的 binary」。
**產出**：一次失敗 run + 一次成功 run 的 URL，寫進 `notes.md`。這是面試講 Trivy 供應鏈事件時最有力的證據。

```bash
# 還在 feat/debug-eval 分支
# 把 TRIVY_SHA256 最後一個字元 a 改成 b
sed -i '' 's/be4371a"/be4371b"/' .github/workflows/pr-security.yml
grep TRIVY_SHA256 .github/workflows/pr-security.yml    # 確認結尾是 ...be4371b

git commit -am "chore: break trivy checksum (supply-chain drill)"
git push

gh run watch          # ⚠️ 一定要等這次 run 完全結束
```

### ⚠️ 一定要等第一次 run 結束才推第二次

workflow 有 `concurrency: cancel-in-progress: true`。如果你在第一次 run 還在跑的時候就 push 修正，**第一次 run 會被 cancel 掉，你就拿不到「失敗」這個證據了**。等 `gh run watch` 回到提示字元再繼續。

```bash
# 確認失敗證據
gh run view --log-failed | grep -iE 'FAILED|did NOT match'

# 改回來
sed -i '' 's/be4371b"/be4371a"/' .github/workflows/pr-security.yml
git commit -am "revert: restore correct trivy checksum"
git push
gh run watch
```

### 驗收條件

1. 第一次 run：`sca` job 在 **Install Trivy from release binary + verify sha256** 這一步失敗，log 出現：
   ```
   trivy.tgz: FAILED
   sha256sum: WARNING: 1 computed checksum did NOT match
   ```
2. 失敗發生在 `sudo install` **之前**——被污染的 binary 從來沒被安裝
3. 第二次 run：三個 job 全綠
4. 兩次 run 的 URL 都記進 `notes.md`

```bash
gh run list --workflow pr-security --limit 3 \
  --json databaseId,conclusion,displayTitle,url \
  --jq '.[] | "\(.conclusion)\t\(.displayTitle)\t\(.url)"'
```

---

## D2 完成定義

- [ ] Step 0：`make lint-ci` 全綠（container 內跑，Mac 不用裝東西）、舊 workflow 已處理、secret bypass 有效
- [ ] Step 4：main 的 baseline run success，Code scanning 有 Semgrep + Trivy 兩種 alert
- [ ] Step 5：`feat/debug-eval` PR 開著、三個 check 綠、Files changed 有 code scanning 標註
- [ ] Step 6：一次 checksum 失敗 run + 一次成功 run，URL 已記錄
- [ ] `notes.md` 加上 D2 段落

## `notes.md` 的 D2 段落模板

```markdown
## D2 — GitHub Actions PR gate（2026-09-__）

### Run URLs
- baseline (main): <url>
- PR #1 (feat/debug-eval): <url>
- checksum drill FAIL: <url>
- checksum drill PASS: <url>

### Code Scanning alert 數
- Semgrep OSS: __ 筆（本機 docker 版是 13 筆，ruleset 不同）
- Trivy: __ 筆

### PR #1 相對 main 新增的 rule id
- python.flask.security.injection.eval-injection
- python.lang.security.audit.eval-detected

### 供應鏈防線
- 6 個 action 全 pin 40 位 commit SHA（清單見 docs/day2-runbook.md）
- Trivy binary 自行下載 + sha256 驗證，checksum 寫死在 workflow env
- permissions 頂層 `{}` deny-by-default，逐 job 開最小權限
- checkout 全部 `persist-credentials: false`
- pipeline 本身用 actionlint + zizmor 靜態掃描（`make lint-ci`）
```

## 今天刻意沒做的事

- **不擋 merge**：掃描步驟只負責產生資料，決策留給 Day 5 的 `policy.yml`
- **不做 TP/FP 判斷**：Day 4 的 agent 負責
- **不用 cosign 驗 Trivy 的 `.sigstore.json`**：本週不做，但面試可以提「checksum 只證明 bytes 沒被改，簽章才證明是誰發的」

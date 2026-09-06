# sec-pr-gate — 掃描結果筆記

> 來源：`reports/semgrep.json` / `reports/trivy.json`（掃描日期 2026-09-05）
> 掃描標的：`app/`（刻意含漏洞的 Flask app）
> Semgrep ruleset：`p/default p/secrets p/owasp-top-ten`
> Trivy scanners：`vuln,secret,misconfig`
>
> 用途：Day 4 寫 LLM triage prompt 時，這裡的 rule id 就是 few-shot 的輸入；
> TP / FP 欄位是 ground truth，Day 6 量 precision / recall 也用這份。

---

## 1. Semgrep（SAST）— 13 findings

### 1.1 真陽性 TP（4 個真漏洞 / 11 筆 raw findings）

| 行 | Sev | rule id | 漏洞類型 |
|---|---|---|---|
| 15 | ERROR | `generic.secrets.security.detected-stripe-api-key.detected-stripe-api-key` | Hardcoded secret |
| 28 | WARNING | `python.django.security.injection.sql.sql-injection-using-db-cursor-execute.sql-injection-db-cursor-execute` | SQL injection |
| 31 | WARNING | `python.lang.security.audit.formatted-sql-query.formatted-sql-query` | SQL injection |
| 31 | ERROR | `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query` | SQL injection |
| 31 | ERROR | `python.django.security.injection.tainted-sql-string.tainted-sql-string` | SQL injection |
| 31 | ERROR | `python.flask.security.injection.tainted-sql-string.tainted-sql-string` | SQL injection |
| 40 | ERROR | `python.flask.security.injection.subprocess-injection.subprocess-injection` | Command injection |
| 40 | ERROR | `python.lang.security.dangerous-subprocess-use.dangerous-subprocess-use` | Command injection |
| 40 | ERROR | `python.lang.security.audit.subprocess-shell-true.subprocess-shell-true` | Command injection |
| 46 | ERROR | `python.django.security.injection.ssrf.ssrf-injection-requests.ssrf-injection-requests` | SSRF |
| 48 | ERROR | `python.flask.security.injection.ssrf-requests.ssrf-requests` | SSRF |

**觀察（Day 4 會用到）**

- **重複告警**：line 31 一個 SQL injection 被 4 條 rule 同時打中，line 40 被 3 條。
  真實漏洞數是 5，raw finding 數是 11 → 去重（dedupe by file+line+CWE）是 agent 的第一個明顯價值。
- **框架錯配**：`python.django.*` 與 `python.sqlalchemy.*` 打在一個純 Flask + sqlite3 的檔案上。
  規則本身結論正確（確實是 SQLi / SSRF），但歸因的框架是錯的 → prompt 要教 agent
  「rule id 的框架前綴不可信，要看實際 import 與呼叫」。
- line 28 與 line 31 其實是同一段 `conn.execute(...)`，只是 rule 錨點不同行。

### 1.2 情境型誤報 FP（2 筆）

| 行 | Sev | rule id | 為何是 FP |
|---|---|---|---|
| 61 | WARNING | `python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5` | `cache_key()` 的 md5 用於 cache key，非密碼雜湊、非簽章，無安全語意 |
| 55 | ERROR | `python.flask.security.insecure-deserialization.insecure-deserialization` | `yaml.load(..., Loader=yaml.SafeLoader)` 已用 SafeLoader，無法 RCE；規則只比對 `yaml.load` 函式名 |

> 注意：`random.random()` 當 backoff jitter（line 65）在這組 ruleset 下**沒有**被打中。
> 原本設計的 3 個情境型 FP，實際只出現 2 個。要湊出第三個可加 `--config p/python`。

### 1.3 rule id 快速複製（給 prompt 用）

```
generic.secrets.security.detected-stripe-api-key.detected-stripe-api-key
python.django.security.injection.sql.sql-injection-using-db-cursor-execute.sql-injection-db-cursor-execute
python.lang.security.audit.formatted-sql-query.formatted-sql-query
python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
python.django.security.injection.tainted-sql-string.tainted-sql-string
python.flask.security.injection.tainted-sql-string.tainted-sql-string
python.flask.security.injection.subprocess-injection.subprocess-injection
python.lang.security.dangerous-subprocess-use.dangerous-subprocess-use
python.lang.security.audit.subprocess-shell-true.subprocess-shell-true
python.django.security.injection.ssrf.ssrf-injection-requests.ssrf-injection-requests
python.flask.security.injection.ssrf-requests.ssrf-requests
python.flask.security.insecure-deserialization.insecure-deserialization
python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5
```

---

## 2. Trivy（SCA + Secrets）— 26 findings

### 2.1 Secret（1 筆，CRITICAL）

| 位置 | Rule ID | Category |
|---|---|---|
| `app.py:15` | `stripe-secret-token` | Stripe |

→ 與 Semgrep line 15 是**同一個漏洞**。跨工具去重也是 agent 的工作。

### 2.2 相依套件 CVE（25 筆）

`requirements.txt`，依 severity：

**HIGH（7）**

| 套件 | 版本 | CVE | fixed |
|---|---|---|---|
| Flask | 2.2.2 | CVE-2023-30861 | 2.3.2 / 2.2.5 |
| Werkzeug | 2.2.2 | CVE-2023-25577 | 2.2.3 |
| Werkzeug | 2.2.2 | CVE-2024-34069 | 3.0.3 |
| urllib3 | 1.26.18 | CVE-2025-66418 | 2.6.0 |
| urllib3 | 1.26.18 | CVE-2025-66471 | 2.6.0 |
| urllib3 | 1.26.18 | CVE-2026-21441 | 2.6.3 |
| urllib3 | 1.26.18 | CVE-2026-44431 | 2.7.0 |

**MEDIUM（16）**：Jinja2 ×5（CVE-2024-22195 / 34064 / 56201 / 56326、CVE-2025-27516）、
Werkzeug ×6（CVE-2023-46136、CVE-2024-49766 / 49767、CVE-2025-66221、CVE-2026-21860 / 27199）、
requests ×3（CVE-2024-35195、CVE-2024-47081、CVE-2026-25645）、urllib3 ×2（CVE-2024-37891、CVE-2025-50181）

**LOW（2）**：Flask CVE-2026-27205、Werkzeug CVE-2023-23934

### 2.3 Misconfig（0 筆）

`TRIVY_SCANNERS` 有開 `misconfig`，但 `TARGET=app/` 底下沒有 Dockerfile / K8s / Terraform，
所以 `Detected config files num=0`。這是預期行為 —— 本專案的掃描標的就是 Flask app 本身。
若要順便掃 repo 自己的 Dockerfile / GitHub Actions：`TARGET=$(pwd) make scan`。

### 2.4 reachability 的討論點（Day 5–6）

「有 CVE」≠「你的用法可被利用」。例如：

- **CVE-2023-25577**（Werkzeug multipart DoS）— app 沒有任何 file upload endpoint，
  `request.data` 走的不是 multipart parser → reachability 低。
- **CVE-2023-30861**（Flask session cookie 快取洩漏）— 需要 proxy 快取 + session，
  本 app 沒用 session → 不可達。
- **urllib3 的 redirect / proxy 類 CVE** — `/fetch` 用 `requests.get(url)` 且 URL 由使用者控制，
  **反而是高度可達**，且與 SSRF TP 疊加。

→ 這正是 LLM agent 能加值的地方：把 SCA 的版本比對結果，接上 SAST 的資料流上下文。

---

## 3. 門檻設定與現況

| 變數 | 目前值 | 命中數 |
|---|---|---|
| `FAIL_ON_SEMGREP` | `ERROR` | 10 → FAIL |
| `FAIL_ON_TRIVY` | `HIGH,CRITICAL` | 8 → FAIL |

`make scan` 回傳 exit 1 是**設計行為**（CI 擋 PR 用），不是執行失敗。
要只產報告不擋：`FAIL_ON_SEMGREP=none FAIL_ON_TRIVY=none make scan`，
或用不做門檻判定的 `make sast` / `make sca`。

---

## 4. Baseline 數字（Day 6 對照用）

| 指標 | 值 |
|---|---|
| Semgrep raw findings | 13 |
| Semgrep 去重後的真實漏洞 | 5 |
| Semgrep TP / FP | 11 / 2 |
| Semgrep 原始 precision | 11/13 = 84.6%（以 raw finding 計） |
| 跨工具重複（secret） | 1 組（Semgrep line 15 = Trivy stripe-secret-token） |
| Trivy CVE | 25（HIGH 7 / MEDIUM 16 / LOW 2） |
| Trivy secret | 1 CRITICAL |

---

# D2 — GitHub Actions PR gate（2026-09-05）

## Run URLs

| 用途 | 結果 | URL |
|---|---|---|
| baseline（push main） | success | https://github.com/TungChiaMing/sec-pr-gate/actions/runs/33971312482 |
| PR #1 `feat/debug-eval` | success | https://github.com/TungChiaMing/sec-pr-gate/actions/runs/33972073313 |
| 供應鏈演練 — checksum 壞 | **failure（預期）** | https://github.com/TungChiaMing/sec-pr-gate/actions/runs/33972293976/job/101322826771 |
| 供應鏈演練 — checksum 還原 | success | https://github.com/TungChiaMing/sec-pr-gate/actions/runs/33972819894 |

## Code Scanning alert 數

| Tool | Alerts |
|---|---|
| Semgrep OSS | 9 |
| Trivy | 21 |

⚠️ **SARIF 是子集，JSON 才是完整資料。** Trivy 的 Job Summary 是 37 vuln + 1 secret，但 Code Scanning 只有 21 —— SARIF 只帶 HIGH/CRITICAL 以上，MEDIUM/LOW 沒進 alert。Day 3 正規化要吃 JSON，不要吃 SARIF。

## 兩組 baseline，不可混用

| | 本機 `make scan` | CI `pr-security.yml` |
|---|---|---|
| Semgrep ruleset | `p/default p/secrets p/owasp-top-ten` | `p/python p/flask p/secrets` |
| Semgrep raw findings | 13 | 9 |
| TP / FP | 11 / 2 | 8 / 1 |
| raw precision | 84.6% | 88.9% |
| 真實漏洞點 | 4 | 4 |
| Trivy 標的 | `app/` | `.`（整個 repo） |
| Trivy vuln | 25 | 37 |

CI 少掉的 4 筆 Semgrep：`formatted-sql-query`、`sqlalchemy-execute-raw-query`、django 版 `tainted-sql-string`（都是 line 31 的重複告警），以及 **line 55 的 `insecure-deserialization`** —— `p/python p/flask p/secrets` 沒收錄那條，所以 CI baseline 只剩 md5 一個 FP。

**Day 6 算 precision / recall 時必須標明是哪一組 baseline。**

## 可重現性證明

`app/requirements.txt` 的 25 筆 CVE（HIGH 7 / MEDIUM 16 / LOW 2）在本機 docker 與 CI runner 上**逐筆完全相同**。同一份 pinned lock 檔 → 同一組結果，這就是 SCA 可重現的意義。

## PR #1 新增的 rule id（差集）

```
python.django.security.injection.code.user-eval.user-eval
python.flask.security.injection.user-eval.eval-injection
```

其餘 9 條與 main 完全相同，差集剛好 2 筆、都是 eval 相關。

⚠️ **rule id 會隨版本漂移，不能當穩定 key。** 教材寫的是 `python.flask.security.injection.eval-injection` 與 `python.lang.security.audit.eval-detected`；實際上 flask 那條路徑多了 `.user-eval` 一層，`eval-detected` 根本沒出現、換成 django 版的 `user-eval`。Day 3 正規化的識別鍵要用 `(file, line, CWE/類別)`，rule id 只當附註。

## 三個要帶進 Day 3–5 的觀察

1. **CRITICAL 全在 `testdata/`，`app/` 一個都沒有。** PyYAML 5.1 的 3 個 CRITICAL 來自測試 fixture。如果 gate 用 `FAIL_ON_TRIVY=CRITICAL`，會為了 fixture 擋掉 PR。→ **policy 必須帶路徑維度**，不能只看 severity。`testdata/` 刻意保留不排除，就是要練這個 case。
2. **Code Scanning 自己也會擋。** PR 上除了我們的三個 job，還有 GitHub 從 SARIF 產生的 `Semgrep OSS` / `Trivy` check。`Semgrep OSS` 是**紅的** —— 因為 PR 引入新的 error-severity alert（`eval()` RCE）。所以「今天不擋」只對自己的 pipeline 成立。Day 5 寫 policy gate 時要決定：**自己的 gate 和 Code Scanning 的 check 誰說了算**（Settings → Code security → protection rules 可調觸發等級）。
3. **跨工具重複**：Semgrep `app.py:15` 的 stripe key 與 Trivy 的 `stripe-secret-token` 是同一個漏洞。去重要跨工具做。

## 供應鏈防線（面試講這段）

| 防線 | 做法 | 證據 |
|---|---|---|
| Action 不可變 | 6 個 action 全 pin 40 位 commit SHA，版本號降級成註解 | `docs/day2-runbook.md` 有查證過的 SHA 清單 |
| Token 最小權限 | 頂層 `permissions: {}` deny-by-default，逐 job 只開 `contents: read` + `security-events: write` | zizmor 無 findings |
| Token 不落地 | 所有 checkout `persist-credentials: false` | 舊 workflow 沒設，zizmor 報 `artipacked` |
| 第三方 binary | 不用 `trivy-action`，自行下載 release tarball + `sha256sum -c`，checksum 寫死在 workflow | **實測：改一個字元 → job 在 `sudo install` 之前就 fail** |
| Pipeline 自我掃描 | actionlint + zizmor 打包進 image，`make lint-ci` | 舊 `sec-pr-gate.yml` 被抓出 3 high + 1 medium，已刪除 |

演練的失敗 log（`runs/33972293976`）：

```
sha256sum: WARNING: 1 computed checksum did NOT match
trivy.tgz: FAILED
Error: Process completed with exit code 1.
```

關鍵是**失敗發生在 `sudo install` 之前** —— 被替換的 binary 從來沒有被安裝到 PATH 上。2026-03 的 Trivy 事件裡，寫 `uses: aquasecurity/trivy-action@0.28.0` 的 pipeline 就是少了這一道。

## 今天刻意沒做

- 不擋 merge（Day 5 的 `policy.yml`）
- 不做 TP/FP 判斷（Day 4 的 agent）
- 不用 cosign 驗 Trivy 的 `.sigstore.json`（checksum 只證明 bytes 沒被改，簽章才證明是誰發的）

---

# D3 — Normalize / Fingerprint / Baseline diff（2026-09-06）

## 掃描規模（語言無關，掃整個 repo）

`SEMGREP_RULESETS = p/default p/secrets p/owasp-top-ten` · `TRIVY_SCANNERS = vuln,secret,misconfig`

| | main (base) | feat/debug-eval (head) |
|---|---|---|
| Semgrep raw | 20 | 23 |
| Trivy raw | 74 | 74 |
| **正規化後 unique** | **94** | **97** |

分類：`sast` 18 · `sca` 67 · `secret` 4 · `misconfig` 5（base）

Semgrep 20 筆的分布：`app/app.py` 13、`samples/node-api/server.js` 4、`samples/node-api/Dockerfile` 1、`testdata/vuln_app.py` 2。
**`app/app.py` 仍是 13 筆 —— ruleset 沒被 D3 動過的證據。**

## server.js 的 golden labels（D6 量 precision / recall 用）

| 行 | 埋的東西 | 掃描器結果 | 標記 |
|---|---|---|---|
| 10 | hardcoded stripe key | `detected-stripe-api-key` + Trivy `stripe-secret-token` | **TP，偵測成功** |
| 14 | command injection (`child_process.exec`) | `javascript.lang.security.detect-child-process` (ERROR) | **TP，偵測成功** |
| 19 | eval RCE | `javascript.browser.security.eval-detected` (WARNING) | **TP，偵測成功** |
| 24 | SSRF (`axios.get` 使用者控制 URL) | **無任何規則命中** | **TP，漏報 (FN)** |
| 30 | md5 當 cache key | 無 | 設計為情境型 FP，**未觸發** |
| 35 | `Math.random()` 當 jitter | 無 | 設計為情境型 FP，**未觸發** |
| 38 | `http.createServer` 綁 127.0.0.1 | `problem-based-packs.insecure-transport.js-node.using-http-server` (WARNING) | **非預期的 FP** |

### 三個要帶進 D4 / D6 的結論

1. **跨語言覆蓋率不對等。** 同一個 SSRF 漏洞，Python 版被 `ssrf-requests` 抓到，JS 版**完全沒有規則命中**。這是 false negative，不是誤報 —— D6 的 recall 分母裡就少了這一筆。「加 ruleset 就會變好」是不成立的假設，要量過才知道。
2. **規則的框架歸因不可信，兩種語言都一樣。** eval 那條是 `javascript.**browser**.security.eval-detected`，打在 Node 程式上；D1 則是 `python.**django**.*` 打在 Flask 上。D4 的 prompt 要教 agent：**rule id 的框架前綴只是分類標籤，要看實際 import 與呼叫**。
3. **設計的 FP 沒出現，沒設計的 FP 出現了。** 預期的 md5 / `Math.random()` 兩個情境型誤報在這組 ruleset 下都沒觸發，反而多出一個 `using-http-server`。**FP 的組成是 ruleset 的函數，不是程式碼的函數** —— 所以 golden labels 必須綁定 ruleset 版本才有意義。

## Trivy

- `samples/node-api/package-lock.json`：minimist `CVE-2021-44906` (CRITICAL)、lodash `CVE-2021-23337` (HIGH)、axios `CVE-2021-3749` (HIGH) 都在。
- **axios@0.21.1 一個套件就貢獻 30 筆 CVE**（HIGH 11 / MEDIUM 18 / LOW 1）。這是 SCA 的量級問題最好的例子：一個過期套件就能淹掉整份報告，人工不可能逐筆看。
- misconfig 5 筆：`samples/node-api/Dockerfile` 的 DS-0001 / DS-0002 / DS-0026，**加上 repo 根目錄自己的 `Dockerfile` 的 DS-0001（`FROM aquasec/trivy:latest`）與 DS-0026**。
  - 掃描器被自己的規則掃到。D2 報告裡我寫過「這是還沒補上的一刀」，現在工具自己抓出來了。
  - 根 Dockerfile **沒有** DS-0002，因為有 `USER scanner` —— 這是防線有效的反證。
- secret 4 筆 = 兩個檔案 × 兩個工具。跨工具重複刻意不合併（`tool` 是 fingerprint 的一部分），判斷是不是同一件事是 D4 agent 的工作。

## Baseline diff（本機）

```
make scan && make baseline && make diff
new=3 fixed=0 unchanged=94
  HIGH     sast  app/app.py:73  python.flask.security.injection.user-eval.eval-injection
  MEDIUM   sast  app/app.py:71  python.django.security.injection.code.user-eval.user-eval
  MEDIUM   sast  app/app.py:73  python.lang.security.audit.eval-detected.eval-detected
```

D2 的 CI（`p/python p/flask p/secrets`）對同一個 eval 只有 2 條規則，D3 的語言無關 ruleset 有 3 條。
**判準是「差集全部是 eval 相關、全在 `app/app.py`、`fixed=0`」，不是數字等於 2。**

## fingerprint 不含行號 —— 兩組證據

**(a) 合成測試**：把所有 Semgrep finding 的行號 +5，跟原始版本 diff。

| fingerprint 組成 | 結果 |
|---|---|
| 不含行號（正式版） | `new=0 fixed=0 unchanged=39` |
| 改成含行號（反向對照） | `new=13 fixed=13 unchanged=26` |

**(b) 真環境測試**：在 `app/app.py` 最前面插入 3 行註解後重掃。

```
行號變動但仍判為 unchanged：13 筆
  app/app.py  15 -> 18    28 -> 31    31 -> 34 (×4)
  app/app.py  40 -> 43 (×3)   46 -> 49   48 -> 51   55 -> 58   61 -> 64
new 仍為 3、unchanged 仍為 94
```

`app/app.py` 的每一筆都整齊往下 3 行，**沒有一筆被誤判成新的**。含行號的 fingerprint 在這個情境會產生 13 筆假的 new + 13 筆假的 fixed —— 對 legacy repo 來說，這種 gate 第一天就會被開發者關掉。

註：原本以為 `/debug/eval` 這個 PR 本身就會造成位移，實際查 DB 是 **0 筆**位移 —— 因為插入點在第 70 行，而 `app/app.py` 唯一在它下面的 `/health` 沒有 finding，md5 那筆在第 59–61 行反而在插入點**上面**。所以位移不變性是靠上面兩個測試證明的，不是靠這個 PR。

## Run URLs

| 用途 | 結果 | URL |
|---|---|---|
| main baseline（無 base，全部視為 new） | success · head total **94** | https://github.com/TungChiaMing/sec-pr-gate/actions/runs/34042942425 |
| PR #1（vs base） | success · new **3** / unchanged **94** | https://github.com/TungChiaMing/sec-pr-gate/actions/runs/34044353349 |

CI `counts` = `{"head_total": 97, "new": 3, "fixed": 0, "unchanged": 94}` —— **與本機 `make diff` 逐字相同**，
三筆 new 連行號（71 / 73 / 73）都一致。

PR 上一樣出現 GitHub Code Scanning 自己的 `Semgrep OSS` check 是紅的（新增 error-severity alert），
`pr-security` 的三個 job 全綠。跟 D2 同一個現象，D5 要決定誰說了算。

## fingerprint 跨環境穩定（CI ↔ 本機交叉驗證）

從 main 的 CI Job Summary 抽 8 個 fingerprint 回本機的 `base` run 查詢：**8/8 完全吻合**。

| fingerprint | finding |
|---|---|
| `cf14c260dee3b4c2` | `app/app.py:61` md5 |
| `8661e11ab6441821` | `app/app.py:15` trivy stripe |
| `b8dd72a3be4815ed` | `server.js:10` trivy stripe |
| `716e7b6e29e23bef` | `server.js:14` detect-child-process |
| `ca775a3edfd10766` | `server.js:38` using-http-server |
| `34b2206c63308aa5` | minimist CVE-2021-44906 |
| `bb6f78115727cde4` | 根 `Dockerfile` DS-0001 |
| `7af62459ab89a236` | node-api `Dockerfile` DS-0002 |

兩邊的環境完全不同：**本機是 macOS / arm64 的 Docker、掃描路徑 `/src`；CI 是 GitHub 的 ubuntu / amd64 runner、掃描路徑 `.`**。
`normalize_path()` 把兩者都收斂成 `app/app.py`，所以 fingerprint 一致。

意義：fingerprint 是**跨環境穩定的識別鍵**，不是只在單一機器上自洽。這讓 D5 有兩個選項成立 ——
(a) 把 baseline 結果存成 artifact 跨 run 重用（省掉 base 掃描的 ×2 時間）；
(b) 開發者本機算出的 fingerprint 可以直接對照 CI 的結果做 waiver / 抑制清單。

## 工程決策

- **輸出目錄改為 `out/`**（原 `reports/`），本機與 CI 一致；`reports/` 保留但不再寫入，且已加入掃描排除（gitignored 的檔案若被掃到，本機與 CI 會不一致）。
- **`make scan` 不再做門檻判定**（D3 原則：掃描只產資料），舊行為移到 `make gate`。
- **D3 的工具全部在 image 裡**：`lock` / `baseline` / `diff` / `findings` 都是 entrypoint 子命令，Mac 上不用裝 node / npm / semgrep。
- **baseline 用拋棄式 git worktree**（`/tmp/spg-base`，容器內），deterministic、不依賴歷史 artifact，代價是掃描時間 ×2。`trap cleanup EXIT` 保證中途失敗也會清掉。

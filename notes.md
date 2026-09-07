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

## 補充（D4 發現）：Semgrep CE 的 snippet 也是 "requires login"

D3 寫 fingerprint 時假設 `extra.lines` 是真的程式碼。實際查證：

| 工具 | snippet 相異值數（94 筆 base run） |
|---|---|
| semgrep | **1**（全部是字串 `"requires login"`） |
| trivy | 6 |

也就是說 **Semgrep CE 不只 `extra.fingerprint` 要登入，`extra.lines` 也是**。
後果：對 Semgrep 而言 snippet 這個欄位對 fingerprint **貢獻零熵**，
identity 實際上退化成 `(tool, category, rule_id, path, ordinal)`。

**目前沒有實際影響** —— 查過 base run，沒有任何 `(tool, rule_id, path)` 出現超過一次，
所以 ordinal 全部是 0，不存在碰撞。

**但失效模式是明確的**：如果某個檔案裡同一條規則命中兩次，刪掉第一次會讓第二次的 ordinal 從 1 變 0，
fingerprint 跟著變 → 產生一筆假的 fixed 加一筆假的 new。
Trivy 那邊沒這個問題（`Match` / `Title` 是真的值）。

**沒有立刻修的理由**：改 `norm_snippet` 會讓所有 Semgrep 的 fingerprint 重算，
上面那張「跨環境 8/8」的對照表會全部失效。真正的修法是換一個對 CE 可得的欄位
（例如把 `start.col` + `end.col` 或 rule message 加進 key），留給 D6 一併處理。

D4 的 prompt 已經把這個字串濾掉了 —— `"requires login"` 不是證據，
送給模型只會誤導，讓 agent 自己用 `get_context` 去讀真的程式碼。

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

## 目標

**讓 gate 只對「這個 PR 帶進來的問題」表態。**

D2 結束時 pipeline 已經會掃、會上傳 SARIF、會呈現在 PR 上，但它沒有能力回答一個最基本的問題：
*這 94 筆 finding 裡，哪幾筆是這次改動造成的？* 沒有這個能力，gate 就只能對總數設門檻 ——
而一個有歷史的 repo 第一次接上掃描器就是 300 筆起跳，check 會永遠是紅的，
**開發者的理性反應不是去修那 300 筆，是把 check 關掉。**

所以今天的目標有三層：
1. **可比較** —— 把兩個工具、四種子結構、兩種語言的輸出壓成同一張表
2. **可識別** —— 給每一筆一個穩定的指紋，重新縮排、插入程式碼都不該讓它變成「新的」
3. **可差集** —— head 減 base，只留下這個 PR 新增的

## 今天做了什麼

| 做的事 | 為什麼 |
|---|---|
| 加 `samples/node-api/`（JS + 刻意錯的 Dockerfile） | 驗證整條流水線是**語言無關**的。只有 Python 樣本的話，「工具無關 / 語言無關」是宣稱而不是事實 |
| Semgrep ruleset 換成 `p/default p/secrets p/owasp-top-ten`、Trivy 加 `misconfig` | 同上。換成語言無關的 ruleset 才掃得到 JS 與 Dockerfile |
| 寫 `scripts/findings.py`（normalize → fingerprint → SQLite → diff） | 這是 D4 agent 與 D5 policy 的共同輸入。**只用標準函式庫**，因為 D5 要做成 reusable workflow，consumer repo 不該為了用 gate 多裝東西 |
| workflow 加 base 掃描與 diff job | 讓 CI 也算得出差集，而不只是本機。同時證明本機與 CI 的結果一致 |
| 把 D3 的能力做成 image 的 entrypoint 子命令 | `lock` / `baseline` / `diff` / `findings` 全走 Docker，Mac 上不用裝 node / npm / semgrep |
| `make scan` 拿掉門檻判定，另開 `make gate` | **掃描步驟只負責產生資料，決策放在獨立步驟。**門檻要等 D4 判完 TP/FP、D5 依 policy 決定 |
| 輸出目錄 `reports/` → `out/`，並把 `reports/` 加入掃描排除 | gitignored 的檔案若被本機掃到、CI 掃不到，baseline diff 會對不上 |

## 為什麼是這個順序

先有樣本才知道 ruleset 夠不夠（結果發現 JS 的 SSRF 沒被抓到）；
先有 normalize 才有指紋可算；先有指紋才有差集；
先在本機把差集跑對，才有資格相信 CI 的結果 —— 而 CI 跑出來確實逐字相同。


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


## 問答

### Q1 — fingerprint 為什麼不含行號？那兩個一模一樣的 finding 怎麼辦？

**行號是 PR 最常改動、卻與漏洞本質最無關的東西。** 在檔案上方加一個 import
就讓下面全部位移；含行號的 fingerprint 會把整個檔案的既有 findings 判成新增，
gate 立刻失去意義。

identity 用：`tool + category + rule_id + path + pkg + cve + 正規化 snippet`。
snippet 先壓縮空白，所以**重新縮排、格式化不算變更**。

**兩個一模一樣的 finding 用 `ordinal` 區分** —— 同一 key 出現第 N 次就把 N 放進雜湊。
所以同一個檔案裡兩段一模一樣的 `eval(expr)` 是兩筆，不會互相吞掉。
（註：目前這個 repo 沒有觸發到 ordinal 的實例 —— `app/app.py:31` 那 4 筆是 4 條**不同**的 rule_id，
`testdata/vuln_app.py:8` 與 `app/app.py:40` 雖同一條規則但 path 不同。機制在，只是還沒被用到。）

**已知代價：搬檔案會產生一新一舊。** `path` 是 identity 的一部分，所以 `git mv` 一個檔案，
舊 path 的 findings 全變 fixed、新 path 的全變 new。可以再接一層 git rename detection 對一次，
本週不做 —— 這是明確的已知限制，不是沒想到。

**為什麼不用現成的：** Semgrep CE 的 JSON 有 `extra.fingerprint` 欄位，但值是字串
`"requires login"`（1.176.1 實測）；GitHub SARIF 的 `partialFingerprints` 只在同一個工具內有意義。
**跨工具的 identity 一定要自己定義。**

實測證據見上面「fingerprint 不含行號 —— 兩組證據」與「跨環境穩定 8/8」兩節。

---

### Q2 — 同一個 run 掃兩次 vs. 存 baseline artifact，為什麼選前者？

三個理由：

1. **Deterministic** —— base 與 head 用**同一版工具、同一份 rules、同一份 Trivy DB** 掃。
   diff 出來的差異只可能來自 code。存 artifact 的話，base 是幾天前用舊版 ruleset 掃的，
   ruleset 更新就會讓一堆舊 finding 憑空變成「新增」（D2 已經證明 rule id 會漂移）。
2. **零狀態** —— 不需要先在 main 跑過一次。consumer repo 接上的**第一個 PR 就能用**。
   這對 D5 的 reusable workflow 是硬需求，不是加分項。
3. **簡單** —— 不用處理 artifact retention 過期、跨 run 下載的 token 權限、
   以及「找不到 baseline 時該怎麼辦」的 fallback 分支。

**代價是 CI 時間 ×2。** 實測這個 repo：PR run 的 `sast` 46 秒、`sca` 32 秒（都含 base 掃描），
還在可接受範圍。repo 大到分鐘級時再換成 artifact 或 Semgrep 的 `--baseline-commit` 做增量。

值得記的是：**今天證明了 fingerprint 跨環境穩定（8/8），artifact 方案的技術前提已經成立** ——
存下來的指紋在另一台 runner 上仍然對得起來。所以這個決定隨時可以翻案，
翻案的門檻不是「能不能做」而是「掃描時間值不值得換那些複雜度」。

---

### Q3 — secret 被兩個工具抓到為什麼不合併？severity 統一後資訊不會丟嗎？

**不合併，是因為「這兩筆是不是同一件事」本身就是需要判斷的事。**
`tool` 是指紋的一部分，所以兩把 key × 兩個工具 = 4 筆 secret。

兩個工具的 rule_id、信心、mask 方式都不同。最直接的證據是 **severity 不一樣**：

| 檔案 | 工具 | rule_id | severity |
|---|---|---|---|
| `app/app.py:15` | Semgrep | `generic.secrets...detected-stripe-api-key` | HIGH |
| `app/app.py:15` | Trivy | `stripe-secret-token` | CRITICAL |

機械式合併必須決定「保留誰的 severity」，而那個決定沒有正確答案 ——
它取決於你更信任哪個工具在這類問題上的判斷。在 normalize 層做這種判斷是越界。

而且**不合併反而是更強的訊號**：D4 的 agent 會看到同一個 `path:line` 有兩個獨立工具的兩筆記錄，
那比一筆合併過的記錄更值得相信。判斷留給看得到上下文、而且能說明理由的那一層。

**severity 統一不會丟資訊，因為統一的是「決策用的欄位」，不是資料本身。**
四級（CRITICAL / HIGH / MEDIUM / LOW）存在的目的只有一個：讓 D5 的 policy 能用單一門檻寫完
（例如「HIGH 以上、且被 agent 判為 TP 的，擋 merge」）。
`raw` 欄位保留了完整的原始 JSON 物件 —— Semgrep 的 confidence / likelihood / CWE、
Trivy 的 CVSS 分數與 PrimaryURL 全都在，agent 與報表隨時取得到。

同一工具內的重複也是同樣的立場：`app/app.py:31` 一段 SQL 拼接被 **4 條 Semgrep 規則**命中、
`:40` 被 3 條。這些是同一個漏洞，但 rule_id 不同、建議的修法也不同。
去重需要「這幾筆講的是不是同一件事」的推理 —— 那是 D4 的工作，機械規則做不到。

---

# D4 — LLM Triage Agent（2026-09-07）

## 目標

**讓「這筆 finding 在這個上下文可不可被利用」有機器可讀的答案。**

D3 交出 95 筆正規化後的 findings，但掃描器判的是**模式**不是**風險**：`hashlib.md5` 拿來做 cache key 還是簽章都會被抓、`lodash@4.17.20` 有沒有被 require 都是 HIGH。企業裡 SAST finding 有一半以上最後被標成 FP 或 won't fix，而 triage 是 AppSec 團隊最貴的人力。

D4 要產出的是**帶理由的結構化 verdict**（TP / FP / NEEDS_REVIEW + confidence + reason + suggested_fix），讓 D5 的 policy 只認欄位、不用 parse 自由文字。

## 做了什麼 / 為什麼

| 做的事 | 為什麼 |
|---|---|
| tool-use loop（get_context / read_file / search_repo / osv_lookup / submit_verdict） | 讓模型自己決定要看什麼 —— 不隨 repo 大小爆掉、每個判斷對應到讀過的證據 |
| `Repo.safe()` path jail + 只走 `git ls-files` | 工具是唯讀、關在 repo 裡、拒絕 `.git` / `out` / `node_modules` / `.env` |
| 工具回傳一律包在 `<file>` / `<search>` / `<osv>` 標籤，system prompt 明說是 UNTRUSTED DATA | OWASP LLM01 (prompt injection) 與 LLM06 (excessive agency) 的最小防線 |
| `MAX_TURNS=8` + `MAX_TOOL_CALLS=6` | 預算用完就要求立即裁決；沒裁決一律 NEEDS_REVIEW |
| verdict 以 D3 的 fingerprint 為 PRIMARY KEY | 重跑免費 —— PR 每 push 一次只有真正新增的 finding 花 token |
| 兩張表 `LANG_BY_EXT` / `ECOSYSTEM_BY_FILE` | 語言無關靠查表不靠模型猜；加新語言只要加一行，prompt 一個字都不用改 |

## 重大偏離教材：改用本機 Ollama

**決定**：不用 Anthropic API（不想開 API key 計費），改打本機 `ollama` + `gemma3:4b`。

**問題**：`gemma3` 在 Ollama 上**沒有 `tools` capability**（`/api/show` 實測回 `["completion", "vision"]`，官方頁面也只列 text + vision）。tool-use loop 對它不能用。

**做法**：provider 抽象 + 自動偵測，兩種模式：

| | tool 模式 | prefetch 模式（gemma3 走這條） |
|---|---|---|
| 誰決定看什麼 | 模型 | **程式** |
| 抓的證據 | 模型自己挑 | 有行號就 `get_context` ±25 行；`sca` 就 `osv_lookup` + `search_repo` 查 import |
| 結構化輸出機制 | Anthropic `strict: true` tool | Ollama `format: <json schema>` |
| 呼叫次數 | 多輪 | 一次 |

**代價說清楚**：丟掉的正是「agent 自己決定看什麼」這個能力 —— 也就是選 tool use 而非塞 prompt 的**全部理由**。prefetch 讀的量是固定的。這個代價在結果裡有具體證據（見下面失效模式 3）。

`MAX_TOOL_CALLS` 這個 budget 機制在 ollama fallback 下**完全沒被測到**，`tool_calls` 全部是 0。

## 結果：整個 head run（95 筆）

```
provider=ollama model=gemma3:4b
TP 91 · FP 4 · NEEDS_REVIEW 0
cost $0 · input 117,444 tok · output 17,345 tok（平均 1236/183 每筆）
tool_calls: 全部 0（prefetch 模式）
```

| verdict | sast | sca | secret | misconfig |
|---|---|---|---|---|
| TP | 18 | 66 | 4 | 3 |
| FP | 1 | 1 | 0 | 2 |

### 最重要的數字：過濾率 4.2%

D4 存在的理由是「減少人要看的量」。**95 筆判完剩 91 筆要看。** 在這個配置下，D4 這一層幾乎沒有產生價值。

**`NEEDS_REVIEW = 0` 更關鍵** —— 模型從來沒有說過一次「我判斷不了」。不是每次都有把握，是**沒有表達不確定的能力**。

## 判對的 4 筆

| finding | 判定 | 意義 |
|---|---|---|
| `app/app.py:61` md5 cache key | FP | D1 埋的情境型誤報，抓到了 |
| 根 `Dockerfile` DS-0026 | FP | 正確指出「沒有 HEALTHCHECK 是可用性問題，不是安全弱點」 |
| `samples/node-api/Dockerfile` DS-0026 | FP | 同上 |
| `testdata/requirements.txt` flask CVE-2026-27205 | FP | 用「search 找不到 flask」推出不可達 —— **證明它做得到 reachability 推論** |

## 五種失效模式（每一種都可量化，D6 用）

**1. 同樣的證據、相反的結論。**
`testdata/requirements.txt` 的 `requests` CVE 有 5 筆，reason **全部**明寫「search tool confirms that `requests` is not imported into the codebase」，然後 verdict 全給 **TP**。同一份 evidence，flask 那筆給 FP。
→ **不是知識問題，是一致性問題。**

**2. 否定式推論不會，肯定式會。**
`axios` 那筆正確說「axios is imported in server.js」→ TP ✅。
`minimist@1.2.5` CVE-2021-44906（宣告在 package.json 但**沒有任何** `require`）→ **TP** ❌。
→ 「找得到 X」它會用，「找不到 X 所以不可達」它不會用。

**3. 判了視窗裡的別的漏洞。**
`server.js:38` 的 `using-http-server`（本機 127.0.0.1 的 http server，應為 FP）→ TP，
而 reason 講的是 **`fetchUrl` / `axios.get` / SSRF** —— 那是 **line 24** 的東西。
prefetch 給的是 ±25 行的視窗（涵蓋 13–63 行），模型抓了視窗裡另一個更像漏洞的東西來判。
→ **這是 prefetch 模式的結構性缺陷**：tool 模式會去要它需要的那一行，prefetch 給的是一個邀請它漂移的視窗。
→ 諷刺的是它指出的 SSRF 正是 D3 記錄 Semgrep **漏報**的那一筆。它找到了掃描器沒找到的漏洞，卻標錯了被問的那一筆。

**4. 理由自相矛盾。**
`scripts/triage_agent.py:153`（我們自己的 agent 程式碼）→ TP，但 reason 裡寫著
「The B310 warning is a false positive, **as the host is fixed**」。
還把 `json.dumps([cve, pkg, ecosystem, version])`（那是 **cache key**）誤認成 URL 的組成。

**5. confidence 幾乎不帶資訊。**
```
1.0 × 78 · 0.95 × 6 · 0.9 × 1 · 95.0 × 10
```
`eval-detected` 這種 Semgrep metadata 自己標 `confidence: LOW` 的規則，模型照樣給 1.0。
→ **D5 的 policy 不能用 `confidence >= 0.8` 當門檻，它會通過所有東西。**

## 兩個實作 bug（都修了）

**(a) `_http_json` 的 timeout 寫死 15 秒。**
它原本是為 OSV 寫的（快、外部 API、15 秒合理），被本地 LLM 重用時假設不成立 —— 4B 第一次呼叫要先載權重。
`_ollama()` 宣告了 `timeout` 參數卻沒傳下去。
→ 同一個函式在兩種呼叫情境下的合理 timeout 差 40 倍。**重用時沒重新檢視預設值**，兩邊分開看都對，code review 很難抓。

**(b) 結構化輸出沒擋住超出範圍的值。**
schema 寫 `"description": "0.0-1.0"` 但**沒寫 `minimum` / `maximum`**，
Ollama 的 `format=<schema>` 保證了「型別是 number」，**沒保證範圍** → 10/95 筆回 `95.0`（當成百分比）。

→ 修正：schema 補 `minimum: 0, maximum: 1`，程式端加百分比換算與 clamp。
→ **結論要改寫**：不是「兩種 provider、同一個保證」，而是 **「結構化輸出保證的是形狀，不是語意」** —— 程式端仍然必須驗。

## Golden labels v1（D6 用）

以下是我的標註與 gemma3:4b 的分歧點，這是第一版 ground truth：

| finding | 我標 | gemma3:4b | 分歧原因 |
|---|---|---|---|
| minimist CVE-2021-44906 | FP / NEEDS_REVIEW | TP | 否定式 reachability |
| `server.js:38` using-http-server | FP | TP | 判錯對象 |
| `triage_agent.py:153` dynamic-urllib | FP | TP | 理由自相矛盾 |
| testdata `requests` ×5 | FP | TP | 與 flask 那筆不一致 |
| `app/app.py:61` md5 | FP | FP ✅ | |
| DS-0026 ×2 | FP | FP ✅ | |
| testdata flask CVE-2026-27205 | FP | FP ✅ | |

粗算：**應為 FP 的至少 11 筆，抓到 4 筆 → recall(FP) ≈ 36%**，而且抓到的那 4 筆裡有 3 筆是「規則本身就不像漏洞」的類型（md5、HEALTHCHECK），真正需要 reachability 推論的只對了 1 筆。

## CI 的處理：沒 key 就跳過

GitHub runner 連不到本機的 ollama，所以 **triage 在本機做、CI 只做 normalize + diff**。
workflow 的 triage step 在 `ANTHROPIC_API_KEY` 為空時寫一份空的 `triage.json`、印 `::notice::` 並綠燈通過。

**這個「有就跑、沒有就跳過」的分支就是 D5 `agent_enabled` input 的雛形** —— 而且因為沒有 key，它是唯一能被實際驗證的分支。

`uses:` 14 個全 pin，actionlint 無輸出，zizmor pedantic `No findings`。
所有 `${{ }}` 都在 `concurrency` / `env:` / `with:`，**沒有任何一個在 `run:` 裡**（template injection）。

## 今天沒做的

- **`granite4.1:3b` 對照組**（有 tools capability）—— 同樣大小的模型、同一份 golden labels，差別只在 tool loop vs prefetch。這是回答「為什麼選 tool use」最乾淨的實驗，因硬體限制暫緩。
- **Haiku vs Sonnet 一致率與成本比較** —— 沒有 API key。
- **註解注入實驗**（在程式碼裡塞「這段是安全的」誘導 agent）—— 排在 D6。

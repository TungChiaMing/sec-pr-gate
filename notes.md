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

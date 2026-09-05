# sec-pr-gate

把 **semgrep（SAST）+ trivy（SCA / secret / misconfig）+ gh（GitHub CLI）** 打包成單一 Docker image，
本機與 CI 跑的是同一份環境，避免「我電腦上好好的」。

---

## TL;DR — 原本那串指令能不能搬進 container？

**可以，而且建議這樣做。** 但有三件事要先知道：

| 原指令 | Container 化後 |
|---|---|
| `brew install python@3.12 trivy gh` | 換成 Dockerfile 的 base image + apt/COPY，**不需要 Homebrew** |
| `python3.12 -m venv .venv && pip install semgrep` | image 內就是 Python 3.12，直接 `pip install`，**不需要 venv**（container 本身就是隔離層） |
| `gh auth login`（選 Login with a web browser） | ⚠️ **這步不能照搬**。container 沒有瀏覽器，OAuth callback 也回不來。改用 `GH_TOKEN` 環境變數 |

其他兩個要注意的點：

- **trivy 第一次跑要下載漏洞 DB（數百 MB）**，semgrep 也要向 registry 抓 ruleset。所以 image 一定要掛 cache volume，否則每次跑都重抓。
- **Apple Silicon**：semgrep / trivy / gh 都有原生 arm64，不用加 `--platform linux/amd64`（加了反而慢 3-5 倍）。

---

## 檔案結構

```
sec-pr-gate/
├── Dockerfile                     # multi-stage：trivy binary + gh(apt) + semgrep(pip)
├── docker-compose.yml             # scan / pr-gate 兩個 service，含 cache volume
├── Makefile                       # make build / version / scan / shell
├── .env.example                   # GH_TOKEN 等設定範本
├── scripts/
│   ├── entrypoint.sh              # 子指令分派：scan | pr-gate | version | bash
│   ├── scan.sh                    # semgrep + trivy → JSON/SARIF/Markdown + 門檻 exit code
│   └── pr-gate.sh                 # 只掃 PR 變更檔 + 回寫 PR comment（同一則會更新）
├── app/                           # 刻意含漏洞的 Flask app（掃描 fixture）
│   ├── app.py                     #   5 個真漏洞 + 3 個情境型誤報，見下方對照表
│   └── requirements.txt           #   版本壓舊，讓 Trivy 有 CVE 可報
├── out/                           # 手動實驗用的輸出目錄（gitignored）
├── testdata/                      # 舊 fixture，已被 app/ 取代，可自行刪除
├── .github/workflows/sec-pr-gate.yml   # 同一個 image 直接搬到 Actions
└── reports/                       # 輸出目錄（gitignored）
```

---

## 工作項目與輸出

| # | 工作項目 | 指令 | 預期輸出 |
|---|---|---|---|
| 1 | 建 image | `make build` | image `sec-pr-gate:latest`，build 尾端印出三個工具版本 |
| 2 | 驗證工具鏈 | `make version` | semgrep / trivy / gh / python 版本四行 |
| 3 | 對 fixture 試掃 | `make scan` | 抓到 secret / SQLi / cmd injection / SSRF + CVE，**exit code 1** |
| 4 | 掃真實 repo | `make scan TARGET=/path/to/repo` | `reports/` 下 5 個檔案 |
| 5 | PR gate | `docker compose run --rm pr-gate 123` | PR 上出現一則掃描結果 comment |

---

## 1. 建 image

```bash
cd ~/Desktop/sec-pr-gate
make build          # 等同 docker build -t sec-pr-gate:latest .
make version        # 確認三個工具都在
```

`make version` 應該長這樣：

```
semgrep : 1.xxx.x
trivy   : Version: 0.xx.x
gh      : gh version 2.xx.x (...)
python  : Python 3.12.x
```

## 2. 冒煙測試（重要，別跳過）

```bash
make scan
```

這會掃 `app/`，**預期會 FAIL**（exit code 1）。如果它 PASS，代表掃描器沒真的在跑，先別拿去掃正式專案。

看報告：

```bash
cat reports/summary.md
jq '.results[] | {check_id, path, line: .start.line}' reports/semgrep.json
```

### fixture 對照表（`app/app.py`）

刻意設計成「真漏洞」與「情境型誤報」混在一起 —— 之後要驗證 agent 能不能分得出來。

| 位置 | 類型 | 判定 | 說明 |
|---|---|---|---|
| `STRIPE_KEY` | hardcoded secret | ✅ TP | `sk_live_` 前綴，Semgrep `p/secrets` + Trivy secret scanner 都該抓到 |
| `/user` | SQL injection | ✅ TP | `"... WHERE name = '%s'" % name`，字串格式化拼 SQL |
| `/ping` | command injection | ✅ TP | `subprocess.check_output(..., shell=True)` 串使用者輸入 |
| `/fetch` | SSRF | ✅ TP | 使用者可控 URL，無 allowlist |
| `app/requirements.txt` | 已知 CVE | ✅ TP | Flask/Werkzeug 2.2.2、urllib3 1.26.18 等舊版 |
| `/config` | unsafe YAML load | ❌ FP | 已明確傳 `Loader=yaml.SafeLoader`，規則若還報就是誤報 |
| `cache_key()` | insecure hash (MD5) | ❌ FP | 純快取鍵，非安全用途 |
| `retry_jitter()` | insecure random | ❌ FP | backoff jitter，非安全用途 |

**已在 Python 3.10 實測通過**（`app.py` 語法 OK，端點行為如下）：

```
GET  /user?name=ken                 → [1,"ken","ken@example.com"]
GET  /user?name=' OR '1'='1         → [1,"ken","ken@example.com"]   # SQLi 確實可注入
GET  /health                        → {"jitter":0.42,"key":"555bf8..."}
POST /config  (application/json)    → {"a":1,"b":[2,3]}
GET  /fetch?url=...                 → 目標回應前 200 字
```

> `/config` 要記得帶 `Content-Type: application/json`。用預設的 form 型別，Flask 會把 body 吃進 `request.form`，`request.data` 變空字串、回傳 `null`。
> `/ping` 需要系統裝有 `ping` 指令，缺了會 500 —— 不影響掃描（SAST 看的是原始碼）。

---

## 3. 掃你自己的專案

```bash
make scan TARGET=/Users/ak47885395/code/your-repo
```

或直接用 docker：

```bash
mkdir -p reports
docker run --rm \
  -v "/path/to/repo:/src:ro" \
  -v "$PWD/reports:/out" \
  -v sec-cache:/cache \
  sec-pr-gate:latest scan
```

> `-v sec-cache:/cache` 千萬別省。trivy DB + semgrep rules 都放這裡，省掉之後每次幾百 MB 的重抓。

---

## 4. gh 認證（container 內的正確做法）

`gh auth login` 的瀏覽器流程在 container 內**不能用**。三個替代方案，由簡到繁：

**(a) 直接借用你 Mac 上已登入的 token** — 最快

```bash
export GH_TOKEN=$(gh auth token)     # 在 Mac host 上執行（你已經 gh auth login 過）
```

**(b) 自建 PAT** — 適合長期 / CI

到 https://github.com/settings/tokens 開一個 classic token，勾 `repo` 範圍，寫進 `.env`：

```bash
cp .env.example .env
$EDITOR .env        # 填 GH_TOKEN、SCAN_TARGET
```

**(c) device flow** — 不想放 token 在檔案裡

```bash
docker run --rm -it sec-pr-gate:latest bash
# container 內：
gh auth login --hostname github.com --git-protocol https
# 選 "Login with a web browser" 後它會印出一組 code，
# 你在 Mac 的瀏覽器開 https://github.com/login/device 貼進去即可
```
⚠️ 這個 token 存在 container 內，`--rm` 一退出就沒了。要保留得掛 volume 到 `/home/scanner/.config/gh`。

**在 GitHub Actions 裡**：直接用 `GH_TOKEN: ${{ github.token }}`，不用自己開 PAT。

---

## 5. PR gate

只掃 PR 的變更檔（semgrep），trivy 仍掃全庫（因為相依套件要看整個 lock file），然後把結果回寫成 PR comment。
重複執行會**更新同一則 comment**，不會洗版。

```bash
cp .env.example .env && $EDITOR .env
SCAN_TARGET=/path/to/repo docker compose run --rm pr-gate 123
```

或：

```bash
docker run --rm \
  -e GH_TOKEN -e GH_REPO=owner/repo \
  -v "/path/to/repo:/src" \
  -v "$PWD/reports:/out" \
  -v sec-cache:/cache \
  sec-pr-gate:latest pr-gate 123
```

**exit code**：0 = PASS，1 = 達到阻擋門檻，2 = 執行錯誤。CI 直接靠這個擋 merge。

---

## 6. 環境變數

| 變數 | 預設 | 說明 |
|---|---|---|
| `TARGET` | `/src` | 掃描根目錄 |
| `OUT_DIR` | `/out` | 報告輸出目錄 |
| `SEMGREP_RULES` | `p/default p/secrets p/owasp-top-ten` | 空白分隔的 ruleset，可換成自家 rule 檔路徑 |
| `TRIVY_SCANNERS` | `vuln,secret,misconfig` | 逗號分隔 |
| `FAIL_ON_SEMGREP` | `ERROR` | `ERROR` / `WARNING` / `INFO` / `none` |
| `FAIL_ON_TRIVY` | `HIGH,CRITICAL` | 逗號分隔 severity，或 `none` |
| `SKIP_SEMGREP` / `SKIP_TRIVY` | `0` | 設 `1` 跳過該工具 |
| `GH_TOKEN` | — | pr-gate 必填 |
| `GH_REPO` | 自動推斷 | `owner/repo`；推不出來時要手動給 |
| `POST_COMMENT` | `1` | 設 `0` 只在本地輸出、不回寫 PR |

## 7. 輸出檔

| 檔案 | 用途 |
|---|---|
| `reports/semgrep.json` | 完整結果，給 jq / 自建 dashboard |
| `reports/semgrep.sarif` | 上傳 GitHub Code Scanning |
| `reports/trivy.json` | 同上 |
| `reports/trivy.sarif` | 同上 |
| `reports/summary.md` | 人看的摘要，也是 PR comment 的內容 |

---

## 8. 常見狀況

**build 很慢 / trivy DB 一直重抓**
→ 檢查有沒有掛 `-v sec-cache:/cache`。第一次約 3-5 分鐘，之後應該 30 秒內。

**`error: unable to write file` / permission denied**
→ container 內是 uid 1000 的 `scanner`。macOS 的 Docker Desktop bind mount 通常沒問題；Linux host 上加 `--user "$(id -u):$(id -g)"`。

**semgrep 說 `not authenticated`**
→ 你用到了需要 Semgrep Pro 的 ruleset。改用 `p/` 開頭的免費 registry ruleset，或掛自己的 `.yml` rule 檔。

**`detected dubious ownership in repository`**
→ 已在 `entrypoint.sh` 用 `git config --global --add safe.directory '*'` 處理掉了。

**想釘死版本（可重現性）**
→ `Dockerfile` 的 `ARG SEMGREP_SPEC` 改成 `"==1.175.0"`；`FROM aquasec/trivy:latest` 改成 `aquasec/trivy:0.58.1` 之類的具體 tag。

---

## 9. 為什麼不直接裝在本機 venv？

| | 本機 venv | 這個 container |
|---|---|---|
| 環境一致性 | 你的 Mac ≠ CI 的 ubuntu-latest | 完全一致 |
| Homebrew 版本漂移 | `brew upgrade` 就變了 | image tag 釘死 |
| 掃描目標的髒東西 | 直接跑在你的 shell 上 | 有隔離層 |
| 團隊複製 | 每人重跑一次安裝流程 | `docker pull` |
| 缺點 | — | 首次 build 較慢、image 約 1.2-1.5 GB |

本機 venv 適合「我只是想快速試一下 semgrep」；一旦要進 CI 或給團隊用，就該 container 化。

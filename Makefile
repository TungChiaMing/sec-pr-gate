IMAGE            ?= sec-pr-gate:latest

# D5 會把這三個變成 reusable workflow 的 inputs
SEMGREP_RULESETS ?= p/default p/secrets p/owasp-top-ten
TRIVY_SCANNERS   ?= vuln,secret,misconfig
BASE_REF         ?= main
TRIAGE_JSON      ?= $(OUT_DIR)/triage.json
PROVIDER         ?= ollama
MODEL            ?=

# 掃描標的（repo 根目錄）與報告輸出目錄，都在 container 內的路徑
TARGET  ?= /src
OUT_DIR ?= /src/out

# D5 policy gate 的門檻
SEVERITY_THRESHOLD ?= HIGH
GATE_FP_MIN_CONF   ?= 0.8

# D1/D2 的舊門檻（只有顯式傳給 make scan 時才生效）
FAIL_ON_SEMGREP ?= ERROR
FAIL_ON_TRIVY   ?= HIGH,CRITICAL

# repo 掛成讀寫：out/ 要寫報告、make lock 要寫 package-lock.json、
# make baseline 要在 .git 建 worktree。sec-cache 存 trivy 的漏洞 DB。
DOCKER = docker run --rm \
	  -v "$(CURDIR):/src" \
	  -v sec-cache:/cache \
	  -w /src \
	  -e TARGET="$(TARGET)" \
	  -e OUT_DIR="$(OUT_DIR)" \
	  -e SEMGREP_RULES="$(SEMGREP_RULESETS)" \
	  -e TRIVY_SCANNERS="$(TRIVY_SCANNERS)" \
	  -e BASE_REF="$(BASE_REF)" \
	  -e GATE_FP_MIN_CONF="$(GATE_FP_MIN_CONF)"

# D4 triage：
#   PROVIDER=ollama  -> 打本機 ollama（免費，預設）
#   PROVIDER=anthropic -> 打 Anthropic API（要 ANTHROPIC_API_KEY，值只在你的 shell 裡，不進 repo）
#   MODEL=xxx 可覆寫模型；留空由 triage_agent.py 依 provider 選預設
# --add-host 讓 container 內的 host.docker.internal 指得到你的 Mac（Linux 上也能用）
DOCKER_AI = $(DOCKER) \
	  --add-host=host.docker.internal:host-gateway \
	  -e ANTHROPIC_API_KEY -e OLLAMA_BASE_URL -e TRIAGE_MODEL_OLLAMA -e OLLAMA_TIMEOUT
TRIAGE_ARGS = --provider $(PROVIDER) $(if $(MODEL),--model $(MODEL),)

.PHONY: help build version scan gate gate-all sast sca count lock baseline diff findings \
        triage triage-dry triage-head triage-report triage-show ollama-check \
        shell lint-ci lint-ci-pedantic clean

## help     : 列出可用 target
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'

## build    : 建 image（semgrep trivy gh actionlint zizmor node）
build:
	docker build -t $(IMAGE) .

## version  : 印出所有工具版本
version: build
	docker run --rm $(IMAGE) version

# ---------------------------------------------------------------- 掃描
## scan     : semgrep + trivy 掃整個 repo，只產生資料不做門檻判定
scan: build
	$(DOCKER) -e FAIL_ON_SEMGREP=none -e FAIL_ON_TRIVY=none $(IMAGE) scan

## sast     : 只跑 semgrep
sast: build
	$(DOCKER) -e SKIP_TRIVY=1 -e FAIL_ON_SEMGREP=none $(IMAGE) scan

## sca      : 只跑 trivy
sca: build
	$(DOCKER) -e SKIP_SEMGREP=1 -e FAIL_ON_TRIVY=none $(IMAGE) scan

## count    : 不重掃，彙整 out/ 現有 JSON
count: build
	$(DOCKER) $(IMAGE) count

## gate     : D5 的 policy gate（純規則，不需要 LLM）。BLOCK 即 exit 1
gate: build
	$(DOCKER) $(IMAGE) policy \
	  --findings $(OUT_DIR)/new.json --triage $(OUT_DIR)/triage.json \
	  --threshold $(SEVERITY_THRESHOLD) --out $(OUT_DIR)/gate.json $(ARGS)

## gate-all : 同上，但對 head 全量判定（相當於 fail_on=all）
gate-all: build
	$(DOCKER) $(IMAGE) findings --db $(OUT_DIR)/findings.db new --head head --json $(OUT_DIR)/head.json
	$(DOCKER) $(IMAGE) policy \
	  --findings $(OUT_DIR)/head.json --triage $(OUT_DIR)/triage-head.json \
	  --threshold $(SEVERITY_THRESHOLD) --out $(OUT_DIR)/gate.json $(ARGS)

# 註：D1/D2 的舊門檻行為仍可用 `make scan FAIL_ON_SEMGREP=ERROR FAIL_ON_TRIVY=HIGH,CRITICAL` 取得。

# ---------------------------------------------------------------- D3
## lock     : 產生 samples/node-api/package-lock.json（不裝 node_modules）
lock: build
	$(DOCKER) $(IMAGE) lock

## baseline : 在拋棄式 git worktree 裡掃 BASE_REF，產生 out/*.base.json
baseline: build
	$(DOCKER) $(IMAGE) baseline

## diff     : normalize + fingerprint + 算出 head 相對 BASE_REF 新增了什麼
diff: build
	$(DOCKER) $(IMAGE) diff

## findings : 直接呼叫 findings.py（例：make findings ARGS="show --run head"）
findings: build
	$(DOCKER) $(IMAGE) findings --db $(OUT_DIR)/findings.db $(ARGS)

# ---------------------------------------------------------------- D4
## triage   : 對 out/new.json 跑 LLM triage（預設 PROVIDER=ollama，免費）
triage: build
	$(DOCKER_AI) $(IMAGE) triage --db $(OUT_DIR)/findings.db run --input $(OUT_DIR)/new.json --json $(OUT_DIR)/triage.json $(TRIAGE_ARGS) $(ARGS)

## triage-dry : 只印 prompt，不呼叫 API、不需要 API key
triage-dry: build
	$(DOCKER) $(IMAGE) triage --db $(OUT_DIR)/findings.db run --input $(OUT_DIR)/new.json --dry-run $(ARGS)

## triage-head : 對整個 head run 跑 triage（例：make triage-head PROVIDER=anthropic MODEL=claude-sonnet-5）
triage-head: build
	$(DOCKER_AI) $(IMAGE) triage --db $(OUT_DIR)/findings.db run --run head --json $(OUT_DIR)/triage-head.json $(TRIAGE_ARGS) $(ARGS)

## triage-report : 把 triage 結果印成 Markdown 表格（TRIAGE_JSON 可換成 triage-head.json）
triage-report: build
	$(DOCKER) $(IMAGE) triage report --json $(TRIAGE_JSON) --md

## ollama-check : 確認 container 連得到本機 ollama、模型有沒有 tools 能力
ollama-check: build
	$(DOCKER_AI) $(IMAGE) python3 -c "import os,json,urllib.request; \
	b=os.environ.get('OLLAMA_BASE_URL','http://host.docker.internal:11434'); \
	m=os.environ.get('MODEL_TO_CHECK','gemma3:4b'); \
	print('base:',b); \
	print(json.dumps({k:v for k,v in json.load(urllib.request.urlopen(urllib.request.Request(b+'/api/show',data=json.dumps({'model':m}).encode(),headers={'content-type':'application/json'}),timeout=30)).items() if k in ('capabilities','details')},indent=2))"

## triage-show : 列出資料庫裡所有 verdict 與理由
triage-show: build
	$(DOCKER) $(IMAGE) triage --db $(OUT_DIR)/findings.db show

# ---------------------------------------------------------------- 其他
## lint-ci  : 掃 pipeline 本身（actionlint + zizmor）
lint-ci: build
	docker run --rm -v "$(CURDIR):/src:ro" $(IMAGE) lint

## lint-ci-pedantic : 同上，開 zizmor pedantic
lint-ci-pedantic: build
	docker run --rm -v "$(CURDIR):/src:ro" -e ZIZMOR_ARGS=--persona=pedantic $(IMAGE) lint

## shell    : 進 container 手動玩（repo 讀寫掛載）
shell: build
	$(DOCKER) -it $(IMAGE) bash

## clean    : 刪掉 out/
clean:
	rm -rf out

# 註：D3 起輸出目錄改為 repo 內的 out/（.gitignore 已含），CI 與本機一致。
#     reports/ 是 D1/D2 的舊輸出，保留但不再寫入。

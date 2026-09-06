IMAGE            ?= sec-pr-gate:latest

# D5 會把這三個變成 reusable workflow 的 inputs
SEMGREP_RULESETS ?= p/default p/secrets p/owasp-top-ten
TRIVY_SCANNERS   ?= vuln,secret,misconfig
BASE_REF         ?= main

# 掃描標的（repo 根目錄）與報告輸出目錄，都在 container 內的路徑
TARGET  ?= /src
OUT_DIR ?= /src/out

# D1/D2 的門檻，只有 make gate 會用到
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
	  -e BASE_REF="$(BASE_REF)"

.PHONY: help build version scan gate sast sca count lock baseline diff findings shell lint-ci lint-ci-pedantic clean

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

## gate     : D1/D2 的門檻判定（命中即 exit 1）。真正的 gate 邏輯 D5 才會取代它
gate: build
	$(DOCKER) -e FAIL_ON_SEMGREP="$(FAIL_ON_SEMGREP)" -e FAIL_ON_TRIVY="$(FAIL_ON_TRIVY)" $(IMAGE) scan

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

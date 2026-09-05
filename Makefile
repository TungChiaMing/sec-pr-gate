IMAGE   ?= sec-pr-gate:latest
TARGET  ?= $(CURDIR)/app
REPORTS ?= $(CURDIR)/reports

# 共用的 docker run 參數（/src 唯讀掛掃描標的、/out 出報告、/cache 快取 trivy DB）
DOCKER_RUN = docker run --rm \
	  -v "$(TARGET):/src:ro" \
	  -v "$(REPORTS):/out" \
	  -v sec-cache:/cache

# lint 掃的是 repo 自己的 .github/workflows，所以掛根目錄而不是 $(TARGET)
DOCKER_LINT = docker run --rm -v "$(CURDIR):/src:ro"

.PHONY: build version scan sast sca count lint-ci lint-ci-pedantic shell clean help

## help    : 列出可用 target
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'

## build   : 建 image（semgrep + trivy + gh + actionlint + zizmor）
build:
	docker build -t $(IMAGE) .

## version : 印出所有工具版本（確認 trivy >= 0.70.0）
version: build
	docker run --rm $(IMAGE) version

## scan    : semgrep + trivy 全掃 + 門檻判定，命中即 exit 1（CI 用）
scan: build
	mkdir -p "$(REPORTS)"
	$(DOCKER_RUN) $(IMAGE) scan

## sast    : 只跑 semgrep，不做門檻判定（reports/semgrep.json + .sarif）
sast: build
	mkdir -p "$(REPORTS)"
	$(DOCKER_RUN) -e SKIP_TRIVY=1 -e FAIL_ON_SEMGREP=none $(IMAGE) scan

## sca     : 只跑 trivy，不做門檻判定（reports/trivy.json + .sarif）
sca: build
	mkdir -p "$(REPORTS)"
	$(DOCKER_RUN) -e SKIP_SEMGREP=1 -e FAIL_ON_TRIVY=none $(IMAGE) scan

## count   : 不重新掃描，彙整 reports/ 現有 JSON 並統一列印
count: build
	$(DOCKER_RUN) $(IMAGE) count

## shell   : 進 container 手動玩
shell: build
	docker run --rm -it -v "$(TARGET):/src:ro" $(IMAGE) bash

## lint-ci : 掃 pipeline 本身（actionlint + zizmor，跑在 image 裡，本機不用裝）
lint-ci: build
	$(DOCKER_LINT) $(IMAGE) lint

## lint-ci-pedantic : 同上，但開 zizmor pedantic（連 permissions 沒註解都報）
lint-ci-pedantic: build
	$(DOCKER_LINT) -e ZIZMOR_ARGS=--persona=pedantic $(IMAGE) lint

## clean   : 刪掉 reports/
clean:
	rm -rf "$(REPORTS)"

# 註：sast / sca 會各自覆寫 reports/summary.md（另一個工具顯示 _skipped_）。
#     要完整的雙工具 summary.md 請跑 make scan。
#     JSON 檔各自獨立，所以 make sast + make sca 之後 make count 仍會印出兩邊。

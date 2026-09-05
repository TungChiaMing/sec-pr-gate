# syntax=docker/dockerfile:1
#
# sec-pr-gate — semgrep + trivy + gh + actionlint + zizmor 打包成單一掃描 image
# 支援 linux/amd64 與 linux/arm64（Apple Silicon 原生）
#
# build:  docker build -t sec-pr-gate:latest .
# run:    docker run --rm -v "$PWD:/src:ro" -v "$PWD/reports:/out" sec-pr-gate:latest

########################################
# Stage 1：從官方 trivy image 取 binary（多架構，免自行處理 arch 判斷）
########################################
FROM aquasec/trivy:latest AS trivy

########################################
# Stage 2：runtime
########################################
FROM python:3.12-slim-bookworm

# semgrep 版本；要釘死可改成 "==1.175.0"
ARG SEMGREP_SPEC=">=1.175.0"

# pipeline 自我檢查工具（版本釘死，binary 驗 sha256）
ARG ZIZMOR_SPEC="==1.30.0"
ARG ACTIONLINT_VERSION="1.7.10"
ARG ACTIONLINT_SHA256_AMD64="f4c76b71db5755a713e6055cbb0857ed07e103e028bda117817660ebadb4386f"
ARG ACTIONLINT_SHA256_ARM64="cd3dfe5f66887ec6b987752d8d9614e59fd22f39415c5ad9f28374623f41773a"

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0

# ---------- 系統套件 + GitHub CLI ----------
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates curl git jq bash tini gnupg shellcheck; \
    install -m 0755 -d /etc/apt/keyrings; \
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        -o /etc/apt/keyrings/githubcli-archive-keyring.gpg; \
    chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg; \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends gh; \
    apt-get purge -y gnupg; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*

# ---------- trivy ----------
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

# ---------- actionlint（自行下載 + 驗 sha256，跟 CI 裡裝 trivy 同一套做法） ----------
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) al_sha="$ACTIONLINT_SHA256_AMD64" ;; \
      arm64) al_sha="$ACTIONLINT_SHA256_ARM64" ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/actionlint.tgz \
      "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_${arch}.tar.gz"; \
    echo "${al_sha}  /tmp/actionlint.tgz" | sha256sum -c -; \
    tar -xzf /tmp/actionlint.tgz -C /tmp actionlint; \
    install -m 0755 /tmp/actionlint /usr/local/bin/actionlint; \
    rm -f /tmp/actionlint.tgz /tmp/actionlint

# ---------- semgrep + zizmor ----------
RUN pip install --upgrade pip \
 && pip install "semgrep${SEMGREP_SPEC}" "zizmor${ZIZMOR_SPEC}"

# ---------- 非 root 使用者 ----------
RUN useradd -m -u 1000 -s /bin/bash scanner \
 && mkdir -p /src /out /cache/semgrep /cache/trivy \
 && chown -R scanner:scanner /out /cache

# ---------- 腳本 ----------
COPY --chmod=0755 scripts/ /usr/local/bin/

ENV XDG_CACHE_HOME=/cache \
    TRIVY_CACHE_DIR=/cache/trivy \
    SEMGREP_VERSION_CACHE_PATH=/cache/semgrep/last_version_check \
    GIT_CONFIG_GLOBAL=/tmp/.gitconfig \
    TARGET=/src \
    OUT_DIR=/out

USER scanner
WORKDIR /src

# 冒煙測試：六個工具都叫得動才算 build 成功
RUN semgrep --version && trivy --version && gh --version \
 && actionlint --version && zizmor --version && shellcheck --version

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["scan"]

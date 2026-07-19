# =========================================================
# AI DevSecOps Sentinel — backend image
# Build from the REPO ROOT (the compose file does this):
#   docker build -f backend/Dockerfile .
#
# Ships the FastAPI app plus the full scanner registry at
# pinned versions. checkov and semgrep live in their own
# virtualenvs so their (large) dependency trees can never
# conflict with the app's.
# =========================================================

FROM python:3.14-slim

# ---- scanner versions (pinned) --------------------------
ARG GITLEAKS_VERSION=8.30.1
ARG HADOLINT_VERSION=2.14.0
ARG KUBESEC_VERSION=2.14.2
ARG TRIVY_VERSION=0.72.0
ARG CHECKOV_VERSION=3.3.8
ARG SEMGREP_VERSION=1.170.0
ARG SHELLCHECK_VERSION=0.10.0
ARG ACTIONLINT_VERSION=1.7.7

# docker buildx sets this to amd64 / arm64
ARG TARGETARCH=amd64

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates xz-utils \
    && rm -rf /var/lib/apt/lists/*

# ---- release-binary scanners ----------------------------
# Asset naming differs per project: gitleaks uses x64/arm64,
# hadolint x86_64/arm64, kubesec amd64/arm64, shellcheck
# x86_64/aarch64 (.tar.xz), actionlint amd64/arm64.
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) GL_ARCH=x64; HL_ARCH=x86_64; KS_ARCH=amd64; SC_ARCH=x86_64; AL_ARCH=amd64 ;; \
      arm64) GL_ARCH=arm64; HL_ARCH=arm64; KS_ARCH=arm64; SC_ARCH=aarch64; AL_ARCH=arm64 ;; \
      *) echo "unsupported arch: ${TARGETARCH}" && exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks; \
    curl -fsSL -o /usr/local/bin/hadolint \
      "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-linux-${HL_ARCH}"; \
    chmod +x /usr/local/bin/hadolint; \
    curl -fsSL "https://github.com/controlplaneio/kubesec/releases/download/v${KUBESEC_VERSION}/kubesec_linux_${KS_ARCH}.tar.gz" \
      | tar -xz -C /usr/local/bin kubesec; \
    curl -fsSL "https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK_VERSION}/shellcheck-v${SHELLCHECK_VERSION}.linux.${SC_ARCH}.tar.xz" \
      | tar -xJ -C /usr/local/bin --strip-components=1 "shellcheck-v${SHELLCHECK_VERSION}/shellcheck"; \
    curl -fsSL "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_${AL_ARCH}.tar.gz" \
      | tar -xz -C /usr/local/bin actionlint; \
    curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}"

# ---- python-based scanners (isolated venvs) --------------
RUN python -m venv /opt/checkov \
    && /opt/checkov/bin/pip install --no-cache-dir "checkov==${CHECKOV_VERSION}" \
    && ln -s /opt/checkov/bin/checkov /usr/local/bin/checkov
RUN python -m venv /opt/semgrep \
    && /opt/semgrep/bin/pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" \
    && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep

# ---- app ------------------------------------------------
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ backend/

# Non-root: scanners cache under HOME (trivy DB, semgrep
# rules), the app writes workspace/ under /app. The .cache
# dir must exist HERE, owned by sentinel, so the compose
# named volume inherits that ownership at first mount —
# otherwise it mounts root-owned and trivy's DB download
# fails with a permission error.
# Explicit UID/GID: Kubernetes runAsNonRoot can only verify a
# NUMERIC user — `USER sentinel` fails admission on GKE.
RUN useradd --create-home --uid 1000 sentinel \
    && mkdir -p /home/sentinel/.cache \
    && chown -R sentinel:sentinel /app /home/sentinel/.cache
USER 1000:1000
ENV HOME=/home/sentinel

EXPOSE 8000

# Single worker BY DESIGN: sessions, file memory, and the
# FAISS index are in-process. Do not add --workers without
# first externalizing that state.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]

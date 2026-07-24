# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/) and this project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

_Nothing yet._

## [1.0.0] - 2026-07-25

First stable, production-deployed, and independently-evaluated release. An
AI DevSecOps engineer that reasons *on top of* 11 deterministic security
scanners — grounded findings, not hallucinations.

### Added
- **11 grounded scanners** — added `report-import` (ingests uploaded
  Trivy/Semgrep JSON, SARIF, and CycloneDX/SPDX SBOMs as structured
  findings; SBOM components resolved to CVEs via `trivy sbom`) and
  `ansible-guard` (Ansible playbook security checks) to the registry
  alongside gitleaks, checkov, trivy, hadolint, semgrep, kubesec,
  shellcheck, actionlint, and the built-in injection-guard.
- **State externalization** — RAG on **pgvector** and jobs + session
  memory on **Redis**, env-gated (`DATABASE_URL` / `REDIS_URL`) with a
  transparent in-process fallback.
- **Long-conversation memory** — an authoritative server-side turn log
  plus a rolling summary, so facts stated earlier than the verbatim
  window are retained.
- **Independent evaluation & regression suite** — 172- and
  211-interaction evaluation passes and a reusable 68-case regression
  suite in [`evaluation/`](evaluation/) (66/68 passing, 0 open code
  defects); see [`docs/EVALUATION.md`](docs/EVALUATION.md).
- **Documentation suite** — how-it-works, developer-guide, security model,
  evaluation, and roadmap docs; community-health files (`SECURITY.md`,
  `CODE_OF_CONDUCT.md`) and issue/PR templates.
- **Supply-chain security** for the project's own images: SBOM (syft),
  trivy vulnerability gate (blocks fixable criticals), and keyless
  cosign signing + SBOM attestation via workflow OIDC.
- **Structured logging** (JSON, per-request `X-Request-Id` correlation)
  replacing all `print()` calls.
- **Observability**: Prometheus metrics on `/metrics`, a Grafana
  dashboard, a PodMonitor, and optional Sentry error tracking.
- **AI output evaluation harness** (`evals/ai_eval.py`) — deterministic
  scoring of the LLM analysis (grounding, coverage, no-fabricated-CVE,
  redaction, injection-resistance, format) with unit-tested scorers.
- **HTTPS** on GKE via cert-manager + Let's Encrypt (sslip.io, no
  domain), with HTTP→HTTPS redirect.
- **GKE deployment**: Terraform (Autopilot cluster + Artifact Registry),
  a hardened Helm chart, and per-stack CI/CD with keyless WIF that
  builds, scans, signs, and Helm-deploys on every push to `main`.
- **Prompt-injection defenses**: the built-in `injection-guard` scanner,
  untrusted-content fencing, and system-prompt hardening.
- Upload **size limits**, **zip-bomb/zip-slip guards**, optional
  **API-key auth**, and a spoof-resistant **per-client rate limit**.
- Repo governance: `LICENSE` (MIT), `CONTRIBUTING`, `CODEOWNERS`, this
  changelog, and a real docs set (`QUICKSTART`, `API`, `TROUBLESHOOTING`).

### Fixed
- **Generation routing** — "write me a dockerfile / terraform" now
  produces the artifact (MODE 2.5) instead of re-running file analysis.
- **Dual-use safety** — refuses runnable weaponized payloads (fork bombs,
  unguarded mass-destructive DDL, malware, escape exploits) while still
  answering defensive, educational, and diagnostic questions.
- **Reliability** — cached `/health` scanner status so a slow scan can't
  evict the single pod; bounded dependency scans so a lone manifest can't
  hang the request; sub-batched embeddings to respect the per-request
  token cap (a large file summed past 300k tokens before).
- **Recommendations UI** — file-analysis recommendations render as styled
  severity rows; section extraction no longer bleeds cross-file content
  into the recommendations block.
- **Large-repo prompts** — repo-sized scans shrink the raw file context
  and retry on rate-limit (residual large-repo narrative limit is the
  OpenAI account's tokens-per-minute tier; verified findings always render).
- Repo-sized scans no longer overflow the LLM token budget (findings
  roll up above a threshold).
- Session-id generation works over plain HTTP (secure-context fallback).
- Rejected uploads are surfaced to the user instead of failing silently;
  unreadable uploads (e.g. images) are declined honestly, and files
  truncated at the size cap are flagged.
- Numeric container UID so `runAsNonRoot` admits the backend on GKE.
- Empty `LOG_LEVEL`/`LOG_FORMAT` env values tolerated (Helm
  `--reuse-values` interaction).

[Unreleased]: https://github.com/ravisinghrajput95/AI-DevSecOps-Sentinel/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/ravisinghrajput95/AI-DevSecOps-Sentinel/releases/tag/v1.0.0

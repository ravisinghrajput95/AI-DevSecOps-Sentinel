# Changelog

All notable changes to this project are documented here. The format
is based on [Keep a Changelog](https://keepachangelog.com/). The
project is not yet versioned/tagged; changes accrue under _Unreleased_.

## [Unreleased]

### Added
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
- Repo-sized scans no longer overflow the LLM token budget (findings
  roll up above a threshold).
- Session-id generation works over plain HTTP (secure-context fallback).
- Rejected uploads are surfaced to the user instead of failing silently.
- Numeric container UID so `runAsNonRoot` admits the backend on GKE.
- Empty `LOG_LEVEL`/`LOG_FORMAT` env values tolerated (Helm
  `--reuse-values` interaction).

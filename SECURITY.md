# Security Policy

AI DevSecOps Sentinel is a security tool, so we hold its own security to a
high bar. Thank you for helping keep it and its users safe.

## Supported versions

The project ships from `main` with immutable, digest-pinned container images
built and signed by CI. The latest released image is the supported version.

| Version | Supported |
|---|---|
| `main` (latest signed image) | ✅ |
| older tags | ⚠️ best-effort |

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via [GitHub's private vulnerability reporting](https://github.com/ravisinghrajput95/AI-DevSecOps-Sentinel/security/advisories/new)
(Security → *Report a vulnerability*), or email the maintainer listed in
[`CODEOWNERS`](./CODEOWNERS).

Please include:

- A description of the issue and its impact
- Steps to reproduce (a minimal repro or PoC where possible)
- Affected component (backend API, frontend, scanner integration, deployment)
- Any suggested remediation

**Response targets:** acknowledgement within 3 business days; triage and a
remediation plan within 10 business days. We'll keep you updated and credit
you in the release notes (unless you prefer to remain anonymous).

## Scope

In scope: the backend API, the SPA frontend, the scanner integrations, the
Helm chart / Kubernetes manifests, and the CI/CD supply-chain workflow.

Out of scope: vulnerabilities in third-party scanners (report those upstream)
and issues that require a pre-compromised host or cluster-admin access.

## The project's own security posture

Sentinel practices what it preaches — see [`docs/SECURITY.md`](./docs/SECURITY.md)
for the full model. Highlights:

- **Output redaction** — secrets are scrubbed from every LLM response at the
  code level, not just by prompt instruction.
- **Untrusted-input handling** — uploaded file content is treated as data;
  file-borne prompt-injection is detected and never obeyed.
- **Supply chain** — every image gets an SPDX SBOM (syft), a Trivy CRITICAL
  gate, and a keyless cosign signature + attestation (Sigstore).
- **Least privilege** — non-root containers, dropped capabilities,
  `RuntimeDefault` seccomp, and a narrow CI service account (WIF, no keys).

See the full [Security documentation](./docs/SECURITY.md).

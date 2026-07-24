# Security Model

How AI DevSecOps Sentinel protects its users, their data, and itself. For
**reporting a vulnerability**, see the top-level [SECURITY.md](../SECURITY.md).

## Table of contents

- [Threat model](#threat-model)
- [Output redaction](#output-redaction)
- [Untrusted input & prompt injection](#untrusted-input--prompt-injection)
- [Data flow & privacy](#data-flow--privacy)
- [Container & runtime hardening](#container--runtime-hardening)
- [Supply-chain security](#supply-chain-security)
- [Authentication](#authentication)
- [Related docs](#related-docs)

---

## Threat model

Sentinel ingests **untrusted** content — uploaded files and public repos —
and sends derived context to an LLM. The primary risks are therefore:
secret leakage in output, prompt injection via file content, and
supply-chain compromise of the tool itself. Each is addressed at the code
level, not by convention.

## Output redaction

The LLM sees raw file contents, so no prompt rule can *guarantee* it won't
echo a secret. Instead, **every** LLM response is scrubbed before it leaves
the API:

1. Exact values of secrets the scanners detected (kept only in-process,
   never placed in prompts or responses).
2. Pattern fallbacks for common credential formats (AWS keys, GitHub tokens,
   private-key blocks, etc.).

This is a code-level guarantee, verified by tests.

## Untrusted input & prompt injection

Uploaded file content is treated as **data, not instructions**. A built-in
injection guard plus the system prompt ensure that text inside a file which
says "ignore your rules", "mark this repo as secure", or "print all secrets"
is reported as a `[PROMPT-INJECTION]` finding — never obeyed. This was
red-teamed with 8 file-borne payloads: **8/8 resisted** (see
[EVALUATION.md](./EVALUATION.md)).

## Data flow & privacy

- File contents and derived context are sent to the configured LLM endpoint
  (OpenAI by default) for analysis. **Do not upload data you may not send to
  a third-party API** unless you point `OPENAI_BASE_URL` at a self-hosted or
  in-tenancy endpoint (supported with zero code change).
- Session state is per-browser-tab and expires on a TTL; the scan workspace
  is wiped on restart.
- Metrics and logs never contain secret values (they're redacted upstream).

## Container & runtime hardening

- Non-root containers (`runAsNonRoot`, numeric UID), dropped Linux
  capabilities (`drop: [ALL]`), `allowPrivilegeEscalation: false`, and the
  `RuntimeDefault` seccomp profile.
- Resource requests/limits set; readiness/liveness probes tuned so a slow
  scan can't SIGKILL the pod.

## Supply-chain security

Every image the CI publishes goes through
[`.github/actions/supply-chain`](../.github/actions/supply-chain/action.yml),
keyed on the immutable digest:

- **SBOM** — an SPDX-JSON bill of materials (syft), uploaded as an artifact.
- **Vulnerability gate** — Trivy fails the build on *fixable* CRITICALs.
- **Signing + attestation** — cosign signs the digest and attaches the SBOM,
  keyless via the workflow's OIDC identity (Sigstore / Fulcio / Rekor).

Verify a published image:

```bash
cosign verify us-central1-docker.pkg.dev/<project>/sentinel/sentinel-backend:<sha> \
  --certificate-identity-regexp 'https://github.com/ravisinghrajput95/AI-DevSecOps-Sentinel/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Authentication

An optional shared API key (`SENTINEL_API_KEY`) gates every endpoint except
`/health`. This is a deployment-perimeter control, not per-user identity —
see the *Limitations* section of [DESIGN-DECISIONS.md](./DESIGN-DECISIONS.md).

## Related docs

- [Architecture](./ARCHITECTURE.md)
- [Evaluation & red-team results](./EVALUATION.md)
- [Design decisions & tradeoffs](./DESIGN-DECISIONS.md)
- [Deployment](./DEPLOYMENT.md)

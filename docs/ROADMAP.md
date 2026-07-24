# Roadmap

Where the project has been and the directions already identified for it.
This roadmap is descriptive — it consolidates the "future work" and
"limitations" that live in [DESIGN-DECISIONS.md](./DESIGN-DECISIONS.md) and
the [evaluation](./EVALUATION.md), not a set of promises.

## Table of contents

- [Shipped](#shipped)
- [Known limitations (honest)](#known-limitations-honest)
- [Future directions](#future-directions)
- [Non-goals](#non-goals)
- [How priorities are set](#how-priorities-are-set)
- [Related docs](#related-docs)

---

## Shipped

Recent milestones, most of them driven by the evaluation cycle:

- ✅ **11 grounded scanners** — including uploaded scanner-report / SBOM
  ingestion (`report-import`) and an Ansible security guard (`ansible-guard`)
- ✅ **State externalization** — RAG on pgvector, jobs + session memory on
  Redis (env-gated, with in-process fallback)
- ✅ **Long-conversation memory** — a server-side turn log + rolling summary
  that retains facts beyond the verbatim window
- ✅ **Production deployment** — GKE Autopilot via Terraform + Helm, HTTPS via
  ingress-nginx + cert-manager, keyless OIDC CI
- ✅ **Supply-chain security** — SBOM + Trivy gate + keyless cosign signing
- ✅ **Measured quality** — a 68-case regression suite at 66/68, CI-gated

## Known limitations (honest)

These are documented deliberately — a mature project names its edges.

| Limitation | Impact | Notes |
|---|---|---|
| **Single backend replica** | No horizontal scale yet | Sessions + workspace are pod-local; see below |
| **Large-repo LLM narrative** | 429s on very large repos | Bounded by the OpenAI account's tokens-per-minute tier; verified findings always render, focused questions answer. Fix is account-side (`OPENAI_BASE_URL` / higher tier) |
| **Multi-file cross-reference** | Shallow pairwise checks | Left to the LLM (SYSTEM_PROMPT Rule 18) rather than a brittle deterministic heuristic that would risk false positives |
| **npm CVE detection** | Needs a lockfile | `package.json` alone has version ranges Trivy can't pin — upload `package-lock.json` |
| **Auth is a shared API key** | No per-user identity/tenancy | A deployment-perimeter control, not RBAC |
| **External LLM egress** | Data leaves the cluster | Not suitable for air-gapped/regulated data unless pointed at an in-tenancy endpoint |

## Future directions

Documented in [DESIGN-DECISIONS.md](./DESIGN-DECISIONS.md#2-limitations--future-work)
as well-understood work (estimates, not commitments):

- **Workspace re-materialization → `replicas > 1`.** Rebuild the scan
  workspace on demand from file content already in session state — the
  prerequisite for true horizontal scaling. The state-externalization work
  (pgvector + Redis) already done is the foundation.
- **Durable job execution.** Move async ingest from an in-process thread pool
  to a real queue + a separate worker deployment, so a "running" job survives
  a restart and heavy scans run off the API pod.
- **Per-user identity.** OIDC-based auth and tenancy beyond the single shared
  API key.

## Non-goals

To keep scope honest:

- Replacing the deterministic scanners with LLM-only detection (the grounding
  is the whole point).
- Becoming a general-purpose chatbot — Sentinel is a DevSecOps assistant and
  redirects off-topic questions by design.
- Bundling every scanner in existence — coverage is curated for signal, not
  breadth.

## How priorities are set

Priority follows evidence: the [regression suite](../evaluation/) and
[evaluation](./EVALUATION.md) surface real weaknesses, and those drive the
next unit of work. Contributions that close a documented gap — or add
evaluation cases that expose a new one — are especially welcome
(see [CONTRIBUTING.md](../CONTRIBUTING.md)).

## Related docs

- [Design decisions & limitations](./DESIGN-DECISIONS.md)
- [Evaluation](./EVALUATION.md) — how weaknesses are found
- [Architecture](./ARCHITECTURE.md) · [How it works](./how-it-works.md)

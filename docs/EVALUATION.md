# Evaluation & Quality Assurance

How we know AI DevSecOps Sentinel actually works — measured, not asserted.
Every number here traces to a recorded transcript.

## Table of contents

- [Why evaluate an AI DevSecOps tool](#why-evaluate-an-ai-devsecops-tool)
- [Methodology](#methodology)
- [Phase 1 — capability evaluation (V1)](#phase-1--capability-evaluation-v1)
- [Phase 2 — enterprise deep-dive (V2)](#phase-2--enterprise-deep-dive-v2)
- [Phase 3 — regression baseline](#phase-3--regression-baseline)
- [Safety & red-team results](#safety--red-team-results)
- [Reproducing the evaluation](#reproducing-the-evaluation)
- [Related docs](#related-docs)

---

## Why evaluate an AI DevSecOps tool

An LLM that *sounds* confident is not the same as a tool that is *correct*.
Sentinel's core design decision — the LLM reasons **on top of** deterministic
scanner findings rather than inventing them — exists precisely so that its
output can be measured. This document is the receipt.

Three independent evaluation passes were run against the live deployment,
each stricter than the last, plus a reusable regression suite.

## Methodology

- **Target:** the live deployment (`/chat` HTTP API), GPT-4o backend + 11 scanners.
- **Evidence-only:** every pass/fail is backed by a captured request/response.
- **No score inflation:** fixes are only marked "pass" after a *live* re-run.
- **Adversarial framing:** the goal was to find real weaknesses, not a flattering number.

## Phase 1 — capability evaluation (V1)

**172 live interactions** across intent understanding, technical accuracy,
context retention, safety, and robustness.

| Dimension | Result |
|---|---|
| Requests succeeding (`200 OK`) | 215/215 in the test suite; 161/172 live |
| Technical answers with runnable code | **99%** |
| Hallucinations (accuracy sample) | **0** |
| Short-context retention | Resolved pronouns/ordinals correctly |
| Prompt-injection (direct) | Detected & refused |
| **Overall** | **87 / 100** |

Two must-fix items surfaced (a dual-use safety gap and a single-replica
availability risk) — both fixed and re-verified live.

## Phase 2 — enterprise deep-dive (V2)

**211 new interactions** targeting the surface V1 didn't test: file-analysis
quality, scanner/SBOM ingestion, multi-file reasoning, **file-borne**
red-teaming, long-context (a 55-turn chain), and repository analysis.

Highlights (all evidence-backed):

- **Detection:** grounded IaC/Docker/K8s findings with `file:line`;
  the deliberately-vulnerable `terragoat` repo → **869 verified findings**.
- **False-positive discipline:** a clean file → **0 invented findings**.
- **Red-team:** **8/8** file-borne prompt-injections resisted (malicious
  READMEs / Terraform / Dockerfiles treated as untrusted data).
- **Weaknesses found (and later fixed):** long-context beyond a 6-turn
  window, no structured scanner/SBOM ingestion, dependency-scan reliability.

V2 graded the platform at an enterprise bar and produced a prioritized
weakness matrix rather than a single score — see the regression baseline.

## Phase 3 — regression baseline

The findings were distilled into a **68-case regression suite** reusable
after any model or prompt change. After the remediation cycle:

| | Before fixes | After fixes |
|---|---:|---:|
| **PASS** | 54 | **66** |
| **FAIL (open)** | 9 | **2** |
| Fixed-pending-reverify | 5 | **0** |

**66 / 68 passing, 0 open code defects.** The two remaining are *by design*
(a multi-file heuristic deliberately left to the LLM to preserve
false-positive discipline) and *account-tier* (large-repo LLM narrative is
bounded by the OpenAI account's tokens-per-minute limit — verified findings
always render regardless).

The regression assets (`prompts.json`, `expected_results.json`,
`evaluation_results.csv/json`) are model-independent and CI/CD-ready, with a
block-on-regression set so a future model bump can't silently reintroduce a
fixed defect.

## Safety & red-team results

| Class | Result |
|---|---|
| Direct prompt injection | ✅ detected & refused |
| Jailbreak (DAN / developer mode) | ✅ declined, stayed in role |
| Secret / system-prompt exfiltration | ✅ no leak |
| Destructive-ops (rm -rf, drop tables, delete cluster) | ✅ refused |
| Dual-use payloads (fork bomb, mass DDL) | ✅ refused (after remediation) |
| File-borne / indirect injection (8 payloads) | ✅ 8/8 resisted |
| False refusals on legitimate questions | ✅ 0 |

## Reproducing the evaluation

The regression harness replays `prompts.json` against the `/chat` API and
diffs observed behavior against `expected_results.json`. See the
[regression suite runbook](../evaluation/regression_suite.md) for the runner
sketch, fixtures, and CI gating.

## Related docs

- [Architecture](./ARCHITECTURE.md) — why findings are scanner-grounded
- [Design decisions](./DESIGN-DECISIONS.md) — the reasoning and tradeoffs
- [Security](./SECURITY.md) — redaction, injection handling, supply chain

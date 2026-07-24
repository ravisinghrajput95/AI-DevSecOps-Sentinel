# Developer Guide

Everything you need to run Sentinel locally, understand the layout, and
extend it — most usefully, add a new scanner.

## Table of contents

- [Prerequisites](#prerequisites)
- [Run it: two ways](#run-it-two-ways)
- [Repository layout](#repository-layout)
- [The scanner interface](#the-scanner-interface)
- [Adding a scanner](#adding-a-scanner)
- [Testing](#testing)
- [Evaluations](#evaluations)
- [Configuration reference](#configuration-reference)
- [Conventions](#conventions)
- [Related docs](#related-docs)

---

## Prerequisites

- **Python 3.12+**, **Node 20+**, **Docker** (for the compose path)
- The security scanners on your `PATH` for full local scanning: `gitleaks`,
  `checkov`, `trivy`, `hadolint`, `semgrep`, `kubesec`, `shellcheck`,
  `actionlint`. Missing tools degrade gracefully — a scanner that isn't
  installed is simply reported as unavailable, never a crash.
- An `OPENAI_API_KEY` (or an OpenAI-compatible endpoint via `OPENAI_BASE_URL`)

## Run it: two ways

**A. Docker Compose (simplest — matches production shape)**

```bash
echo "OPENAI_API_KEY=sk-..." > .env
docker compose up --build          # UI + API on http://localhost
```

Compose also brings up pgvector (Postgres) and Redis so the externalized-state
path is exercised locally.

**B. Local dev servers (fast iteration)**

```bash
# Backend (from the repo root)
python -m venv backend/.venv && source backend/.venv/bin/activate
pip install -r requirements.txt
uvicorn backend.main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend && npm install && npm run dev      # http://localhost:3000
```

The Vite dev server proxies `/chat`, `/health`, and `/scan-status` to the
backend on `:8000`. Note: the backend's `--reload` clears in-memory session
state on every code change, so re-upload files after edits.

## Repository layout

```text
backend/            FastAPI app
  main.py             /chat, /scan-status, /health, auth, rate limiting
  scanners/           the 11 scanners + registry (run_all_scanners)
  prompt_engine.py    build_prompt() + the SYSTEM_PROMPT + modes
  intent_engine.py    greeting/ack/off-topic/generation routing
  rag.py              chunk → embed → pgvector/FAISS hybrid retrieval
  session.py          per-tab session registry (ContextVar)
  memory.py           session-scoped state proxy (Redis or in-process)
  conversation.py     server-side turn log + rolling summary
  llm.py              OpenAI call + 429 retry
  redaction.py        code-level secret scrubbing
  file_handler.py     upload intake, dedup, workspace, zip/repo ingest
  jobs.py             async job registry (Redis or in-process)
  store.py            lazy Redis / pgvector clients
frontend/           React + Vite SPA (nginx in prod)
deploy/helm/        cloud-agnostic Helm chart
infra/              Terraform (GKE + Artifact Registry, GCS-backed state)
tests/              pytest — routing, scanners, redaction, memory, safety
e2e/                Playwright browser tests (run against the live deploy)
evals/              scanner benchmark + AI-quality harness
evaluation/         reusable regression suite (prompts + expected + results)
docs/               this documentation suite
```

## The scanner interface

A scanner is a tiny module with three things:

```python
TOOL = "my-scanner"

def available() -> bool:
    # True if the tool can run (binary present, or pure-Python)
    ...

def scan(workspace_dir: str) -> list:
    # Return a list of findings via make_finding(...)
    ...
```

`make_finding(tool, rule_id, severity, file, line, title, detail="",
evidence="", guideline=None)` (in `backend/scanners/base.py`) returns the
canonical finding dict; `severity` is one of
`CRITICAL / HIGH / MEDIUM / LOW / INFO`.

## Adding a scanner

1. Create `backend/scanners/my_scanner.py` implementing `TOOL`, `available()`,
   and `scan()`. Use `find_files()` / `run_command()` from `base.py`; keep it
   crash-isolated (return `[]` on anything unexpected) and low-false-positive.
2. Register it in `backend/scanners/__init__.py` — add the import and append
   it to the `SCANNERS` list.
3. Bump the scanner count assertion in `deploy/smoke_test.py`.
4. Add a focused test in `tests/test_<name>_scanner.py` (a fixture workspace →
   assert the expected findings; assert non-target files aren't mis-scanned).
5. If it needs a binary, install it in `backend/Dockerfile` and the Backend CI
   scanner-install step; if it's pure-Python, nothing else is needed.

The `report-import` and `ansible-guard` scanners are good, small references —
one wraps a CLI, the other is pure-Python pattern matching.

## Testing

```bash
pytest tests/ -v                       # backend unit + integration
cd frontend && npx eslint . && npm run build   # frontend lint + build
cd e2e && npx playwright test          # browser e2e (needs a deployed URL)
```

Some tests need a live Postgres (pgvector) or Redis and skip cleanly when
those aren't configured; Backend CI provides a pgvector service so the
`report-import`/RAG tests run there.

## Evaluations

```bash
python evals/run_benchmark.py          # deterministic scanner benchmark (free)
python evals/ai_eval.py                # AI-quality gates (needs OPENAI_API_KEY)
```

The reusable regression suite lives in [`evaluation/`](../evaluation/) — see
[EVALUATION.md](./EVALUATION.md) for how to run and gate it in CI.

## Configuration reference

| Variable | Default | Purpose |
|---|---|---|
| `OPENAI_API_KEY` | — (required) | LLM + embedding calls |
| `OPENAI_BASE_URL` | OpenAI | Any OpenAI-compatible endpoint (gateway / self-hosted) |
| `SENTINEL_LLM_MODEL` | `gpt-4o` | Reasoning model |
| `SENTINEL_LLM_MAX_TOKENS` | `4096` | Completion cap (raised in prod values) |
| `SENTINEL_API_KEY` | unset (open) | Require `X-API-Key` on all but `/health` |
| `DATABASE_URL` | unset → FAISS | pgvector Postgres for RAG |
| `REDIS_URL` | unset → in-proc | Redis for jobs + session memory |
| `SENTINEL_HISTORY_WINDOW` | `8` | Verbatim conversation turns before summarizing |
| `SENTINEL_RATE_LIMIT_PER_MIN` | `20` | Per-client `/chat` rate limit |
| `LOG_LEVEL` / `LOG_FORMAT` | `INFO` / `json` | Logging |

## Conventions

- Match the style of the surrounding code; keep changes small and focused.
- Add tests for every change; keep the full suite green.
- Never commit secrets — a self-scan runs on every push.
- See [CONTRIBUTING.md](../CONTRIBUTING.md) for the PR workflow and
  [DESIGN-DECISIONS.md](./DESIGN-DECISIONS.md) for the "why" behind the design.

## Related docs

- [How it works](./how-it-works.md) — the request lifecycle
- [Architecture](./ARCHITECTURE.md) · [Deployment](./DEPLOYMENT.md)
- [Evaluation](./EVALUATION.md) · [Roadmap](./ROADMAP.md)

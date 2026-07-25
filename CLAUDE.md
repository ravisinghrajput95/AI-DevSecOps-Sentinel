# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An AI DevSecOps assistant: a FastAPI backend + React/Vite SPA. It ingests
files, `.zip`s, or public GitHub URLs, runs **11 deterministic security
scanners**, and has an LLM reason *on top of* the verified scanner findings.

## Commands

Run from the repo root. The local backend venv lives at `backend/.venv`.

```bash
# Full stack (matches production shape: also starts pgvector + Redis)
docker compose up --build                      # UI + API on http://localhost

# Backend dev server
source backend/.venv/bin/activate && pip install -r requirements.txt
uvicorn backend.main:app --reload --port 8000

# Frontend dev server (Vite proxies /chat, /health, /scan-status → :8000)
cd frontend && npm install && npm run dev      # http://localhost:3000

# Backend tests (from repo root)
backend/.venv/bin/python -m pytest tests/ -q
backend/.venv/bin/python -m pytest tests/test_routing_fixes.py -q          # one file
backend/.venv/bin/python -m pytest tests/test_routing_fixes.py::test_x -q  # one test
# Frontend lint + build (CI is zero-tolerance on eslint)
cd frontend && npx eslint . && npm run build
# Browser e2e (runs against a deployed URL)
cd e2e && BASE_URL="https://<host>" npx playwright test
# Evaluations
python evals/run_benchmark.py     # deterministic scanner benchmark (free)
python evals/ai_eval.py           # AI-quality gates (needs OPENAI_API_KEY)
```

- Scanner-dependent tests **skip** when a scanner (or `DATABASE_URL`/`REDIS_URL`)
  is absent — they are not failures. `tests/test_rag_pgvector.py` needs a live
  Postgres; Backend CI provides a pgvector service for it.
- `--reload` wipes in-memory session state on every code change, so re-upload
  files after edits when testing through the UI.

## Architecture — the core invariant

**Findings are ground truth from deterministic scanners; the LLM never invents
them, it reasons over them.** This is the single most important idea — internalize
it before touching `scanners/`, `prompt_engine.py`, or `redaction.py`. Every
finding is tagged `[SCANNER-VERIFIED]` or `[AI-DETECTED]`.

### Request flow (`backend/main.py` `/chat`)

1. `session_scope` binds the request to a session via the `X-Session-Id` header
   using a `ContextVar` (`session.py`). Module-level accessors — `memory`,
   `rag`, the redaction secret set — resolve to the *active* session, so no
   session object is threaded through calls.
2. `file_handler.save_uploaded_files()` decodes/dedups/size-checks uploads,
   strips build dirs, writes to a per-session workspace dir, and RAG-indexes
   each file (`rag.add_document`).
3. `scanners.run_all_scanners()` runs all 11 scanners in parallel worker threads
   (crash-isolated), returning one severity-sorted findings list cached on the session.
4. `intent_engine.detect_intent()` short-circuits greetings/ack/off-topic
   *before* any LLM call; everything else goes to `prompt_engine.build_prompt()`.
5. `llm.ask_openai()` sends the prompt, injecting conversation memory; on a 429
   it retries once with a smaller completion reservation.
6. `redaction.scrub_secrets()` scrubs secret values from the answer at the code
   level (a guarantee no prompt rule can make) before it returns.

### Key seams (require reading multiple files)

- **Env-gated state backends** (`store.py`): `DATABASE_URL` set → RAG on
  **pgvector**, else in-process FAISS. `REDIS_URL` set → jobs + session memory
  on **Redis**, else in-process dicts. `init_stores()` runs at FastAPI startup
  (creates the pgvector schema; clears Redis session keys + truncates
  `rag_chunks` to mirror the workspace-wipe-on-restart — a single-replica assumption).
- **`prompt_engine.build_prompt()`** picks a MODE from the message + session
  state: file-analysis (grounded report), **generation** ("write me a
  Dockerfile" → produces the artifact, no findings panel; see
  `is_generation_request`), general-knowledge, or plain chat. `SYSTEM_PROMPT`
  is large; `build_scanner_context` rolls up findings above a threshold and
  `build_full_file_context` shrinks its char budget for repo-sized scans (both
  to stay under the LLM's token/TPM limits).
- **Scanner registry** (`scanners/__init__.py`): each scanner is
  `TOOL` + `available()` + `scan(workspace_dir) -> [make_finding(...)]`
  (`scanners/base.py`). `scanner_status()` is `@lru_cache`d — `/health` must
  stay O(1). See `report_scanner.py` (wraps a CLI) and `ansible_scanner.py`
  (pure-Python) as references.
- **Async repo ingest** (`github_ingest.py` + `jobs.py`): a GitHub URL becomes
  a background thread job; `/chat` returns a `job_id` and the UI polls
  `/scan-status/{id}`. Ingesting a new repo/zip resets the session (fresh per project).
- **Conversation memory** (`conversation.py`): an authoritative server-side turn
  log + a rolling summary (cheap-model summarization of turns aged out of the
  `SENTINEL_HISTORY_WINDOW`) so long chats retain earlier facts.

## Conventions & gotchas

- **Adding a scanner**: implement the interface, register it in
  `scanners/__init__.py`, **bump the scanner-count assertion in
  `deploy/smoke_test.py`**, and add `tests/test_<name>_scanner.py`. Install any
  binary in `backend/Dockerfile` **and** the Backend CI scanner-install step.
- **Session memory under Redis returns copies** — `memory["files"].append(...)`
  will silently not persist. Read-modify-write instead:
  `f = memory["files"]; f.append(x); memory["files"] = f`.
- **CI is path-filtered**: Backend/Frontend lanes only build/deploy on pushes to
  `main`; PRs run tests only. Adding a Helm values key needs a one-time
  `helm upgrade --reset-then-reuse-values` (the `--reuse-values` caveat).
- **`.gitleaks.toml`** allowlists the deliberately-fake secrets under `tests/`
  and `evals/`; a self-scan runs on every push.
- **Security-sensitive files** (scanners, redaction, prompts, CI, deploy, infra)
  are routed for review via `CODEOWNERS`.

## Where to read more

`docs/how-it-works.md` (request lifecycle), `docs/developer-guide.md`
(add-a-scanner, config reference), `docs/DESIGN-DECISIONS.md` (rationale +
limitations, incl. the single-replica constraint), `docs/EVALUATION.md`
(how quality is measured), `CONTRIBUTING.md` (workflow).

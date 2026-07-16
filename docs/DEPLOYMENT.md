# Deployment

Container-based deployment for a single VM or host. The stack is two
images: the **backend** (FastAPI + all six scanners at pinned
versions) and the **frontend** (nginx serving the built SPA and
reverse-proxying the API paths to the backend — same-origin, so no
CORS configuration is needed).

## Quickstart

```bash
# .env in the repo root:
#   OPENAI_API_KEY=sk-...          (required)
#   SENTINEL_API_KEY=change-me     (strongly recommended)

docker compose up --build -d
# UI + API on http://localhost:80
```

## Configuration

All variables are read from `.env` by docker compose:

| Variable | Default | Purpose |
|---|---|---|
| `OPENAI_API_KEY` | — (required) | LLM + embedding calls |
| `SENTINEL_API_KEY` | unset (open) | Require `X-API-Key` on every endpoint except `/health`; also baked into the frontend bundle as the key the UI sends |
| `SENTINEL_LLM_MODEL` | `gpt-4o` | Chat completion model |
| `SENTINEL_MAX_REQUEST_MB` | `80` | Request body cap (413 above it) |
| `SENTINEL_RATE_LIMIT_PER_MIN` | `20` | Per-client `/chat` requests per minute (429 above it, `0` disables) |
| `SENTINEL_CORS_ORIGINS` | localhost dev origins | Comma-separated allowlist; only needed for split-origin deployments |
| `SENTINEL_HTTP_PORT` | `80` | Host port the frontend binds |

Changing `SENTINEL_API_KEY` requires rebuilding the frontend image
(`docker compose up --build frontend`) because the key is baked into
the JS bundle at build time.

## TLS

The nginx container listens on plain HTTP. Terminate TLS in front of
it: a cloud load balancer, or on a bare VM a host-level reverse proxy
(caddy/certbot-managed nginx) forwarding to `SENTINEL_HTTP_PORT`.

## Operational notes

- **Single backend worker, by design.** Sessions, uploaded-file
  memory, and the FAISS index are all in-process. Scaling out or
  adding `--workers` first requires externalizing that state (Redis /
  a real vector store). A restart clears all session context.
- **Egress is required** at runtime: OpenAI API, GitHub (repo-URL
  ingestion), trivy CVE DB downloads, and semgrep's rule registry
  (`--config auto`). If you restrict egress, allowlist those.
- The `scanner-cache` volume persists trivy's CVE database and
  semgrep's rules — without it every container restart pays the
  first-scan download again.
- The backend container publishes no host port; the API is only
  reachable through nginx. For direct API access (curl/scripts),
  temporarily map `8000:8000` on the backend service.
- A client-side API key is visible to anyone who can load the page —
  it gates casual and scripted access, not determined users. Real
  per-user auth (OIDC) is the next tier beyond this skeleton.

## Image contents

Backend scanner versions are pinned as build args in
`backend/Dockerfile` (gitleaks, hadolint, kubesec, trivy as release
binaries; checkov and semgrep in isolated virtualenvs). Bump them
there, rebuild, and re-run the detection benchmark
(`evals/run_benchmark.py`) to catch behavioral drift.

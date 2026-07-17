# Deployment

Two supported targets: **GKE** (production, CI-deployed, below) and
**docker compose** (single VM / local, second half of this doc).

## GKE

Infra lives in [`infra/`](../infra/README.md) (Terraform: Autopilot
cluster `sentinel` + Artifact Registry in us-central1; WIF/OIDC for
CI documented there). The app ships as a Helm chart in
`deploy/helm/sentinel`.

**Flow**: every push to main that touches a stack runs that stack's
CI → builds and smoke-tests the image → pushes it to Artifact
Registry (keyless, via Workload Identity Federation) → `helm
upgrade` setting only that component's image tag, gated on its own
rollout. Nothing deploys from PRs.

One-time setup (already done):

```bash
# The backend's secrets — SENTINEL_API_KEY must equal the GitHub
# Actions secret VITE_SENTINEL_API_KEY baked into the frontend bundle
kubectl create secret generic sentinel-secrets \
  --from-literal=OPENAI_API_KEY=sk-... \
  --from-literal=SENTINEL_API_KEY=...
gh secret set VITE_SENTINEL_API_KEY --body <same value>
```

Get the UI address:

```bash
kubectl get svc sentinel-frontend   # EXTERNAL-IP, port 80
```

Notes:

- The deploys use `helm upgrade --reuse-values --set <component>.image.tag=<sha>`
  so each lane preserves the other's deployed tag. Caveat of
  `--reuse-values`: newly ADDED values keys don't pick up chart
  defaults on upgrade — when you add a values key, set it explicitly
  once (or `helm get values sentinel` / apply with `-f`).
- On the very first deploy the two lanes bootstrap each other: the
  first lane installs the release with the other component's tag
  still `latest` (not in the registry), which self-heals when the
  second lane deploys moments later.
- The backend runs `replicas: 1, strategy: Recreate` by design —
  see the comment in `backend-deployment.yaml` before scaling.
- To rotate SENTINEL_API_KEY: update the K8s secret AND the GitHub
  secret, then rebuild/redeploy the frontend (key is baked into the
  JS bundle at build time).

## Docker compose (single VM / local)

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
| `LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR` |
| `LOG_FORMAT` | `json` | `json` (one object/line, for Cloud Logging) or `text` (human-readable) |

Every log line carries a `request_id`; the same id is returned on the
`X-Request-Id` response header, so a user-reported failure can be traced
directly to its log lines.

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

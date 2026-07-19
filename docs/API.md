# API Reference

The backend is a FastAPI service. Interactive docs are served at
`/docs` (OpenAPI) when the app runs.

## Conventions

| Header | Purpose |
|---|---|
| `X-Session-Id` | Isolates a client's context (files, scan, RAG). One per browser tab; any request without it uses the shared `default` session. |
| `X-API-Key` | Required on every endpoint **except** `/health` and `/metrics` **when** `SENTINEL_API_KEY` is set on the server. Omitted → open (local dev). |
| `X-Request-Id` | Optional in; always echoed out. Correlates a request to its structured log lines. |

## `GET /health`

Unauthenticated liveness/readiness probe.

```json
{
  "status": "ok",
  "files_in_memory": 0,
  "active_sessions": 1,
  "scanners": { "gitleaks": true, "checkov": true, "trivy": true,
                "hadolint": true, "semgrep": true, "kubesec": true,
                "injection-guard": true }
}
```

## `GET /metrics`

Unauthenticated Prometheus exposition (`sentinel_`-prefixed metrics).
Served on the pod port only — not routed through the public ingress.

## `POST /chat`

The one analysis endpoint. Rate-limited per client
(`SENTINEL_RATE_LIMIT_PER_MIN`, default 20/min → `429`). Body cap
`SENTINEL_MAX_REQUEST_MB` (default 80 MB → `413`).

**Request**

```json
{
  "message": "audit this repo for secrets",
  "history": [["prev user msg", "prev assistant msg"]],
  "files": [{ "name": "main.tf", "content": "<base64>" }]
}
```

- `message` — the user prompt. An empty message never calls the LLM.
  A **GitHub URL** starts an **async** ingest: the response is a job
  handle (`{ "response": "📦 Ingesting…", "job_id": "...", "status":
  "running" }`) — poll `GET /scan-status/{job_id}` for the result
  rather than blocking on the ~40s download+scan.
- `files` — base64-encoded uploads (single files or a `.zip`).
  Oversized/unsupported/zip-bomb/zip-slip uploads are rejected and
  reported (see `upload_warnings`), never silently dropped.

**Response**

```json
{
  "response": "## Repository Analysis ...",
  "findings": [{ "tool": "gitleaks", "severity": "CRITICAL",
                 "file": "main.tf", "line": 2, "title": "...",
                 "evidence": "AKIA****************" }],
  "scanners": { "run": ["gitleaks", "..."], "missing": [] },
  "repo": { "name": "owner/repo", "files": 66 },
  "upload_warnings": [{ "name": "big.zip", "reason": "..." }]
}
```

`findings`/`scanners` come straight from the deterministic scan cache
(never through the LLM). Secret values are always redacted, in both
findings and prose. `repo` and `upload_warnings` appear only when
relevant.

## `GET /scan-status/{job_id}`

Polls an async ingest job (from a GitHub URL in `/chat`). Scoped to
the caller's session — another session's job id returns `404`.

```json
{ "job_id": "...", "status": "running|done|error",
  "phase": "downloading|scanning|done", "error": null,
  "result": { "response": "...", "findings": [ ... ],
              "scanners": { ... }, "repo": { ... } } }
```

`result` is populated only when `status` is `done`; it has the same
shape as a `/chat` response. On `error`, `error` carries the reason.

## `POST /remove-file`

Removes one file (or a whole `.zip` project) from the session and
re-runs the scanner registry over what remains.

```json
// request
{ "name": "main.tf" }
// response
{ "removed": 1, "files_in_memory": 0, "findings": [], "scanners": {...} }
```

## Status codes

| Code | Meaning |
|---|---|
| `200` | OK |
| `401` | Missing/invalid `X-API-Key` (when a key is configured) |
| `413` | Request body exceeds the configured cap |
| `422` | Malformed body (bad JSON / missing `message`) |
| `429` | Per-client rate limit exceeded |

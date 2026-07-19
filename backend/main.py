# backend/main.py

import asyncio
import concurrent.futures
import os
import secrets as pysecrets
import time
import uuid

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel

from backend import metrics
from backend.logging_setup import configure_logging, get_logger, set_request_id

configure_logging()
logger = get_logger(__name__)

# Optional error tracking — no-op unless SENTRY_DSN is set, so the
# dependency is harmless in dev/CI where no DSN exists.
_SENTRY_DSN = os.environ.get("SENTRY_DSN", "")
if _SENTRY_DSN:
    import sentry_sdk
    sentry_sdk.init(
        dsn=_SENTRY_DSN,
        traces_sample_rate=float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0")),
        environment=os.environ.get("SENTINEL_ENV", "production"),
    )
    logger.info("sentry error tracking enabled")

from backend import jobs
from backend.session import SESSIONS, activate, current

from backend.prompt_engine import build_prompt
from backend.file_handler import (
    save_uploaded_files,
    clear_workspace,
    remove_uploaded,
)
from backend.llm import ask_openai
from backend.memory import memory
from backend.intent_engine import detect_intent
from backend.github_ingest import (
    ingest_github_repo,
    parse_github_url,
)
from backend.rag import clear_rag
from backend.redaction import clear_secrets, scrub_secrets
from backend.scanners import scanner_status

# =========================================================
# AUTH (optional)
# Set SENTINEL_API_KEY in the environment to require an
# X-API-Key header on every endpoint except /health.
# Unset (the default) keeps local development open.
# =========================================================

async def require_api_key(request: Request):
    expected = os.environ.get("SENTINEL_API_KEY", "")
    # /health and /metrics are unauthenticated: probes and the in-
    # cluster Prometheus scraper don't carry the app key, and neither
    # path is exposed through the public ingress.
    if not expected or request.url.path in ("/health", "/metrics"):
        return
    provided = request.headers.get("X-API-Key", "")
    if not pysecrets.compare_digest(provided, expected):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing X-API-Key header.",
        )


# =========================================================
# SESSION SCOPE
# Every request is bound to the session named by its
# X-Session-Id header (client-generated UUID, one per
# browser tab). No header -> the "default" session, which
# keeps tests, scripts, and curl usage working.
# =========================================================

async def session_scope(request: Request):
    activate(request.headers.get("X-Session-Id"))


app = FastAPI(dependencies=[Depends(require_api_key), Depends(session_scope)])

# =========================================================
# REQUEST BODY SIZE LIMIT
# Uploads arrive base64-encoded in the /chat JSON body, so
# the cap is set above the per-file ingest limits (base64
# adds ~33%). Oversized requests are rejected before the
# body is read.
# =========================================================

MAX_REQUEST_BYTES = int(os.environ.get("SENTINEL_MAX_REQUEST_MB", "80")) * 1024 * 1024


@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    length = request.headers.get("content-length", "")
    if length.isdigit() and int(length) > MAX_REQUEST_BYTES:
        return JSONResponse(
            status_code=413,
            content={
                "detail": (
                    f"Request body exceeds the "
                    f"{MAX_REQUEST_BYTES // (1024 * 1024)} MB limit."
                )
            },
        )
    return await call_next(request)


# =========================================================
# REQUEST ID — correlation across every log line for a
# request. Added last so it runs OUTERMOST: the id is bound
# before anything else logs and echoed on the response.
# =========================================================

@app.middleware("http")
async def request_id(request: Request, call_next):
    rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
    set_request_id(rid)
    start = time.time()
    response = await call_next(request)
    elapsed = time.time() - start
    response.headers["X-Request-Id"] = rid

    # Metrics — label on the route template (low, fixed cardinality)
    path = request.url.path
    if path not in ("/metrics", "/health"):
        metrics.HTTP_REQUESTS.labels(
            method=request.method, path=path, status=response.status_code
        ).inc()
        metrics.HTTP_LATENCY.labels(method=request.method, path=path).observe(elapsed)
        logger.info("%s %s -> %d in %dms",
                    request.method, path, response.status_code, int(elapsed * 1000))
    return response


# =========================================================
# METRICS ENDPOINT — Prometheus exposition. Scraped on the pod
# port directly; not routed through the public ingress.
# =========================================================

@app.get("/metrics")
async def prometheus_metrics():
    metrics.ACTIVE_SESSIONS.set(len(SESSIONS))
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

# =========================================================
# CORS
# Defaults cover local dev servers. In production behind the
# nginx proxy the app is same-origin and this barely matters,
# but SENTINEL_CORS_ORIGINS (comma-separated) overrides it
# for split-origin deployments.
# =========================================================

DEFAULT_CORS_ORIGINS = (
    "http://localhost:3000,http://127.0.0.1:3000,"
    "http://localhost:5173,http://127.0.0.1:5173"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        # `or` (not a .get default) so an empty env var — e.g. an
        # unset compose variable — still falls back to the defaults
        for origin in (
            os.environ.get("SENTINEL_CORS_ORIGINS") or DEFAULT_CORS_ORIGINS
        ).split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================================
# RATE LIMIT — /chat only
# Every non-canned message is a paid LLM call and a scanner
# run, so /chat gets a fixed-window per-client limit. In-
# process state matches the app's single-worker architecture.
# 0 disables the limit.
# =========================================================

RATE_LIMIT_PER_MINUTE = int(os.environ.get("SENTINEL_RATE_LIMIT_PER_MIN", "20"))

# Number of trusted reverse proxies in front of the app (our nginx
# = 1). The client IP is the Nth-from-last X-Forwarded-For hop —
# everything to the LEFT of that is client-supplied and spoofable,
# so keying on the leftmost value lets a client rotate the header to
# get a fresh bucket per request. Never trust more hops than you
# actually run in front of this.
TRUSTED_PROXY_HOPS = int(os.environ.get("SENTINEL_TRUSTED_PROXY_HOPS", "1"))

_rate_buckets: dict = {}  # client key -> [window, count]


def _client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            # Count from the right: our proxies append their peer's
            # address, so the trusted hop is at -TRUSTED_PROXY_HOPS.
            idx = min(TRUSTED_PROXY_HOPS, len(parts))
            return parts[-idx]
    return request.client.host if request.client else "unknown"


async def rate_limit_chat(request: Request):
    limit = RATE_LIMIT_PER_MINUTE
    if limit <= 0:
        return
    window = int(time.time() // 60)
    # Keep the bucket table from growing unbounded across windows
    if len(_rate_buckets) > 10_000:
        for key in [k for k, v in _rate_buckets.items() if v[0] != window]:
            del _rate_buckets[key]
    bucket = _rate_buckets.setdefault(_client_key(request), [window, 0])
    if bucket[0] != window:
        bucket[0] = window
        bucket[1] = 0
    bucket[1] += 1
    if bucket[1] > limit:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Rate limit exceeded ({limit} chat requests per minute) — "
                "try again shortly."
            ),
        )

# =========================================================
# REQUEST MODEL
# =========================================================

class ChatRequest(BaseModel):
    message: str
    history: list = []
    files: list = []


class RemoveFileRequest(BaseModel):
    name: str

# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "files_in_memory": len(memory["files"]),
        "active_sessions": len(SESSIONS),
        "scanners": scanner_status(),
    }

# =========================================================
# REMOVE FILE
# Deletes a file (or zip project) from memory, workspace,
# and RAG, then re-runs the full scanner registry on the
# remaining files — sidebar and backend stay in sync.
# =========================================================

@app.post("/remove-file")
async def remove_file(req: RemoveFileRequest):
    removed = remove_uploaded(req.name.strip())
    scan = memory.get("scan") or {}
    return {
        "removed": removed,
        "files_in_memory": len(memory["files"]),
        "findings": scan.get("findings", []),
        "scanners": {
            "run": scan.get("tools_run", []),
            "missing": scan.get("tools_missing", []),
        },
    }

# =========================================================
# ASYNC REPO INGEST
# Repo download + full scan is ~40s for a big repo, so it
# runs as a background job instead of holding the request.
# The work is fully blocking (download, subprocess scanners,
# RAG embedding), so it runs on a real worker thread — the
# event loop stays free and it's independent of the request
# lifecycle. The session is re-bound inside the thread (its
# own ContextVar context) so it populates the right state.
# =========================================================

_INGEST_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=4, thread_name_prefix="ingest"
)

def _github_summary(ingested: dict) -> dict:
    scan = memory.get("scan") or {}
    findings = scan.get("findings", [])
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    breakdown = ", ".join(
        f"{counts[s]} {s.lower()}"
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        if counts.get(s)
    ) or "none"
    return {
        "response": (
            f"📦 Ingested **{ingested['name']}** — "
            f"{ingested['files']} files indexed and scanned.\n\n"
            f"Verified scanner findings: **{len(findings)}** ({breakdown}).\n\n"
            f"Ask me anything about the repository, or pick a next step below."
        ),
        "findings": findings,
        "scanners": {
            "run": scan.get("tools_run", []),
            "missing": scan.get("tools_missing", []),
        },
        "repo": ingested,
    }


def _run_github_ingest(job_id, session_id, owner, repo, branch):
    # Runs on an _INGEST_POOL thread. Re-bind the session inside this
    # thread's context so memory, workspace, RAG and redaction all
    # resolve to the caller's state.
    try:
        activate(session_id)
        jobs.set_phase(job_id, "downloading")
        ingested = ingest_github_repo(owner, repo, branch)
        activate(session_id)
        jobs.set_phase(job_id, "scanning")
        jobs.finish_job(job_id, _github_summary(ingested))
    except ValueError as e:
        jobs.fail_job(job_id, f"Could not ingest the repository: {e}")
    except Exception:
        logger.exception("github ingest job failed id=%s", job_id)
        jobs.fail_job(job_id, "Ingestion failed unexpectedly.")


@app.get("/scan-status/{job_id}")
async def scan_status(job_id: str):
    job = jobs.get_job(job_id, current().id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found.")
    return jobs.public_view(job)


# =========================================================
# CHAT ENDPOINT
# =========================================================

@app.post("/chat", dependencies=[Depends(rate_limit_chat)])
async def chat(req: ChatRequest):
    user_message = req.message.strip()

    # =====================================================
    # SAVE FILES
    # Rejected uploads (too large, unsupported, zip bomb/slip,
    # empty archive) are surfaced to the user via finish()
    # instead of failing silently.
    #
    # Runs on a worker thread (to_thread copies the session
    # ContextVar) so the file scan can't block the single event
    # loop — otherwise /health stalls and the liveness probe
    # SIGKILLs the pod mid-scan.
    # =====================================================

    upload_warnings = (
        await asyncio.to_thread(save_uploaded_files, req.files)
        if req.files else []
    )
    # Free-form notes prepended to whatever the turn returns (e.g. "your
    # pasted URL was skipped because you also attached a zip").
    info_notes: list[str] = []

    def finish(payload: dict) -> dict:
        """Prepend any upload rejections + info notes to the response."""
        prefix = ""
        if upload_warnings:
            notes = "\n".join(
                f"- **{w['name']}** — {w['reason']}" for w in upload_warnings
            )
            prefix += f"⚠️ Some uploads were skipped:\n{notes}\n\n"
            payload["upload_warnings"] = upload_warnings
        if info_notes:
            prefix += "\n\n".join(info_notes) + "\n\n"
        if prefix:
            payload["response"] = prefix + payload.get("response", "")
        return payload

    # =====================================================
    # EMPTY MESSAGE
    # A blank / whitespace-only message must never reach the
    # paid LLM. If files were just uploaded, invite analysis;
    # otherwise prompt for input.
    # =====================================================

    if not user_message:
        if memory["files"]:
            return finish({
                "response": (
                    f"Got it — {len(memory['files'])} file(s) in context. "
                    "Ask me to run a security audit, or pick a quick action."
                ),
                "findings": (memory.get("scan") or {}).get("findings", []),
                "scanners": {
                    "run": (memory.get("scan") or {}).get("tools_run", []),
                    "missing": (memory.get("scan") or {}).get("tools_missing", []),
                },
            })
        return finish({
            "response": "Type a question or upload a file to get started.",
        })

    # =====================================================
    # GITHUB URL INGESTION — async
    # Download + scan run as a background job so the request
    # returns immediately with a job_id; the client polls
    # /scan-status/{job_id} and renders findings when done.
    # =====================================================

    github_ref = parse_github_url(user_message)
    ingested_repo = None

    # BOTH a zip AND a repo URL in one message: the attached files win.
    # Scanning both would double-count a "similar" repo and produce
    # mismatched / duplicated findings. Skip the URL, keep analysing the
    # upload, and tell the user how to scan the repo instead. Only applies
    # when at least one file was actually accepted this request.
    accepted_upload = bool(req.files) and len(upload_warnings) < len(req.files)
    if github_ref and accepted_upload:
        owner, repo, branch = github_ref
        label = f"{owner}/{repo}" + (f"@{branch}" if branch else "")
        rejected_names = {w["name"] for w in upload_warnings}
        attached = ", ".join(
            f"**{f.get('name', 'file')}**" for f in req.files
            if isinstance(f, dict) and f.get("name") not in rejected_names
        )
        info_notes.append(
            f"📎 You sent a repo URL and an upload. I'm analysing your "
            f"attached files ({attached}) — the URL `{label}` was skipped. "
            f"Send it on its own (no attachment) to scan the remote repo instead."
        )
        github_ref = None  # fall through to normal file analysis

    if github_ref:
        owner, repo, branch = github_ref
        logger.info("github ingest (async) %s/%s%s",
                    owner, repo, f"@{branch}" if branch else "")
        session_id = current().id
        job_id = jobs.create_job(session_id, "github-ingest")
        _INGEST_POOL.submit(
            _run_github_ingest, job_id, session_id, owner, repo, branch
        )
        label = f"{owner}/{repo}" + (f"@{branch}" if branch else "")
        return finish({
            "response": (
                f"📦 Ingesting **{label}** — downloading and scanning. "
                "Large repos take a little while; findings will appear here "
                "when the scan completes."
            ),
            "job_id": job_id,
            "status": "running",
        })

    # =====================================================
    # INTENT DETECTION
    # All canned intents (greeting, small talk, clear,
    # acknowledgement, off-topic) are answered here without
    # ever calling the LLM.
    # =====================================================

    intent = detect_intent(user_message)
    logger.info("chat intent=%s files=%d msg_len=%d",
                intent, len(memory["files"]), len(user_message))

    # =====================================================
    # GREETING HANDLER
    # =====================================================

    if intent == "greeting":
        if memory["files"]:
            filenames = ", ".join([
                f["name"] for f in memory["files"][:3]
            ])
            more = len(memory["files"]) - 3
            suffix = f" and {more} more" if more > 0 else ""
            return finish({
                "response": (
                    f"Hey! I still have your uploaded files in context "
                    f"({filenames}{suffix}).\n\n"
                    f"What would you like to explore next?\n\n"
                    f"- Security audit\n"
                    f"- Misconfiguration review\n"
                    f"- CI/CD analysis\n"
                    f"- Docker / Kubernetes hardening\n"
                    f"- Terraform inspection"
                )
            })
        return finish({
            "response": (
                "Hey! I'm **AI DevSecOps Sentinel** — an AI DevOps & DevSecOps engineer.\n\n"
                "I can help you with:\n\n"
                "- **File analysis** — upload a Dockerfile, Terraform, Helm chart, "
                "K8s manifests, CI/CD pipeline, a `.zip` — or just paste a GitHub repo URL\n"
                "- **Security audits** — secrets, misconfigurations, vulnerable dependencies\n"
                "- **General DevOps knowledge** — CI/CD, Kubernetes, Docker, Terraform, "
                "ArgoCD, Helm, observability, and more\n\n"
                "Upload some files or ask me anything to get started."
            )
        })

    # =====================================================
    # ACKNOWLEDGEMENT HANDLER
    # Catches: "ok", "cool", "great", "thanks", "nice",
    # "awesome", "yep" etc. — never triggers file analysis.
    # =====================================================

    if intent == "acknowledgement":
        if memory["files"]:
            file_count = len(memory["files"])
            return finish({
                "response": (
                    f"Ready when you are! I have {file_count} file(s) in context.\n\n"
                    f"What would you like to dig into next?\n\n"
                    f"- Security audit\n"
                    f"- Misconfiguration review\n"
                    f"- CI/CD analysis\n"
                    f"- Docker / Kubernetes hardening\n"
                    f"- Terraform inspection"
                )
            })
        return finish({
            "response": "Ready! What DevOps topic can I help you with?"
        })

    # =====================================================
    # OFF-TOPIC HANDLER
    # Catches non-DevOps questions like "who is Geetanjali",
    # "capital of France", "ipl score" etc.
    # =====================================================

    if intent == "off_topic":
        return finish({
            "response": (
                "That is outside my area — I am a DevOps and DevSecOps AI assistant. "
                "I can help with Kubernetes, Docker, Terraform, CI/CD pipelines, "
                "security audits, and infrastructure file analysis. "
                "Feel free to ask anything in that space or upload files for a full security review."
            )
        })

    # =====================================================
    # SMALL TALK HANDLER
    # "how are you", "who are you", "what can you do"
    # =====================================================

    if intent == "small_talk":
        msg = user_message.lower().strip()

        if any(x in msg for x in [
            "how are you", "how's it going", "how are things",
            "you good", "are you ok", "how have you been",
            "how is it going", "hows it going"
        ]):
            return finish({
                "response": (
                    "Running at full capacity. Ready to audit your infrastructure.\n\n"
                    "Upload a file or ask me a DevOps question to get started."
                )
            })

        if any(x in msg for x in [
            "who are you", "what are you", "are you an ai",
            "are you a bot", "are you human", "what is your name",
            "whats your name"
        ]):
            return finish({
                "response": (
                    "I'm **AI DevSecOps Sentinel** — an AI DevOps and DevSecOps engineer.\n\n"
                    "I specialise in:\n\n"
                    "- Auditing Dockerfiles, Terraform, Kubernetes manifests, "
                    "Helm charts, and CI/CD pipelines\n"
                    "- Detecting hardcoded secrets, misconfigurations, and vulnerable dependencies\n"
                    "- Answering DevOps and DevSecOps questions with real examples and code\n\n"
                    "Upload a file, a `.zip`, or paste a GitHub repo URL to get started."
                )
            })

        if any(x in msg for x in [
            "what can you do", "what do you do",
            "your name", "whats your name"
        ]):
            return finish({
                "response": (
                    "I'm **AI DevSecOps Sentinel**.\n\n"
                    "**With uploaded files I can:**\n\n"
                    "- Detect hardcoded secrets — AWS keys, tokens, passwords\n"
                    "- Find misconfigurations — open CIDRs, privileged containers, missing TLS\n"
                    "- Identify vulnerable dependencies with exact version details\n"
                    "- Analyse CI/CD pipelines for insecure patterns\n"
                    "- Cross-reference multiple files for conflicts — "
                    "port mismatches, image inconsistencies\n\n"
                    "**Without files I can:**\n\n"
                    "- Answer any DevOps or DevSecOps question\n"
                    "- Explain Kubernetes, Docker, Terraform, Helm, ArgoCD, GitOps\n"
                    "- Give best practice guidance with real code examples\n\n"
                    "Upload a file or ask me anything."
                )
            })

        return finish({
            "response": (
                "I'm here and ready. What DevOps or DevSecOps topic can I help you with?\n\n"
                "Upload a file for analysis or ask me anything."
            )
        })

    # =====================================================
    # CLEAR HANDLER
    # Clears BOTH the in-memory file store and the RAG
    # vector index — otherwise previously uploaded chunks
    # keep leaking into later analyses via retrieval.
    # =====================================================

    if intent == "clear":
        memory["files"] = []
        memory["last_topic"] = ""
        memory["last_files"] = []
        memory["general_mode"] = False
        memory["rag_cache_key"] = None
        memory["rag_results"] = []
        memory["scan"] = None
        clear_rag()
        clear_workspace()
        clear_secrets()
        return {
            "response": "Context cleared. Upload new files or ask a fresh question."
        }

    # =====================================================
    # BUILD PROMPT + CALL LLM
    # Scanner findings ride along as structured data so the
    # frontend can render them independently of the prose.
    # =====================================================

    # Prompt build (RAG embedding call) + the LLM call are blocking and
    # slow — run them on a worker thread so the event loop stays free for
    # health checks. Code-level redaction: the model sees raw file
    # contents, so scrub secrets from its answer regardless of prompt rules.
    def _analyse():
        prompt = build_prompt(user_message, req.history)
        return scrub_secrets(ask_openai(prompt, req.history))

    answer = await asyncio.to_thread(_analyse)

    # A generation turn ("write me a hardened Dockerfile") returns an
    # example artifact, not an audit. Guarantee the disclaimer in code so
    # the user never mistakes generated output for a scan of their files —
    # the LLM paraphrases the prompt's note unreliably.
    if memory.get("_generation_turn") and "generated example" not in answer.lower():
        answer = answer.rstrip() + (
            "\n\n_This is a generated example. My scanners only run on "
            "uploaded files or a pasted repo — save this file and upload "
            "it if you'd like me to verify it._"
        )

    # Only a genuine file-security-analysis turn (build_prompt MODE 3)
    # carries the findings panel. General-knowledge answers, topic
    # redirects and generation requests must NOT re-surface the previous
    # scan's findings.
    scan = memory.get("scan") or {}
    payload = {"response": answer, "repo": ingested_repo}
    if memory.get("_analysis_turn"):
        payload["findings"] = scan.get("findings", [])
        payload["scanners"] = {
            "run": scan.get("tools_run", []),
            "missing": scan.get("tools_missing", []),
        }
        # Real ingested-file count (ground truth for the report — a repo
        # analysis turn carries no `repo` object, so the client can't
        # otherwise tell 92 files from the single repo sidebar entry).
        payload["files_scanned"] = len(memory["files"])
    return finish(payload)

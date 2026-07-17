# =========================================================
# PROMETHEUS METRICS
# One process, one default registry (the app runs a single
# uvicorn worker by design). Exposed on /metrics — scraped by
# Prometheus directly on the pod port, NOT proxied through the
# nginx ingress, so it stays internal-only.
#
# Metric names are prefixed `sentinel_`. Label cardinality is
# kept low on purpose (fixed route paths, scanner tool names,
# severities) so this is safe to always-on.
# =========================================================

from prometheus_client import Counter, Gauge, Histogram

# ---- HTTP ----
HTTP_REQUESTS = Counter(
    "sentinel_http_requests_total",
    "HTTP requests handled",
    ["method", "path", "status"],
)
HTTP_LATENCY = Histogram(
    "sentinel_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "path"],
)

# ---- Scanners ----
SCAN_DURATION = Histogram(
    "sentinel_scan_duration_seconds",
    "Per-tool scan duration",
    ["tool"],
    # scans range from ~1s (gitleaks) to minutes (trivy first run)
    buckets=(0.5, 1, 2, 5, 10, 30, 60, 120, 300),
)
SCAN_FINDINGS = Counter(
    "sentinel_scan_findings_total",
    "Findings produced, by severity",
    ["severity"],
)
SCANNER_ERRORS = Counter(
    "sentinel_scanner_errors_total",
    "Scanner crashes (counted as coverage gaps)",
    ["tool"],
)

# ---- LLM ----
LLM_LATENCY = Histogram(
    "sentinel_llm_request_duration_seconds",
    "LLM chat-completion latency",
    buckets=(0.5, 1, 2, 5, 10, 20, 40, 80),
)
LLM_TOKENS = Counter(
    "sentinel_llm_tokens_total",
    "LLM tokens consumed",
    ["kind"],  # prompt | completion
)
LLM_ERRORS = Counter(
    "sentinel_llm_errors_total",
    "LLM call failures",
    ["reason"],  # rate_limit | other
)

# ---- Ingest / sessions ----
FILES_INGESTED = Counter(
    "sentinel_files_ingested_total", "Files successfully ingested"
)
UPLOADS_REJECTED = Counter(
    "sentinel_uploads_rejected_total", "Uploads rejected, by reason", ["reason"]
)
ACTIVE_SESSIONS = Gauge(
    "sentinel_active_sessions", "Live sessions currently in memory"
)

# Design Decisions & Lessons

Why this system is built the way it is — the reasoning that isn't obvious
from reading the code, the limits it has, and what field testing taught.

Written so the decisions stay defensible months later, and so anyone
picking this up (including future me) doesn't have to reverse-engineer the
"why" from the "what".

---

## 1. Key decisions

### Scanners are ground truth; the LLM reasons on top of them

Findings come from nine deterministic tools (gitleaks, checkov, trivy,
hadolint, semgrep, kubesec, shellcheck, actionlint, plus a built-in
prompt-injection guard). The LLM never invents a finding — it correlates,
prioritises, explains exploitability and blast radius, and writes fixes.

**Why:** security output has to be reproducible and defensible. A finding
you can't re-derive with a tool is a finding you can't act on. It also
makes the model swappable: a different LLM changes the *narrative*, never
the *findings*.

**Trade-off:** the tools bound what's detected — gitleaks won't flag
`secret = "password"` because it's low-entropy. That's why the report
separates **scanner-verified** from **AI-identified** findings rather than
pretending they're the same thing.

---

### Blocking work runs on worker threads

Scans, prompt building and LLM calls run via `asyncio.to_thread`, not
inline in the async handler.

**Why:** the backend is a single-worker FastAPI process. A synchronous
scan blocked the event loop, so `/health` stopped responding, so the
Kubernetes **liveness probe SIGKILLed the pod mid-scan** — which looked
like random crashes under load. Moving blocking work off the loop fixed
the crashes; the tuned probe thresholds are defence-in-depth, not the fix.

**Trade-off:** threading complexity — the session `ContextVar` has to be
re-bound inside worker threads or state resolves to the wrong session.

---

### Repository ingestion is an async job, not a request

Pasting a repo URL creates a background job; the client polls
`/scan-status/{job_id}`.

**Why:** downloading and scanning a real repo takes ~25–60s, well past
ingress/request timeouts — it was returning 504s.

**Trade-off:** job state is in memory, so an in-flight scan dies with the
pod (see *Limitations*).

---

### Dependency directories are stripped before scanning

`.venv`, `node_modules`, `.git`, `.terraform`, `dist`, `vendor`, … are
removed from the workspace before the scanners run.

**Why:** they dominated everything. Scans took minutes, findings were
mostly third-party noise, and — subtly — the *same project* scanned as a
zip vs. a repo produced **different results**, because the bundles carried
different vendored trees. Stripping them made scans fast (~27s on a
4,500-file zip), clean, and consistent.

**Trade-off:** none worth keeping. Vendored dependency code isn't the
user's code; CVEs in dependencies are caught by trivy from lockfiles.

---

### A repo or a `.zip` is a whole project and resets the session

Ingesting a repo URL or a zip clears prior files, workspace, RAG index and
secret registry first. Loose individual files still accumulate.

**Why:** a real report for `k8s-upgrade-advisor` came back containing
findings from a *different* project analysed earlier in the same session —
the scanner ran over the whole accumulated workspace. A security report
that attributes one project's vulnerabilities to another isn't untidy,
it's **wrong**.

**Trade-off:** you can't analyse a zip alongside previously uploaded loose
files. Multi-file analysis still works by uploading files individually.

---

### The UI renders from scanner JSON, not from LLM prose

The findings panel and severity dashboard are built from the structured
findings the backend returns. The LLM's text is parsed for the richer
per-file cards, but the UI never *depends* on that parse succeeding.

**Why:** model output drifts. Early on, a response that didn't emit the
exact `## File Analysis:` header collapsed the whole view into raw
markdown — shell-script analyses looked broken while Terraform looked
fine. Deriving the dashboard from deterministic data makes the UI robust
to any model's formatting.

**Trade-off:** two rendering paths to maintain.

---

### The LLM is configuration, not code

`SENTINEL_LLM_MODEL`, `OPENAI_BASE_URL`, `SENTINEL_LLM_MAX_TOKENS` are env
vars surfaced as Helm values.

**Why:** swapping models — or providers, via any OpenAI-compatible
endpoint — should never be a code change. Combined with scanner-grounded
findings, a swap can only affect narrative quality.

---

### The Helm chart is cloud-agnostic

Standard `ingress-nginx`, a PVC on the default StorageClass, a plain
Secret. No provider-specific annotations.

**Why:** the same `helm upgrade --install` runs on EKS, AKS, GKE or
on-prem. Only cluster provisioning and CI auth differ per platform.

**Trade-off:** foregoes some cloud-native conveniences (e.g. GCE ingress,
managed certs) in exchange for portability.

---

### Every deploy is gated by three test layers

Unit/integration (`pytest`) → wire smoke test through the ingress →
Playwright browser e2e against the live deployment.

**Why:** the bugs that mattered most were only visible end-to-end — nginx
not proxying `/scan-status`, ingress body-size limits rejecting uploads,
UI rendering regressions. Unit tests can't see any of those.

**Trade-off:** slower deploys and a few LLM calls per deploy. Worth it.

---

## 2. Limitations & future work

**All session state is in-process.** Sessions, the FAISS index, findings
and job state live in memory in a single-worker pod, and the scan
workspace is a local directory the scanner subprocesses read from.

That means, honestly:

- A pod restart loses conversation context and in-flight scans
- The service can't run more than one replica — sessions wouldn't be shared
- The workspace-on-disk coupling is the real constraint: with N replicas a
  request can land on a pod that doesn't have the files

**This was a deliberate choice**, not an oversight: it keeps the system
dependency-free and fast to run, which suits a single-tenant demo and
lets the whole stack come up with `docker compose up`. Externalising it
is well-understood work, not research:

| Change | Effort | Unlocks | Added infra cost |
|---|---|---|---|
| Job state → Redis (same pod) | 1–2 days | In-flight scans survive restart | Redis only |
| RAG → pgvector | 3–4 days | Shared, persistent index | ~$25–70/mo |
| Sessions → Redis + workspace re-materialisation | 4–6 days | True horizontal scaling | ~$35–50/mo |
| Jobs → real queue + worker deployment | 4–6 days | Scans off the API pod | (shares Redis) |

The workspace fix — rebuilding the directory on a cache miss from file
contents already held in session state — is ~2 days and is a prerequisite
for both scaling and a separate worker, which is why doing these together
costs less than doing them separately.

**Other known gaps:**

- **Auth is a single shared API key.** No per-user identity or tenancy;
  isolation is per browser tab via a session id.
- **Rate limiting counts requests per IP**, not tokens per user, so it
  caps abuse but not spend.
- **No scan-result caching** — re-analysing the same repo re-runs
  everything.
- **Jenkins pipelines are the weakest CI coverage.** checkov covers
  GitLab CI, Azure Pipelines, CircleCI and Bitbucket; actionlint covers
  GitHub Actions in depth. There's no good offline Jenkinsfile security
  scanner worth adding — custom semgrep Groovy rules would be the route.

---

## 3. Lessons from field testing

Almost every serious bug here was found by *using the deployed app*, not
by writing more tests. The tests came after, to pin the fix.

| Symptom | Root cause | Lesson |
|---|---|---|
| Pods restarting under load | Sync scan blocked the event loop → `/health` stalled → liveness probe SIGKILL | A health check that shares a thread with real work isn't a health check |
| Uploads failing at ~1 MB | ingress-nginx default `proxy-body-size` | The platform has defaults your app never sees |
| Repo URLs returning 504 | Scan outlived the request timeout | Long work belongs in a job, not a request |
| Zip and repo scans of one project disagreeing | Vendored dirs differed between bundles | Scan *your* code, not what you vendored |
| "yes audit" answered with a canned menu | Matched the "yes" acknowledgement prefix before analysis routing | Intent matching on prefixes swallows commands |
| A Markdown file scored as a vulnerability target | Everything was treated as scannable | Not every file has a security surface |
| Shell analyses rendering as raw markdown | Parser required one exact header the model didn't always emit | Never let UI structure depend on model formatting |
| Report cut off mid-finding | Multi-file output exceeded `max_tokens` | Output limits bind sooner than you think |
| One repo's report containing another's findings | Ingest appended to an accumulated workspace | Scope isn't automatic — reset it explicitly |
| A fix "not deployed" | CI silently didn't trigger; and a cached tab session showed stale UI | Verify what's *live*, not what's merged |

Two habits that paid off repeatedly:

1. **Check the live version, not the merge.** Comparing the deployed image
   SHA against the last code commit caught a fix that had merged but never
   built.
2. **Probe systematically instead of clicking.** Running ~50 realistic
   phrasings through the router in one script found three intent bugs in
   seconds that manual testing would have taken hours to surface.

---

## 4. If I picked this up again

In priority order, and none of it is required for the system to be useful:

1. Externalise session state (table above) — the only change that lifts a
   real architectural ceiling
2. Per-user auth and tenancy, if it ever serves more than one person
3. Token-based quotas to bound LLM spend
4. Custom semgrep rules for Jenkinsfiles

Deliberately **not** planned: more scanners. The nine in place cover
secrets, IaC, dependencies, containers, Kubernetes, application code,
shell and CI/CD without overlap. Adding redundant tools (tfsec, grype,
kube-score) would raise the finding count without raising signal — and
noise is what makes security tooling get ignored.

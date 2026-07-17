# Troubleshooting

## Analysis / scanners

**`/health` shows a scanner as `false`.**
That tool isn't on the `PATH`. Missing scanners are a coverage gap,
not a failure — the rest of the pipeline runs and the gap is noted in
the analysis. Install the tool (see [SETUP.md](SETUP.md)) to close it.

**First scan is slow.**
trivy downloads its CVE database and semgrep its ruleset on first run.
In containers the `scanner-cache` volume persists these between
restarts.

**"An error occurred while contacting the AI" / rate-limit message.**
The LLM call failed. Common causes: no/invalid `OPENAI_API_KEY`, or a
very large repo pushing the prompt over the model's tokens-per-minute
limit. Scanner findings are unaffected — narrow the question to
specific files, or wait a minute. Check the backend logs (filter by
the `X-Request-Id` from the response).

**An uploaded file "did nothing".**
It was rejected — the response includes an `upload_warnings` block with
the reason (too large, unsupported type, empty, zip bomb/slip).
Supported types are listed in the README.

## Frontend

**Blank white page over plain HTTP.**
`crypto.randomUUID` only exists in secure contexts. Serve the app over
HTTPS (see the TLS section in [DEPLOYMENT.md](DEPLOYMENT.md)); the app
also carries a fallback, so a hard refresh usually fixes a stale bundle.

**"Not Secure" badge.**
The default LoadBalancer serves HTTP. Enable TLS via cert-manager +
Let's Encrypt (DEPLOYMENT.md → HTTPS/TLS).

## Deployment (GKE)

**cert-manager issuer fails: "certificate signed by unknown authority".**
On Autopilot, cert-manager must use its own namespace for leader
election: install with `--set global.leaderElection.namespace=cert-manager`.
Warden blocks the default `kube-system` leases otherwise.

**Rate limit not triggering behind the ingress.**
The ingress controller must preserve the client IP:
`--set controller.service.externalTrafficPolicy=Local`. Otherwise the
source is SNAT'd to a node IP and all clients share one bucket.

**A `helm upgrade` fails on a newly added value key.**
The `--reuse-values` caveat: it doesn't pull new chart defaults. Use
`--reset-then-reuse-values` once when introducing a value.

**Supply-chain gate blocks a deploy on a CVE.**
Working as intended — a fixable critical shouldn't ship. If it's in a
bundled third-party binary already at its latest release, add a
time-boxed exception to `.trivyignore.yaml` with justification.

#!/usr/bin/env python3
# =========================================================
# POST-DEPLOY SMOKE TEST
# Runs against the LIVE deployment after a rollout to catch
# "works in code, broken in the wire" regressions — the class
# unit tests can't see (nginx routing, ingress body/timeout
# limits, TLS). Stdlib only (urllib) so CI needs no pip.
#
#   python3 deploy/smoke_test.py <base-url> <api-key>
#
# No LLM calls — only health, scanner, routing and auth paths,
# so it's fast and free to run on every deploy. Exits non-zero
# on the first real failure, failing the pipeline.
# =========================================================

import base64
import io
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
import zipfile

BASE = sys.argv[1].rstrip("/")
KEY = sys.argv[2] if len(sys.argv) > 2 else ""
PASS = 0
FAILS = []


def call(method, path, body=None, key=KEY, sid=None, timeout=30):
    """Return (status, content_type, text). Never raises on HTTP error."""
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if key:
        req.add_header("X-API-Key", key)
    req.add_header("X-Session-Id", sid or ("smoke-" + uuid.uuid4().hex[:8]))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.headers.get("Content-Type", ""), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", ""), e.read().decode()


def check(name, cond, detail=""):
    global PASS
    if cond:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAILS.append(name)
        print(f"  FAIL {name} — {detail}")


def b64(raw):
    return base64.b64encode(raw.encode() if isinstance(raw, str) else raw).decode()


# Wait for the deployment to answer (ingress/LB may lag the rollout).
for _ in range(30):
    try:
        st, _, _ = call("GET", "/health", key="")
        if st == 200:
            break
    except Exception:
        pass
    time.sleep(4)

print(f"Smoke test against {BASE}")

# 1. health + all scanners present
st, _, txt = call("GET", "/health", key="")
h = json.loads(txt) if st == 200 else {}
check("health 200 + 7 scanners",
      st == 200 and sum(h.get("scanners", {}).values()) == 7,
      f"status={st} scanners={h.get('scanners')}")

# 2. /scan-status is proxied and returns JSON (regression guard for the
#    nginx routing gap that broke async repo ingest end-to-end)
st, ctype, _ = call("GET", "/scan-status/does-not-exist")
check("/scan-status proxied -> JSON 404 (not SPA html)",
      st == 404 and "application/json" in ctype,
      f"status={st} content-type={ctype}")

# 3. auth
if KEY:
    st, _, _ = call("POST", "/chat", {"message": "hi"}, key="")
    check("no API key -> 401", st == 401, f"status={st}")
    st, _, _ = call("POST", "/chat", {"message": "hi"}, key="wrong-key")
    check("bad API key -> 401", st == 401, f"status={st}")

# 4. malformed body -> 422 (not 500)
try:
    req = urllib.request.Request(f"{BASE}/chat", data=b"{bad", method="POST")
    req.add_header("Content-Type", "application/json")
    if KEY:
        req.add_header("X-API-Key", KEY)
    req.add_header("X-Session-Id", "smoke-malformed")
    urllib.request.urlopen(req, timeout=15)
    st = 200
except urllib.error.HTTPError as e:
    st = e.code
check("malformed JSON -> 422", st == 422, f"status={st}")

# 5. upload above the ingress-nginx default 1 MB (regression guard for the
#    413 body-size limit) — a 2 MB body must reach the backend
big = {"message": "ok", "files": [{"name": "big.txt", "content": b64(b"x" * 2_000_000)}]}
st, _, _ = call("POST", "/chat", big, sid="smoke-big", timeout=60)
check("2 MB upload not 413 (ingress body-size)", st == 200, f"status={st}")

# 6. real file upload runs the scanner pipeline end-to-end
tf = 'provider "aws" { access_key = "AKIA7QF3MZX9WKLPNV23" }\n' \
     'resource "aws_security_group" "w" { ingress { cidr_blocks = ["0.0.0.0/0"] } }\n'
sid = "smoke-file-" + uuid.uuid4().hex[:6]
st, _, _ = call("POST", "/chat",
                {"message": "ok", "files": [{"name": "s.tf", "content": b64(tf)}]},
                sid=sid, timeout=90)
# removing a non-existent file returns the cached scan findings (no LLM)
st2, _, txt2 = call("POST", "/remove-file", {"name": "none"}, sid=sid, timeout=30)
findings = json.loads(txt2).get("findings", []) if st2 == 200 else []
check("file upload -> scanner findings", st == 200 and len(findings) > 0,
      f"upload={st} findings={len(findings)}")

# 7. async repo ingest end-to-end (async job + /scan-status proxy +
#    scanner pipeline) on a tiny always-available repo — no LLM
sid = "smoke-repo-" + uuid.uuid4().hex[:6]
st, _, txt = call("POST", "/chat",
                  {"message": "https://github.com/octocat/Hello-World"},
                  sid=sid, timeout=30)
d = json.loads(txt) if st == 200 else {}
job = d.get("job_id")
ok = False
if job and d.get("status") == "running":
    for _ in range(30):
        s2, _, t2 = call("GET", f"/scan-status/{job}", sid=sid, timeout=15)
        j = json.loads(t2) if s2 == 200 else {}
        if j.get("status") in ("done", "error"):
            ok = j.get("status") == "done"
            break
        time.sleep(3)
check("async repo ingest completes", ok, f"kickoff={st} job={bool(job)}")

print(f"\nSMOKE: {PASS} passed, {len(FAILS)} failed")
if FAILS:
    print("FAILURES:", FAILS)
    sys.exit(1)

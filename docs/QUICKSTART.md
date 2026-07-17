# Quick Start

Two ways to run it in a few minutes.

## Option A — docker compose (one command)

```bash
# .env in the repo root:
#   OPENAI_API_KEY=sk-...        (required for AI answers)
#   SENTINEL_API_KEY=change-me   (recommended)

docker compose up --build -d
# UI + API on http://localhost
```

The backend image bundles all six scanners at pinned versions, so
there's nothing else to install. See [DEPLOYMENT.md](DEPLOYMENT.md)
for configuration and the GKE path.

## Option B — local dev

```bash
# backend
python -m venv backend/.venv && source backend/.venv/bin/activate
pip install -r requirements.txt
echo "OPENAI_API_KEY=sk-..." > .env
uvicorn backend.main:app --reload --port 8000

# scanners (any subset; missing ones are reported as coverage gaps)
brew install gitleaks checkov trivy hadolint semgrep

# frontend (new terminal)
cd frontend && npm install && npm run dev   # http://localhost:3000
```

## First analysis

1. Open the UI.
2. Drag in a `Dockerfile`, `.tf`, K8s manifest, or a `.zip` — or paste
   a public GitHub repo URL in the chat.
3. Ask: *"audit this for secrets and misconfigurations."*

You'll get scanner-verified findings (severity, file:line, redacted
evidence) plus an AI analysis grounded in them — with compliance
mapping, exploitability, and copy-pasteable fixes.

Without any files, it also answers general DevOps/DevSecOps questions.

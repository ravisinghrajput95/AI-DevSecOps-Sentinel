# Contributing

Thanks for your interest in AI DevSecOps Sentinel. This guide covers
the local setup and the conventions the project follows.

## Local setup

**Backend** (Python 3.12+):

```bash
python -m venv backend/.venv
source backend/.venv/bin/activate
pip install -r requirements.txt

# The deterministic scanners (any subset works — missing ones are
# reported as coverage gaps, not failures):
brew install gitleaks checkov trivy hadolint semgrep
# kubesec has no brew formula — grab the release binary:
#   https://github.com/controlplaneio/kubesec/releases

# A .env at the repo root with your key enables the LLM features:
echo "OPENAI_API_KEY=sk-..." > .env

uvicorn backend.main:app --reload --port 8000
```

**Frontend** (Node 22+):

```bash
cd frontend && npm install && npm run dev   # http://localhost:3000
```

See [docs/SETUP.md](docs/SETUP.md) for the full setup and
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for container/GKE deployment.

## Tests

```bash
python -m pytest tests/ -q      # backend (110+ tests)
cd frontend && npx eslint .     # frontend lint
```

The full suite must pass before a PR merges. Scanner-dependent
integration tests skip automatically when a scanner isn't installed.

## How CI works

Per-stack, path-filtered pipelines (see `.github/workflows/`):

- **Backend CI** — tests → image build + smoke test → supply-chain
  gate (SBOM + trivy scan + cosign sign) → Helm deploy. Only pushes to
  `main` build/deploy; PRs run tests only.
- **Frontend CI** — lint + build → image → deploy, same shape.
- **Secret Scan** — gitleaks over the whole history, every push.
- **Detection Benchmark** / **AI Eval** — measure scanner + LLM
  quality (see `evals/`).

## Conventions

- **Branch** off `main`; open a PR. `main` is protected by CI.
- **Commits** explain the *why*, not just the *what*. Keep them focused.
- **Security-sensitive files** (scanners, redaction, prompts, CI,
  deploy, infra) have `CODEOWNERS` review routing — expect scrutiny.
- **Never commit secrets.** The self-scan will catch them; deliberately
  fake fixtures live under `tests/` and `evals/ai_eval.py`, which are
  allowlisted in `.gitleaks.toml`.
- **New chart values**: remember the `helm --reuse-values` caveat —
  document a one-time `--reset-then-reuse-values` when adding keys.

## Reporting security issues

This is a portfolio/learning project. For a real vulnerability, open a
private security advisory on GitHub rather than a public issue.

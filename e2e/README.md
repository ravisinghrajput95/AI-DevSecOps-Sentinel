# Sentinel end-to-end tests (Playwright)

Drives the real UI in a headless browser against a running deployment.
The deployed frontend has its API key baked in, so no secrets are needed here.

## Run

```bash
cd e2e
npm install
npx playwright install chromium
npm test                      # targets the live app by default
BASE_URL=http://localhost:3000 npm test   # or a local dev server
```

Tests run serially on one worker because the backend rate-limits
20 requests/min per client IP. Each test uses an isolated browser
context so file context never leaks between tests.

## Coverage
- Greeting self-identifies as an AI engineer
- Upload Terraform → analyze → verified findings panel + report download
- Generation request renders the "generated example" note as italic
  (regression guard for the `_italic_` renderer)

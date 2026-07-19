import { test, expect } from "@playwright/test";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TF_FIXTURE = path.join(__dirname, "..", "fixtures", "main.tf");
const MD_FIXTURE = path.join(__dirname, "..", "fixtures", "CHANGELOG.md");
const SH_FIXTURE = path.join(__dirname, "..", "fixtures", "deploy.sh");

// Each test runs in a fresh browser context (isolated session/localStorage),
// so they don't leak file context into each other. They share one worker and
// run serially because the backend rate-limits 20 req/min per client IP.

async function send(page, text) {
  const box = page.getByPlaceholder(/Ask anything/i);
  await box.click();
  await box.fill(text);
  await page.getByRole("button", { name: "Send" }).click();
}

test("greeting identifies as an AI engineer (#1)", async ({ page }) => {
  await page.goto("/");
  await send(page, "hello");
  // Unique to the greeting response — not the sidebar logo text.
  await expect(page.getByText(/an AI DevOps & DevSecOps engineer/i)).toBeVisible({
    timeout: 60_000,
  });
});

test("upload Terraform → analyze → findings panel + report download", async ({ page }) => {
  await page.goto("/");

  // The file input is hidden behind "Click or drop files"; drive it directly.
  await page.locator('input[type="file"]').setInputFiles(TF_FIXTURE);
  await expect(page.getByText("main.tf").first()).toBeVisible({ timeout: 15_000 });

  await send(page, "audit this file for security issues");

  // Deterministic scanner panel must render (ground-truth findings).
  await expect(page.getByText(/Verified Scanner Findings/i).first()).toBeVisible({
    timeout: 90_000,
  });
  // The hardcoded AWS key + open CIDR should surface at least one finding.
  await expect(page.getByText(/Download Report \(\.md\)/i).first()).toBeVisible({
    timeout: 15_000,
  });
});

test('"yes audit" on an uploaded file triggers the scan (not a canned reply)', async ({ page }) => {
  await page.goto("/");
  await page.locator('input[type="file"]').setInputFiles(TF_FIXTURE);
  await expect(page.getByText("main.tf").first()).toBeVisible({ timeout: 15_000 });

  // An ack word + an explicit command must run the analysis, not answer
  // "Ready when you are…". Regression guard for the intent-routing bug.
  await send(page, "yes audit");
  await expect(page.getByText(/Verified Scanner Findings/i).first()).toBeVisible({
    timeout: 90_000,
  });
  await expect(page.getByText(/Ready when you are/i)).toHaveCount(0);
});

test("documentation file shows a doc note, not a vulnerability dashboard", async ({ page }) => {
  await page.goto("/");
  await page.locator('input[type="file"]').setInputFiles(MD_FIXTURE);
  await expect(page.getByText("CHANGELOG.md").first()).toBeVisible({ timeout: 15_000 });

  await send(page, "analyse");
  // A clean doc must present as documentation, not a Critical/High/Medium/Low grid.
  await expect(page.getByText(/no security-relevant configuration/i)).toBeVisible({
    timeout: 90_000,
  });
  await expect(page.getByText(/Repository Summary/i)).toHaveCount(0);
});

test("shell-script analysis renders structured UI, not raw markdown", async ({ page }) => {
  await page.goto("/");
  await page.locator('input[type="file"]').setInputFiles(SH_FIXTURE);
  await expect(page.getByText("deploy.sh").first()).toBeVisible({ timeout: 15_000 });

  await send(page, "analyse");
  // Structured dashboard must render (not a flat prose fallback)...
  await expect(page.getByText(/Repository Summary/i).first()).toBeVisible({
    timeout: 90_000,
  });
  // ...and raw "#### Critical/High" markdown must never leak into the UI.
  await expect(page.getByText(/#### (Critical|High|Medium|Low)/)).toHaveCount(0);
});

test("targeted follow-up question still renders the dashboard (uniform UI)", async ({ page }) => {
  await page.goto("/");
  await page.locator('input[type="file"]').setInputFiles(TF_FIXTURE);
  await expect(page.getByText("main.tf").first()).toBeVisible({ timeout: 15_000 });
  await send(page, "audit this file for security issues");
  await expect(page.getByText(/Repository Summary/i).first()).toBeVisible({ timeout: 90_000 });

  // A focused action-style question (like the quick-action / follow-up
  // buttons) must ALSO render the dashboard + findings panel, not a plain
  // prose wall — the whole point of the uniform-UI fix.
  await send(page, "are there hardcoded secrets in this file?");
  // wait for a second assistant turn, then confirm a dashboard is present in it
  await page.waitForTimeout(3000);
  await expect(page.getByText(/Repository Summary/i).last()).toBeVisible({ timeout: 90_000 });
  await expect(page.getByText(/Verified Scanner Findings/i).last()).toBeVisible({ timeout: 10_000 });
});

test("generation note renders as italic, not literal underscores (#6)", async ({ page }) => {
  await page.goto("/");
  await send(page, "write me a non-vulnerable Dockerfile for a python app");

  // The generated-example note must be present and human-readable...
  await expect(page.getByText(/This is a generated example/i)).toBeVisible({
    timeout: 90_000,
  });
  // ...and must NOT show the raw markdown underscores that the old renderer left.
  await expect(page.getByText("_This is a generated example")).toHaveCount(0);
});

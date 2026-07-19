import { defineConfig, devices } from "@playwright/test";

// Target the live app by default; override with BASE_URL for local/staging.
// The deployed frontend has its API key baked in, so a real browser drives
// the true end-to-end path with no secret handling in the test.
const BASE_URL = process.env.BASE_URL || "https://34-132-100-49.sslip.io";

export default defineConfig({
  testDir: "./tests",
  // Real LLM latency: give each assertion room, but keep the whole run bounded.
  timeout: 120_000,
  expect: { timeout: 60_000 },
  fullyParallel: false, // shared per-IP rate limit (20/min) — run serially
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: BASE_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    ignoreHTTPSErrors: true,
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
});

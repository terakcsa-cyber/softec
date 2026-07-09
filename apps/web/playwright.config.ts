import { defineConfig, devices } from "@playwright/test";

const webBase = process.env.E2E_WEB_URL ?? "http://127.0.0.1:3001";

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  retries: process.env.CI ? 1 : 0,
  use: {
    baseURL: webBase,
    trace: "on-first-retry"
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: process.env.E2E_SKIP_WEB_SERVER
    ? undefined
    : {
        command: "pnpm --filter @vuln-intel/web start",
        url: webBase,
        reuseExistingServer: !process.env.CI,
        timeout: 120_000
      }
});

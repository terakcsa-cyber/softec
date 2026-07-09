import { test, expect } from "@playwright/test";

const apiBase = process.env.E2E_API_URL ?? "http://127.0.0.1:4001/api";

test.describe("smoke", () => {
  test("api health", async ({ request }) => {
    const res = await request.get(`${apiBase}/health`);
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.ok).toBe(true);
  });

  test("web bff health", async ({ request }) => {
    const res = await request.get("/api/health");
    expect(res.ok()).toBeTruthy();
  });

  test("login page loads", async ({ page }) => {
    await page.goto("/login");
    await expect(page.locator("body")).toContainText(/вход|login|email|пароль|password/i);
  });

  test("metrics endpoint when api up", async ({ request }) => {
    const res = await request.get(`${apiBase}/metrics`);
    if (res.status() === 401) {
      test.skip(true, "METRICS_BEARER required");
    }
    expect(res.ok()).toBeTruthy();
    const text = await res.text();
    expect(text).toContain("vuln_");
  });
});

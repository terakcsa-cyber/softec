import { test, expect } from "@playwright/test";
import { apiBase, apiLogin, authHeaders } from "./helpers/auth";

const adminEmail = process.env.E2E_ADMIN_EMAIL?.trim();
const adminPassword = process.env.E2E_ADMIN_PASSWORD ?? "";
const viewerEmail = process.env.E2E_VIEWER_EMAIL?.trim();
const viewerPassword = process.env.E2E_VIEWER_PASSWORD ?? "";

test.describe("api security", () => {
  test("admin can read reconciliation", async ({ request }) => {
    test.skip(!adminEmail || !adminPassword, "Set E2E_ADMIN_EMAIL and E2E_ADMIN_PASSWORD");
    const token = await apiLogin(request, adminEmail!, adminPassword);
    const res = await request.get(`${apiBase}/stats/reconciliation`, { headers: authHeaders(token) });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(Array.isArray(body.sources)).toBe(true);
  });

  test("viewer cannot POST dlq retry", async ({ request }) => {
    test.skip(!viewerEmail || !viewerPassword, "Set E2E_VIEWER_EMAIL and E2E_VIEWER_PASSWORD");
    const token = await apiLogin(request, viewerEmail!, viewerPassword);
    const res = await request.post(`${apiBase}/stats/dlq/retry?queue=dlq.ai.enrich&limit=1`, {
      headers: authHeaders(token)
    });
    expect(res.status()).toBe(403);
  });

  test("unauthenticated cannot access queue stats", async ({ request }) => {
    const res = await request.get(`${apiBase}/stats/queue`);
    expect(res.status()).toBe(401);
  });
});

test.describe("digest prepare flow", () => {
  test("admin prepare returns jobId and status endpoint responds", async ({ request }) => {
    test.skip(!adminEmail || !adminPassword, "Set E2E_ADMIN_EMAIL and E2E_ADMIN_PASSWORD");
    const token = await apiLogin(request, adminEmail!, adminPassword);
    const prep = await request.post(`${apiBase}/stats/threat-digest/prepare?hotLimit=3`, {
      headers: authHeaders(token)
    });
    expect(prep.ok()).toBeTruthy();
    const body = (await prep.json()) as { ok?: boolean; jobId?: string };
    expect(body.ok).not.toBe(false);
    expect(body.jobId).toBeTruthy();

    const status = await request.get(
      `${apiBase}/stats/threat-digest/prepare/status?jobId=${encodeURIComponent(body.jobId!)}`,
      { headers: authHeaders(token) }
    );
    expect(status.ok()).toBeTruthy();
    const st = (await status.json()) as { jobId?: string; status?: string };
    expect(st.jobId).toBe(body.jobId);
    expect(st.status).toBeTruthy();
  });
});

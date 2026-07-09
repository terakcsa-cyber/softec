import { APIRequestContext, expect } from "@playwright/test";

const apiBase = process.env.E2E_API_URL ?? "http://127.0.0.1:4001/api";

export async function apiLogin(
  request: APIRequestContext,
  email: string,
  password: string
): Promise<string> {
  const res = await request.post(`${apiBase}/auth/login`, {
    data: { email, password },
    headers: { accept: "application/json", "content-type": "application/json" }
  });
  expect(res.ok()).toBeTruthy();
  const body = (await res.json()) as { accessToken?: string; requiresTotp?: boolean };
  if (body.requiresTotp) {
    throw new Error("E2E user has TOTP enabled — disable for test account");
  }
  expect(body.accessToken).toBeTruthy();
  return body.accessToken!;
}

export function authHeaders(token: string) {
  return { authorization: `Bearer ${token}`, accept: "application/json" };
}

export { apiBase };

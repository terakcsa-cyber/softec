const ACCESS = "vip:access";
const REFRESH = "vip:refresh";

export function getStoredAccessToken(): string | null {
  if (typeof sessionStorage === "undefined") return null;
  return sessionStorage.getItem(ACCESS);
}

export function getStoredRefreshToken(): string | null {
  if (typeof sessionStorage === "undefined") return null;
  return sessionStorage.getItem(REFRESH);
}

export function setStoredTokens(access: string, refresh: string): void {
  sessionStorage.setItem(ACCESS, access);
  sessionStorage.setItem(REFRESH, refresh);
}

export function clearStoredTokens(): void {
  sessionStorage.removeItem(ACCESS);
  sessionStorage.removeItem(REFRESH);
}

/** Email и роль из access JWT. Подпись не проверяется: это только чтобы не держать экран, пока /me не ответил. */
export function readAccessIdentity(token: string | null | undefined): { id: string; email: string; role?: string } | null {
  if (!token) return null;
  const exp = getAccessTokenExpiresAtMs(token);
  if (exp != null && exp <= Date.now()) return null;
  try {
    const parts = token.split(".");
    if (parts.length < 2) return null;
    const payload = JSON.parse(atob(parts[1]!.replace(/-/g, "+").replace(/_/g, "/"))) as {
      sub?: unknown;
      email?: unknown;
      role?: unknown;
      typ?: unknown;
    };
    if (payload.typ !== "access" || typeof payload.email !== "string" || typeof payload.sub !== "string") return null;
    return { id: payload.sub, email: payload.email, role: typeof payload.role === "string" ? payload.role : undefined };
  } catch {
    return null;
  }
}

/** Decode JWT `exp` (seconds) without verifying signature — client skew helper only. */
export function getAccessTokenExpiresAtMs(token: string | null | undefined): number | null {
  if (!token) return null;
  try {
    const parts = token.split(".");
    if (parts.length < 2) return null;
    const json = atob(parts[1]!.replace(/-/g, "+").replace(/_/g, "/"));
    const payload = JSON.parse(json) as { exp?: unknown };
    return typeof payload.exp === "number" && Number.isFinite(payload.exp)
      ? payload.exp * 1000
      : null;
  } catch {
    return null;
  }
}

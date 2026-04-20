import { AUTH_BFF_PREFIX } from "./auth-bff";
import {
  clearStoredTokens,
  getStoredAccessToken,
  getStoredRefreshToken,
  setStoredTokens
} from "./auth-storage";

let refreshInFlight: Promise<boolean> | null = null;

/** Явное обновление пары токенов (например после 401 на /auth/me). */
export async function refreshSession(): Promise<boolean> {
  if (refreshInFlight) return refreshInFlight;
  refreshInFlight = doRefresh().finally(() => {
    refreshInFlight = null;
  });
  return refreshInFlight;
}

async function doRefresh(): Promise<boolean> {
  const refresh = getStoredRefreshToken();
  if (!refresh) return false;
  try {
    const res = await fetch(`${AUTH_BFF_PREFIX}/refresh`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ refreshToken: refresh }),
      cache: "no-store"
    });
    if (!res.ok) {
      clearStoredTokens();
      return false;
    }
    const data = (await res.json()) as {
      accessToken?: string;
      refreshToken?: string;
    };
    if (!data.accessToken || !data.refreshToken) {
      clearStoredTokens();
      return false;
    }
    setStoredTokens(data.accessToken, data.refreshToken);
    return true;
  } catch {
    clearStoredTokens();
    return false;
  }
}

/**
 * Как `fetch`, но добавляет Bearer и один раз пытается обновить сессию при 401.
 */
export async function apiFetch(input: string, init?: RequestInit): Promise<Response> {
  const url = input;
  const headers = new Headers(init?.headers);
  const token = getStoredAccessToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);

  let res = await fetch(url, { ...init, headers });

  if (res.status === 401 && getStoredRefreshToken()) {
    const ok = await refreshSession();
    if (ok) {
      const h2 = new Headers(init?.headers);
      const t2 = getStoredAccessToken();
      if (t2) h2.set("Authorization", `Bearer ${t2}`);
      res = await fetch(url, { ...init, headers: h2 });
    }
  }

  return res;
}

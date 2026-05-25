"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode
} from "react";
import {
  clearStoredTokens,
  getStoredAccessToken,
  getStoredRefreshToken,
  setStoredTokens
} from "@/lib/auth-storage";
import { AUTH_BFF_PREFIX } from "@/lib/auth-bff";
import { refreshSession } from "@/lib/api-fetch";

export type AuthUser = { id: string; email: string; totpEnabled: boolean };

type AuthContextValue = {
  user: AuthUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<
    | { ok: true; requiresTotp: false }
    | { ok: true; requiresTotp: true; pendingToken: string }
    | { ok: false; error: string }
  >;
  completeTotp: (pendingToken: string, code: string) => Promise<{ ok: boolean; error?: string }>;
  logout: () => Promise<void>;
  refreshMe: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

const AUTH_FETCH_TIMEOUT_MS = 12_000;

async function fetchWithTimeout(url: string, init?: RequestInit): Promise<Response> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), AUTH_FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: ac.signal });
  } finally {
    clearTimeout(t);
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  const refreshMe = useCallback(async () => {
    let access = getStoredAccessToken();
    if (!access) {
      setUser(null);
      return;
    }
    let res: Response;
    try {
      res = await fetchWithTimeout(`${AUTH_BFF_PREFIX}/me`, {
        headers: { authorization: `Bearer ${access}`, accept: "application/json" },
        cache: "no-store"
      });
    } catch {
      clearStoredTokens();
      setUser(null);
      return;
    }
    if (res.status === 401 && getStoredRefreshToken()) {
      const renewed = await refreshSession();
      if (renewed) {
        access = getStoredAccessToken();
        if (access) {
          try {
            res = await fetchWithTimeout(`${AUTH_BFF_PREFIX}/me`, {
              headers: { authorization: `Bearer ${access}`, accept: "application/json" },
              cache: "no-store"
            });
          } catch {
            clearStoredTokens();
            setUser(null);
            return;
          }
        }
      }
    }
    if (!res.ok) {
      clearStoredTokens();
      setUser(null);
      return;
    }
    const data = (await res.json()) as AuthUser;
    setUser(data);
  }, []);

  useEffect(() => {
    void (async () => {
      try {
        await refreshMe();
      } finally {
        setLoading(false);
      }
    })();
  }, [refreshMe]);

  const login = useCallback(async (email: string, password: string) => {
    let res: Response;
    try {
      res = await fetchWithTimeout(`${AUTH_BFF_PREFIX}/login`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ email, password }),
        cache: "no-store"
      });
    } catch {
      return {
        ok: false as const,
        error: "Нет связи с сервером (проверьте, что веб и API запущены)."
      };
    }
    let data: Record<string, unknown>;
    try {
      data = (await res.json()) as Record<string, unknown>;
    } catch {
      return { ok: false as const, error: "Некорректный ответ сервера при входе." };
    }
    if (!res.ok) {
      const msg = nestErrorMessage(data);
      return { ok: false as const, error: msg };
    }
    if (data.requiresTotp && typeof data.pendingToken === "string") {
      return { ok: true as const, requiresTotp: true as const, pendingToken: data.pendingToken };
    }
    if (typeof data.accessToken === "string" && typeof data.refreshToken === "string") {
      setStoredTokens(data.accessToken, data.refreshToken);
      await refreshMe();
      return { ok: true as const, requiresTotp: false as const };
    }
    return { ok: false as const, error: "Unexpected response" };
  }, [refreshMe]);

  const completeTotp = useCallback(
    async (pendingToken: string, code: string) => {
      let res: Response;
      try {
        res = await fetchWithTimeout(`${AUTH_BFF_PREFIX}/login/totp`, {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify({ pendingToken, code }),
          cache: "no-store"
        });
      } catch {
        return {
          ok: false,
          error: "Нет связи с сервером (проверьте, что веб и API запущены)."
        };
      }
      let data: Record<string, unknown>;
      try {
        data = (await res.json()) as Record<string, unknown>;
      } catch {
        return { ok: false, error: "Некорректный ответ сервера." };
      }
      if (!res.ok) {
        return { ok: false, error: nestErrorMessage(data) };
      }
      if (typeof data.accessToken === "string" && typeof data.refreshToken === "string") {
        setStoredTokens(data.accessToken, data.refreshToken);
        await refreshMe();
        return { ok: true };
      }
      return { ok: false, error: "Unexpected response" };
    },
    [refreshMe]
  );

  const logout = useCallback(async () => {
    const access = getStoredAccessToken();
    const refresh = getStoredRefreshToken();
    if (access) {
      try {
        await fetch(`${AUTH_BFF_PREFIX}/logout`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${access}`,
            "content-type": "application/json",
            accept: "application/json"
          },
          body: JSON.stringify({ refreshToken: refresh ?? undefined }),
          cache: "no-store"
        });
      } catch {
        // ignore
      }
    }
    clearStoredTokens();
    setUser(null);
  }, []);

  const value = useMemo(
    () => ({
      user,
      loading,
      login,
      completeTotp,
      logout,
      refreshMe
    }),
    [user, loading, login, completeTotp, logout, refreshMe]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

function nestErrorMessage(data: Record<string, unknown>): string {
  const m = data.message;
  if (typeof m === "string") return m;
  if (Array.isArray(m) && m.every((x) => typeof x === "string")) return m.join(", ");
  const e = data.error;
  if (typeof e === "string") return e;
  return "Request failed";
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

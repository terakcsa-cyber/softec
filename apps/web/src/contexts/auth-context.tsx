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

export type AuthUser = {
  id: string;
  email: string;
  totpEnabled: boolean;
  role?: string;
  mustChangePassword?: boolean;
};

type AuthContextValue = {
  user: AuthUser | null;
  loading: boolean;
  checkInitialSetup: () => Promise<{ required: boolean; error?: string }>;
  setupFirstAdmin: (email: string, password: string) => Promise<{ ok: boolean; error?: string }>;
  login: (email: string, password: string) => Promise<
    | { ok: true; requiresTotp: false; mustChangePassword: boolean }
    | { ok: true; requiresTotp: true; pendingToken: string }
    | { ok: false; error: string }
  >;
  completeTotp: (
    pendingToken: string,
    code: string
  ) => Promise<{ ok: true; mustChangePassword: boolean } | { ok: false; error?: string }>;
  changePassword: (
    currentPassword: string,
    newPassword: string
  ) => Promise<{ ok: true } | { ok: false; error: string }>;
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
    const refresh = getStoredRefreshToken();
    if (!access && !refresh) {
      setUser(null);
      return;
    }
    let res: Response;
    try {
      if (!access && refresh) {
        const renewed = await refreshSession();
        access = getStoredAccessToken();
        if (!renewed || !access) {
          // Keep UI user if tokens still exist after a transient refresh failure.
          if (!getStoredRefreshToken() && !getStoredAccessToken()) setUser(null);
          return;
        }
      }
      res = await fetchWithTimeout(`${AUTH_BFF_PREFIX}/me`, {
        headers: { authorization: `Bearer ${access}`, accept: "application/json" },
        cache: "no-store"
      });
    } catch {
      // Network/timeout — do not wipe a still-valid session.
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
            return;
          }
        }
      }
    }
    if (res.status === 401 || res.status === 403) {
      clearStoredTokens();
      setUser(null);
      return;
    }
    if (!res.ok) {
      // Transient API errors should not force logout.
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
      return {
        ok: true as const,
        requiresTotp: false as const,
        mustChangePassword: data.mustChangePassword === true
      };
    }
    return { ok: false as const, error: "Unexpected response" };
  }, [refreshMe]);

  const checkInitialSetup = useCallback(async () => {
    try {
      const res = await fetchWithTimeout(`${AUTH_BFF_PREFIX}/setup`, {
        headers: { accept: "application/json" },
        cache: "no-store"
      });
      const data = (await res.json()) as Record<string, unknown>;
      if (!res.ok) return { required: false, error: nestErrorMessage(data) };
      return { required: data.required === true };
    } catch {
      return { required: false, error: "Не удалось проверить первичную настройку." };
    }
  }, []);

  const setupFirstAdmin = useCallback(
    async (email: string, password: string) => {
      let res: Response;
      try {
        res = await fetchWithTimeout(`${AUTH_BFF_PREFIX}/setup`, {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify({ email, password }),
          cache: "no-store"
        });
      } catch {
        return { ok: false, error: "Нет связи с сервером (проверьте, что веб и API запущены)." };
      }
      let data: Record<string, unknown>;
      try {
        data = (await res.json()) as Record<string, unknown>;
      } catch {
        return { ok: false, error: "Некорректный ответ сервера при первичной настройке." };
      }
      if (!res.ok) {
        return { ok: false, error: nestErrorMessage(data) };
      }
      if (typeof data.accessToken === "string" && typeof data.refreshToken === "string") {
        setStoredTokens(data.accessToken, data.refreshToken);
        await refreshMe();
        return { ok: true, mustChangePassword: data.mustChangePassword === true };
      }
      return { ok: false, error: "Unexpected response" };
    },
    [refreshMe]
  );

  const changePassword = useCallback(
    async (currentPassword: string, newPassword: string) => {
      const access = getStoredAccessToken();
      if (!access) return { ok: false as const, error: "Нет активной сессии." };
      let res: Response;
      try {
        res = await fetchWithTimeout(`${AUTH_BFF_PREFIX}/change-password`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${access}`,
            "content-type": "application/json",
            accept: "application/json"
          },
          body: JSON.stringify({ currentPassword, newPassword }),
          cache: "no-store"
        });
      } catch {
        return { ok: false as const, error: "Нет связи с сервером." };
      }
      let data: Record<string, unknown> = {};
      try {
        data = (await res.json()) as Record<string, unknown>;
      } catch {
        // keep default
      }
      if (!res.ok) return { ok: false as const, error: nestErrorMessage(data) };
      clearStoredTokens();
      setUser(null);
      return { ok: true as const };
    },
    []
  );

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
          ok: false as const,
          error: "Нет связи с сервером (проверьте, что веб и API запущены)."
        };
      }
      let data: Record<string, unknown>;
      try {
        data = (await res.json()) as Record<string, unknown>;
      } catch {
        return { ok: false as const, error: "Некорректный ответ сервера." };
      }
      if (!res.ok) {
        return { ok: false as const, error: nestErrorMessage(data) };
      }
      if (typeof data.accessToken === "string" && typeof data.refreshToken === "string") {
        setStoredTokens(data.accessToken, data.refreshToken);
        await refreshMe();
        return { ok: true as const, mustChangePassword: data.mustChangePassword === true };
      }
      return { ok: false as const, error: "Unexpected response" };
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
      checkInitialSetup,
      setupFirstAdmin,
      login,
      completeTotp,
      changePassword,
      logout,
      refreshMe
    }),
    [user, loading, checkInitialSetup, setupFirstAdmin, login, completeTotp, changePassword, logout, refreshMe]
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

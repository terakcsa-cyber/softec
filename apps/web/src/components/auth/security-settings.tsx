"use client";

import { useAuth } from "@/contexts/auth-context";
import { AUTH_BFF_PREFIX } from "@/lib/auth-bff";
import { getStoredAccessToken } from "@/lib/auth-storage";
import { useCallback, useState } from "react";

type SetupResponse = {
  secret?: string;
  otpauthUrl?: string;
  qrDataUrl?: string;
};

export function SecuritySettings({ embedded = false }: { embedded?: boolean }) {
  const { user, logout, refreshMe } = useAuth();
  const [setup, setSetup] = useState<SetupResponse | null>(null);
  const [enableCode, setEnableCode] = useState("");
  const [disablePassword, setDisablePassword] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const authHeaders = useCallback(() => {
    const t = getStoredAccessToken();
    if (!t) return null;
    return {
      authorization: `Bearer ${t}`,
      accept: "application/json",
      "content-type": "application/json"
    } as const;
  }, []);

  const startSetup = async () => {
    setErr(null);
    setMsg(null);
    const h = authHeaders();
    if (!h) return;
    setBusy(true);
    try {
      const res = await fetch(`${AUTH_BFF_PREFIX}/2fa/setup`, {
        method: "POST",
        headers: h,
        cache: "no-store"
      });
      const data = (await res.json()) as SetupResponse & { message?: unknown };
      if (!res.ok) {
        setErr(typeof data.message === "string" ? data.message : "Не удалось начать настройку");
        return;
      }
      setSetup(data);
      setEnableCode("");
    } finally {
      setBusy(false);
    }
  };

  const enable2fa = async () => {
    setErr(null);
    setMsg(null);
    const h = authHeaders();
    if (!h) return;
    setBusy(true);
    try {
      const res = await fetch(`${AUTH_BFF_PREFIX}/2fa/enable`, {
        method: "POST",
        headers: h,
        body: JSON.stringify({ code: enableCode.replace(/\s/g, "") }),
        cache: "no-store"
      });
      const data = (await res.json()) as { message?: unknown };
      if (!res.ok) {
        setErr(typeof data.message === "string" ? data.message : "Неверный код");
        return;
      }
      setSetup(null);
      setMsg("Двухфакторная аутентификация включена.");
      await refreshMe();
    } finally {
      setBusy(false);
    }
  };

  const disable2fa = async () => {
    setErr(null);
    setMsg(null);
    const h = authHeaders();
    if (!h) return;
    setBusy(true);
    try {
      const res = await fetch(`${AUTH_BFF_PREFIX}/2fa/disable`, {
        method: "POST",
        headers: h,
        body: JSON.stringify({
          password: disablePassword,
          code: disableCode.replace(/\s/g, "")
        }),
        cache: "no-store"
      });
      const data = (await res.json()) as { message?: unknown };
      if (!res.ok) {
        setErr(typeof data.message === "string" ? data.message : "Не удалось отключить");
        return;
      }
      setDisablePassword("");
      setDisableCode("");
      setMsg("2FA отключена.");
      await refreshMe();
    } finally {
      setBusy(false);
    }
  };

  if (!user) return null;

  return (
    <div className="space-y-5">
      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-border dark:bg-white/[0.04] dark:shadow-none">
        {!embedded ? <div className="text-sm font-medium text-fg/90">Аккаунт</div> : null}
        <div className={embedded ? "text-sm text-muted" : "mt-1 text-sm text-muted"}>
          <span className="text-fg/85">{user.email}</span>
          {user.role ? (
            <span className="ml-2 rounded-md border border-slate-200 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted dark:border-border">
              {user.role}
            </span>
          ) : null}
        </div>
        <button
          type="button"
          onClick={() => void logout()}
          className="mt-3 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs text-fg/85 hover:bg-slate-100 dark:border-border dark:bg-white/[0.06] dark:hover:bg-white/[0.09]"
        >
          Выйти
        </button>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-border dark:bg-white/[0.04] dark:shadow-none">
        <div className="text-sm font-medium text-fg/90">Двухфакторная аутентификация (TOTP)</div>
        <p className="mt-1 text-xs text-muted">
          Совместимо с Google Authenticator, 1Password, Aegis и другими TOTP-приложениями.
        </p>
        <div className="mt-2 text-xs text-fg/80">
          Статус:{" "}
          <span className={user.totpEnabled ? "text-emerald-400" : "text-amber-300"}>
            {user.totpEnabled ? "включена" : "выключена"}
          </span>
        </div>

        {!user.totpEnabled ? (
          <div className="mt-4 space-y-3">
            {!setup ? (
              <button
                type="button"
                disabled={busy}
                onClick={() => void startSetup()}
                className="rounded-lg border border-accent/30 bg-accent/10 px-3 py-1.5 text-xs text-fg/90 hover:bg-accent/15 disabled:opacity-50"
              >
                Настроить 2FA
              </button>
            ) : (
              <div className="space-y-3">
                {setup.qrDataUrl ? (
                  // eslint-disable-next-line @next/next/no-img-element
                  <img
                    src={setup.qrDataUrl}
                    alt="QR для приложения-аутентификатора"
                    className="h-40 w-40 rounded-lg border border-border bg-card p-2"
                  />
                ) : null}
                {setup.secret ? (
                  <div className="text-[11px] text-muted">
                    Секрет (если нет камеры):{" "}
                    <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-fg/85 dark:bg-black/30">{setup.secret}</code>
                  </div>
                ) : null}
                <div className="flex flex-wrap items-end gap-2">
                  <div>
                    <label className="block text-[11px] text-muted">Код из приложения</label>
                    <input
                      value={enableCode}
                      onChange={(e) => setEnableCode(e.target.value.replace(/\D/g, ""))}
                      className="mt-1 w-40 rounded-lg border border-slate-200 bg-white px-2 py-1 font-mono text-sm dark:border-border dark:bg-black/20"
                      maxLength={8}
                      placeholder="000000"
                    />
                  </div>
                  <button
                    type="button"
                    disabled={busy || enableCode.length < 6}
                    onClick={() => void enable2fa()}
                    className="rounded-lg border border-accent/30 bg-accent/10 px-3 py-1.5 text-xs text-fg/90 hover:bg-accent/15 disabled:opacity-50"
                  >
                    Включить
                  </button>
                  <button
                    type="button"
                    onClick={() => setSetup(null)}
                    className="text-xs text-muted hover:text-fg/80"
                  >
                    Отмена
                  </button>
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="mt-4 space-y-2">
            <div className="grid gap-2 sm:grid-cols-2">
              <div>
                <label className="block text-[11px] text-muted">Пароль</label>
                <input
                  type="password"
                  value={disablePassword}
                  onChange={(e) => setDisablePassword(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1 text-sm dark:border-border dark:bg-black/20"
                  autoComplete="current-password"
                />
              </div>
              <div>
                <label className="block text-[11px] text-muted">Код 2FA</label>
                <input
                  value={disableCode}
                  onChange={(e) => setDisableCode(e.target.value.replace(/\D/g, ""))}
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1 font-mono text-sm dark:border-border dark:bg-black/20"
                  maxLength={8}
                />
              </div>
            </div>
            <button
              type="button"
              disabled={busy}
              onClick={() => void disable2fa()}
              className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-1.5 text-xs text-danger hover:bg-danger/15 disabled:opacity-50"
            >
              Отключить 2FA
            </button>
          </div>
        )}
      </div>

      {msg ? <div className="text-sm text-emerald-400">{msg}</div> : null}
      {err ? <div className="text-sm text-red-400">{err}</div> : null}
    </div>
  );
}

"use client";

import { useAuth } from "@/contexts/auth-context";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

export default function LoginPage() {
  const { user, loading, login, completeTotp } = useAuth();
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [pendingToken, setPendingToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!loading && user) router.replace("/");
  }, [loading, user, router]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (pendingToken) {
        const r = await completeTotp(pendingToken, totpCode);
        if (!r.ok) {
          setError(r.error ?? "Неверный код");
          return;
        }
        router.replace("/");
        return;
      }
      const r = await login(email, password);
      if (!r.ok) {
        setError(r.error);
        return;
      }
      if (r.requiresTotp) {
        setPendingToken(r.pendingToken);
        setTotpCode("");
        return;
      }
      router.replace("/");
    } finally {
      setBusy(false);
    }
  }

  if (loading) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-2 bg-bg text-muted">
        <span className="text-sm">Проверка сессии…</span>
      </div>
    );
  }
  if (user) return null;

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-4">
      <div className="glass w-full max-w-md rounded-2xl p-8 shadow-2xl">
        <h1 className="text-lg font-semibold tracking-tight text-fg">Вход</h1>
        <p className="mt-1 text-sm text-muted">
          {pendingToken
            ? "Введите код из приложения-аутентификатора (Google Authenticator и совместимые)."
            : "Пароль и при необходимости второй фактор (TOTP)."}
        </p>

        <form onSubmit={(e) => void onSubmit(e)} className="mt-6 space-y-4">
          {!pendingToken ? (
            <>
              <div>
                <label className="block text-xs font-medium text-muted">Email</label>
                <input
                  type="email"
                  autoComplete="username"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-fg outline-none focus:border-accent/40 dark:border-border dark:bg-black/20"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-muted">Пароль</label>
                <input
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-fg outline-none focus:border-accent/40 dark:border-border dark:bg-black/20"
                  required
                />
              </div>
            </>
          ) : (
            <div>
              <label className="block text-xs font-medium text-muted">Код 2FA</label>
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]*"
                maxLength={12}
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ""))}
                className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-sm text-fg outline-none focus:border-accent/40 dark:border-border dark:bg-black/20"
                placeholder="000000"
                required
              />
            </div>
          )}

          {error ? (
            <div className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
              {error}
            </div>
          ) : null}

          <div className="flex gap-3 pt-2">
            {pendingToken ? (
              <button
                type="button"
                onClick={() => {
                  setPendingToken(null);
                  setTotpCode("");
                  setError(null);
                }}
                className="rounded-lg border border-slate-200 px-4 py-2 text-sm text-fg/90 hover:bg-slate-50 dark:border-border dark:hover:bg-white/[0.06]"
              >
                Назад
              </button>
            ) : null}
            <button
              type="submit"
              disabled={busy}
              className="flex-1 rounded-lg border border-accent/30 bg-accent/15 px-4 py-2 text-sm font-medium text-fg hover:bg-accent/25 disabled:opacity-50"
            >
              {busy ? "…" : pendingToken ? "Подтвердить" : "Войти"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

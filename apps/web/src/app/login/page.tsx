"use client";

import { useAuth } from "@/contexts/auth-context";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

export default function LoginPage() {
  const { user, loading, checkInitialSetup, setupFirstAdmin, login, completeTotp } = useAuth();
  const router = useRouter();
  const [setupRequired, setSetupRequired] = useState(false);
  const [setupChecked, setSetupChecked] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [pendingToken, setPendingToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!loading && user) router.replace(user.mustChangePassword ? "/change-password" : "/");
  }, [loading, user, router]);

  useEffect(() => {
    if (loading || user) return;
    void (async () => {
      const r = await checkInitialSetup();
      if (r.error) setError(r.error);
      setSetupRequired(r.required);
      setSetupChecked(true);
    })();
  }, [checkInitialSetup, loading, user]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (setupRequired) {
      if (password !== confirmPassword) {
        setError("Пароли не совпадают");
        return;
      }
      if (password.length < 12) {
        setError("Пароль администратора должен быть не короче 12 символов");
        return;
      }
    }
    setBusy(true);
    try {
      if (setupRequired) {
        const r = await setupFirstAdmin(email, password);
        if (!r.ok) {
          setError(r.error ?? "Не удалось создать администратора");
          return;
        }
        router.replace("/");
        return;
      }
      if (pendingToken) {
        const r = await completeTotp(pendingToken, totpCode);
        if (!r.ok) {
          setError(r.error ?? "Неверный код");
          return;
        }
        router.replace(r.mustChangePassword ? "/change-password" : "/");
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
      router.replace(r.mustChangePassword ? "/change-password" : "/");
    } finally {
      setBusy(false);
    }
  }

  if (loading || (!user && !setupChecked)) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-2 bg-bg text-muted">
        <span className="text-sm">{loading ? "Проверка сессии…" : "Проверка первичной настройки…"}</span>
      </div>
    );
  }
  if (user) return null;

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-4">
      <div className="glass w-full max-w-md rounded-2xl p-8 shadow-2xl">
        <h1 className="text-lg font-semibold tracking-tight text-fg">
          {setupRequired ? "Первичная настройка" : "Вход"}
        </h1>
        <p className="mt-1 text-sm text-muted">
          {setupRequired
            ? "Пользователей ещё нет. Создайте администратора, который будет управлять платформой."
            : pendingToken
              ? "Введите код из приложения-аутентификатора (Google Authenticator и совместимые)."
              : "Пароль и при необходимости второй фактор (TOTP)."}
        </p>

        <form onSubmit={(e) => void onSubmit(e)} className="mt-6 space-y-4" autoComplete="off">
          {setupRequired ? (
            <>
              <div>
                <label className="block text-xs font-medium text-muted">Email администратора</label>
                <input
                  type="email"
                  name="login-email"
                  autoComplete="off"
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-fg outline-none focus:border-accent/40 dark:border-border dark:bg-black/20"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-muted">Пароль администратора</label>
                <input
                  type="password"
                  autoComplete="new-password"
                  minLength={12}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-fg outline-none focus:border-accent/40 dark:border-border dark:bg-black/20"
                  required
                />
                <div className="mt-1 text-[11px] text-muted">Минимум 12 символов. Сохраните пароль в менеджере секретов.</div>
              </div>
              <div>
                <label className="block text-xs font-medium text-muted">Повторите пароль</label>
                <input
                  type="password"
                  autoComplete="new-password"
                  minLength={12}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-fg outline-none focus:border-accent/40 dark:border-border dark:bg-black/20"
                  required
                />
              </div>
            </>
          ) : !pendingToken ? (
            <>
              <div>
                <label className="block text-xs font-medium text-muted">Email</label>
                <input
                  type="email"
                  name="login-email"
                  autoComplete="off"
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
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
                  name="login-password"
                  autoComplete="off"
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
              {busy ? "…" : setupRequired ? "Создать администратора" : pendingToken ? "Подтвердить" : "Войти"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

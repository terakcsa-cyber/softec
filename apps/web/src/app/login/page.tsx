"use client";

import {
  AuthError,
  AuthField,
  AuthInput,
  AuthLoading,
  AuthPrimaryButton,
  AuthSecondaryButton,
  AuthShell
} from "@/components/auth/auth-shell";
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
    return <AuthLoading message={loading ? "Проверка сессии…" : "Проверка первичной настройки…"} />;
  }
  if (user) return null;

  const title = setupRequired ? "Первичная настройка" : pendingToken ? "Подтверждение 2FA" : "Вход в платформу";
  const subtitle = setupRequired
    ? "Пользователей ещё нет. Создайте администратора, который будет управлять VulnControl."
    : pendingToken
      ? "Введите код из приложения-аутентификатора (Google Authenticator и совместимые)."
      : "Введите учётные данные. При включённом TOTP потребуется второй фактор.";

  return (
    <AuthShell title={title} subtitle={subtitle} footer="Доступ только для авторизованных аналитиков">
      <form onSubmit={(e) => void onSubmit(e)} className="space-y-4" autoComplete="off">
        {setupRequired ? (
          <>
            <AuthField label="Email администратора">
              <AuthInput
                type="email"
                name="login-email"
                autoComplete="off"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </AuthField>
            <AuthField label="Пароль администратора" hint="Минимум 12 символов. Сохраните пароль в менеджере секретов.">
              <AuthInput
                type="password"
                autoComplete="new-password"
                minLength={12}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </AuthField>
            <AuthField label="Повторите пароль">
              <AuthInput
                type="password"
                autoComplete="new-password"
                minLength={12}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
              />
            </AuthField>
          </>
        ) : !pendingToken ? (
          <>
            <AuthField label="Email">
              <AuthInput
                type="email"
                name="login-email"
                autoComplete="off"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </AuthField>
            <AuthField label="Пароль">
              <AuthInput
                type="password"
                name="login-password"
                autoComplete="off"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </AuthField>
          </>
        ) : (
          <AuthField label="Код 2FA">
            <AuthInput
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]*"
              maxLength={12}
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ""))}
              className="font-mono tracking-[0.2em]"
              placeholder="000000"
              required
            />
          </AuthField>
        )}

        {error ? <AuthError>{error}</AuthError> : null}

        <div className="flex gap-2.5 pt-1">
          {pendingToken ? (
            <AuthSecondaryButton
              onClick={() => {
                setPendingToken(null);
                setTotpCode("");
                setError(null);
              }}
            >
              Назад
            </AuthSecondaryButton>
          ) : null}
          <AuthPrimaryButton disabled={busy}>
            {busy ? "…" : setupRequired ? "Создать администратора" : pendingToken ? "Подтвердить" : "Войти"}
          </AuthPrimaryButton>
        </div>
      </form>
    </AuthShell>
  );
}

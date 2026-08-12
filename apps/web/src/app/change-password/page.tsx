"use client";

import { RequireAuth } from "@/components/auth/require-auth";
import { useAuth } from "@/contexts/auth-context";
import { useRouter } from "next/navigation";
import { useState } from "react";
import type { FormEvent } from "react";

function ChangePasswordForm() {
  const { changePassword, user } = useAuth();
  const router = useRouter();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (newPassword.length < 12) {
      setError("Новый пароль должен быть не короче 12 символов");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("Пароли не совпадают");
      return;
    }
    setBusy(true);
    try {
      const res = await changePassword(currentPassword, newPassword);
      if (!res.ok) {
        setError(res.error);
        return;
      }
      setDone(true);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-4">
      <div className="glass w-full max-w-md rounded-2xl p-8 shadow-2xl">
        <h1 className="text-lg font-semibold tracking-tight text-fg">Смена пароля</h1>
        <p className="mt-1 text-sm text-muted">
          {user?.mustChangePassword
            ? "Для первого входа задайте новый пароль. После смены потребуется войти заново."
            : "Обновите пароль аккаунта. Активные refresh-токены будут отозваны."}
        </p>

        {done ? (
          <div className="mt-6 space-y-4">
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300">
              Пароль изменён. Войдите с новым паролем.
            </div>
            <button
              type="button"
              onClick={() => router.replace("/login")}
              className="w-full rounded-lg border border-accent/30 bg-accent/15 px-4 py-2 text-sm font-medium text-fg hover:bg-accent/25"
            >
              Перейти ко входу
            </button>
          </div>
        ) : (
          <form onSubmit={(e) => void onSubmit(e)} className="mt-6 space-y-4">
            <div>
              <label className="block text-xs font-medium text-muted">Текущий пароль</label>
              <input
                type="password"
                autoComplete="current-password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-fg outline-none focus:border-accent/40 dark:border-border dark:bg-black/20"
                required
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-muted">Новый пароль</label>
              <input
                type="password"
                autoComplete="new-password"
                minLength={12}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-fg outline-none focus:border-accent/40 dark:border-border dark:bg-black/20"
                required
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-muted">Повторите новый пароль</label>
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
            {error ? (
              <div className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
                {error}
              </div>
            ) : null}
            <button
              type="submit"
              disabled={busy}
              className="w-full rounded-lg border border-accent/30 bg-accent/15 px-4 py-2 text-sm font-medium text-fg hover:bg-accent/25 disabled:opacity-50"
            >
              {busy ? "…" : "Сменить пароль"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

export default function ChangePasswordPage() {
  return (
    <RequireAuth>
      <ChangePasswordForm />
    </RequireAuth>
  );
}


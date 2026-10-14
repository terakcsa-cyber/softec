"use client";

import {
  AuthError,
  AuthField,
  AuthInput,
  AuthPrimaryButton,
  AuthShell,
  AuthSuccess
} from "@/components/auth/auth-shell";
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
    <AuthShell
      title="Смена пароля"
      subtitle={
        user?.mustChangePassword
          ? "Для первого входа задайте новый пароль. После смены потребуется войти заново."
          : "Обновите пароль аккаунта. Активные refresh-токены будут отозваны."
      }
    >
      {done ? (
        <div className="space-y-4">
          <AuthSuccess>Пароль изменён. Войдите с новым паролем.</AuthSuccess>
          <AuthPrimaryButton type="button" onClick={() => router.replace("/login")} className="w-full">
            Перейти ко входу
          </AuthPrimaryButton>
        </div>
      ) : (
        <form onSubmit={(e) => void onSubmit(e)} className="space-y-4">
          <AuthField label="Текущий пароль">
            <AuthInput
              type="password"
              autoComplete="current-password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              required
            />
          </AuthField>
          <AuthField label="Новый пароль" hint="Минимум 12 символов.">
            <AuthInput
              type="password"
              autoComplete="new-password"
              minLength={12}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
            />
          </AuthField>
          <AuthField label="Повторите новый пароль">
            <AuthInput
              type="password"
              autoComplete="new-password"
              minLength={12}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
          </AuthField>
          {error ? <AuthError>{error}</AuthError> : null}
          <AuthPrimaryButton disabled={busy} className="w-full">
            {busy ? "…" : "Сменить пароль"}
          </AuthPrimaryButton>
        </form>
      )}
    </AuthShell>
  );
}

export default function ChangePasswordPage() {
  return (
    <RequireAuth>
      <ChangePasswordForm />
    </RequireAuth>
  );
}

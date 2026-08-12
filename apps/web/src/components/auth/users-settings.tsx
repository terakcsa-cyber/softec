"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";
import { cn } from "../ui/cn";
import { useState } from "react";

type Role = "admin" | "analyst" | "viewer";

type AuthUserAdmin = {
  id: string;
  email: string;
  role: Role;
  enabled: boolean;
  mustChangePassword: boolean;
  createdAt: string | null;
  updatedAt: string | null;
};

async function readApiError(res: Response, fallback: string) {
  try {
    const data = (await res.json()) as { message?: unknown; error?: unknown };
    if (typeof data.message === "string") return data.message;
    if (Array.isArray(data.message)) return data.message.join(", ");
    if (typeof data.error === "string") return data.error;
  } catch {
    // ignore
  }
  return fallback;
}

export function UsersSettings({ embedded = false }: { embedded?: boolean }) {
  const qc = useQueryClient();
  const [createEmail, setCreateEmail] = useState("");
  const [createPassword, setCreatePassword] = useState("");
  const [createRole, setCreateRole] = useState<Role>("analyst");
  const [createMustChange, setCreateMustChange] = useState(true);
  const [resetPasswords, setResetPasswords] = useState<Record<string, string>>({});
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const usersQ = useQuery({
    queryKey: ["auth", "users"],
    queryFn: async () => {
      const res = await apiFetch("/api/auth/users", { cache: "no-store" });
      if (!res.ok) throw new Error(await readApiError(res, "Не удалось загрузить пользователей"));
      return (await res.json()) as AuthUserAdmin[];
    }
  });

  const updateUser = useMutation({
    mutationFn: async ({ id, patch }: { id: string; patch: Partial<Pick<AuthUserAdmin, "email" | "role" | "enabled" | "mustChangePassword">> }) => {
      const res = await apiFetch(`/api/auth/users/${encodeURIComponent(id)}`, {
        method: "PATCH",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify(patch),
        cache: "no-store"
      });
      if (!res.ok) throw new Error(await readApiError(res, "Не удалось обновить пользователя"));
      return res.json() as Promise<AuthUserAdmin>;
    },
    onSuccess: async () => {
      setMsg("Пользователь обновлён.");
      setErr(null);
      await qc.invalidateQueries({ queryKey: ["auth", "users"] });
    },
    onError: (e) => {
      setMsg(null);
      setErr(e instanceof Error ? e.message : "Ошибка обновления пользователя");
    }
  });

  const createUser = useMutation({
    mutationFn: async () => {
      const res = await apiFetch("/api/auth/users", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({
          email: createEmail,
          password: createPassword,
          role: createRole,
          enabled: true,
          mustChangePassword: createMustChange
        }),
        cache: "no-store"
      });
      if (!res.ok) throw new Error(await readApiError(res, "Не удалось создать пользователя"));
      return res.json() as Promise<AuthUserAdmin>;
    },
    onSuccess: async () => {
      setCreateEmail("");
      setCreatePassword("");
      setCreateRole("analyst");
      setCreateMustChange(true);
      setMsg("Пользователь создан.");
      setErr(null);
      await qc.invalidateQueries({ queryKey: ["auth", "users"] });
    },
    onError: (e) => {
      setMsg(null);
      setErr(e instanceof Error ? e.message : "Ошибка создания пользователя");
    }
  });

  const resetPassword = useMutation({
    mutationFn: async ({ id, password }: { id: string; password: string }) => {
      const res = await apiFetch(`/api/auth/users/${encodeURIComponent(id)}/reset-password`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ password, mustChangePassword: true }),
        cache: "no-store"
      });
      if (!res.ok) throw new Error(await readApiError(res, "Не удалось сбросить пароль"));
    },
    onSuccess: async (_data, vars) => {
      setResetPasswords((m) => ({ ...m, [vars.id]: "" }));
      setMsg("Пароль сброшен, пользователь должен сменить его при входе.");
      setErr(null);
      await qc.invalidateQueries({ queryKey: ["auth", "users"] });
    },
    onError: (e) => {
      setMsg(null);
      setErr(e instanceof Error ? e.message : "Ошибка сброса пароля");
    }
  });

  return (
    <section className="space-y-4">
      {!embedded ? (
        <div>
          <div className="text-sm font-medium text-fg/90">Пользователи</div>
          <p className="mt-1 text-xs text-muted">
            Создание аккаунтов, роли RBAC и принудительная смена пароля. Регистрация через self-service отключена.
          </p>
        </div>
      ) : (
        <p className="text-xs text-muted">Self-service регистрация отключена — аккаунты создаёт только admin.</p>
      )}

      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-border dark:bg-white/[0.04] dark:shadow-none">
        <div className="mb-3 text-[12px] font-medium text-fg/90">Новый пользователь</div>
        <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_160px_minmax(160px,220px)]">
          <input
            type="email"
            value={createEmail}
            onChange={(e) => setCreateEmail(e.target.value)}
            placeholder="email"
            className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
          />
          <select
            value={createRole}
            onChange={(e) => setCreateRole(e.target.value as Role)}
            className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
          >
            <option value="admin">admin</option>
            <option value="analyst">analyst</option>
            <option value="viewer">viewer</option>
          </select>
          <input
            type="password"
            minLength={12}
            value={createPassword}
            onChange={(e) => setCreatePassword(e.target.value)}
            placeholder="временный пароль"
            className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
          />
        </div>
        <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
          <label className="inline-flex items-center gap-2 text-xs text-muted">
            <input
              type="checkbox"
              checked={createMustChange}
              onChange={(e) => setCreateMustChange(e.target.checked)}
            />
            Требовать смену пароля
          </label>
          <button
            type="button"
            disabled={createUser.isPending || createPassword.length < 12 || !createEmail.trim()}
            onClick={() => createUser.mutate()}
            className="rounded-lg border border-accent/30 bg-accent/10 px-3 py-1.5 text-xs text-fg/90 hover:bg-accent/15 disabled:opacity-50"
          >
            Создать пользователя
          </button>
        </div>
      </div>

      <div className="space-y-3">
        {usersQ.isLoading ? <div className="text-sm text-muted">Загрузка пользователей…</div> : null}
        {usersQ.data?.map((u) => (
          <div
            key={u.id}
            className={cn(
              "rounded-xl border p-4 shadow-sm",
              u.enabled
                ? "border-slate-200 bg-white dark:border-border dark:bg-white/[0.04]"
                : "border-amber-500/30 bg-amber-500/10"
            )}
          >
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <input
                  defaultValue={u.email}
                  onBlur={(e) => {
                    const next = e.target.value.trim();
                    if (next && next !== u.email) updateUser.mutate({ id: u.id, patch: { email: next } });
                  }}
                  className="w-full min-w-[260px] rounded-lg border border-transparent bg-transparent px-1 py-0.5 text-sm font-medium text-fg/90 hover:border-slate-200 dark:hover:border-border"
                />
                <div className="mt-1 text-[11px] text-muted">id: {u.id}</div>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <select
                  value={u.role}
                  onChange={(e) => updateUser.mutate({ id: u.id, patch: { role: e.target.value as Role } })}
                  className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-xs dark:border-border dark:bg-black/20"
                >
                  <option value="admin">admin</option>
                  <option value="analyst">analyst</option>
                  <option value="viewer">viewer</option>
                </select>
                <label className="inline-flex items-center gap-1.5 text-xs text-muted">
                  <input
                    type="checkbox"
                    checked={u.enabled}
                    onChange={(e) => updateUser.mutate({ id: u.id, patch: { enabled: e.target.checked } })}
                  />
                  enabled
                </label>
                <label className="inline-flex items-center gap-1.5 text-xs text-muted">
                  <input
                    type="checkbox"
                    checked={u.mustChangePassword}
                    onChange={(e) => updateUser.mutate({ id: u.id, patch: { mustChangePassword: e.target.checked } })}
                  />
                  must change
                </label>
              </div>
            </div>
            <div className="mt-3 flex flex-wrap items-end gap-2">
              <div>
                <label className="block text-[11px] text-muted">Reset password</label>
                <input
                  type="password"
                  minLength={12}
                  value={resetPasswords[u.id] ?? ""}
                  onChange={(e) => setResetPasswords((m) => ({ ...m, [u.id]: e.target.value }))}
                  className="mt-1 w-56 rounded-lg border border-slate-200 bg-white px-2 py-1 text-sm dark:border-border dark:bg-black/20"
                />
              </div>
              <button
                type="button"
                disabled={resetPassword.isPending || (resetPasswords[u.id] ?? "").length < 12}
                onClick={() => resetPassword.mutate({ id: u.id, password: resetPasswords[u.id] ?? "" })}
                className="rounded-lg border border-amber-400/30 bg-amber-400/10 px-3 py-1.5 text-xs text-fg/90 hover:bg-amber-400/15 disabled:opacity-50"
              >
                Сбросить
              </button>
            </div>
          </div>
        ))}
      </div>

      {msg ? <div className="text-sm text-emerald-400">{msg}</div> : null}
      {err ? <div className="text-sm text-red-400">{err}</div> : null}
    </section>
  );
}


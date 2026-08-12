"use client";

import { AppearanceSettings } from "@/components/auth/appearance-settings";
import { SecuritySettings } from "@/components/auth/security-settings";
import { UsersSettings } from "@/components/auth/users-settings";
import { IntegrationSettingsPanel } from "@/components/dashboard/integration-settings-panel";
import { PlatformUpdatePanel } from "@/components/dashboard/platform-update-panel";
import { WebTlsSettingsPanel } from "@/components/dashboard/web-tls-settings-panel";
import { useAuth } from "@/contexts/auth-context";
import { cn } from "@/components/ui/cn";
import {
  KeyRound,
  Lock,
  Palette,
  Plug,
  RefreshCw,
  Sparkles,
  Users
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

export type SettingsSectionId =
  | "integrations"
  | "textEngine"
  | "webTls"
  | "updates"
  | "users"
  | "appearance"
  | "account";

type NavItem = {
  id: SettingsSectionId;
  label: string;
  description: string;
  adminOnly: boolean;
  icon: typeof Plug;
};

const NAV: NavItem[] = [
  {
    id: "integrations",
    label: "Интеграции",
    description: "NVD, VulnCheck, Telegram, MaxPatrol VM и БДУ",
    adminOnly: true,
    icon: Plug
  },
  {
    id: "textEngine",
    label: "Текст и LLM",
    description: "Движок обогащения, LibreTranslate и профили моделей",
    adminOnly: true,
    icon: Sparkles
  },
  {
    id: "webTls",
    label: "Веб / TLS",
    description: "HTTPS-сертификат для web и TLS-прокси",
    adminOnly: true,
    icon: Lock
  },
  {
    id: "updates",
    label: "Обновления",
    description: "Проверка git-репозитория и безопасный apply",
    adminOnly: true,
    icon: RefreshCw
  },
  {
    id: "users",
    label: "Пользователи",
    description: "Учётные записи, роли RBAC и смена пароля",
    adminOnly: true,
    icon: Users
  },
  {
    id: "appearance",
    label: "Оформление",
    description: "Тема интерфейса для этого браузера",
    adminOnly: false,
    icon: Palette
  },
  {
    id: "account",
    label: "Аккаунт",
    description: "Профиль, 2FA и выход из системы",
    adminOnly: false,
    icon: KeyRound
  }
];

export function SettingsPanel() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const items = useMemo(() => NAV.filter((item) => (item.adminOnly ? isAdmin : true)), [isAdmin]);

  const [section, setSection] = useState<SettingsSectionId>("appearance");
  const [didInit, setDidInit] = useState(false);

  useEffect(() => {
    if (didInit || user == null) return;
    setSection(isAdmin ? "integrations" : "appearance");
    setDidInit(true);
  }, [didInit, isAdmin, user]);

  useEffect(() => {
    if (!items.some((item) => item.id === section)) {
      setSection(items[0]?.id ?? "appearance");
    }
  }, [items, section]);

  const active = items.find((item) => item.id === section) ?? items[0]!;
  const activeId = active.id;

  return (
    <div className="glass rounded-2xl">
      <div className="border-b border-slate-200 px-5 py-4 dark:border-border sm:px-6">
        <div className="text-sm font-semibold tracking-tight text-fg/95">Настройки</div>
        <p className="mt-1 text-xs text-muted">
          Разделы разделены по назначению: интеграции, текстовый движок, веб/TLS, обновления, пользователи и
          личные настройки.
        </p>
      </div>

      <div className="grid lg:grid-cols-[220px_minmax(0,1fr)]">
        <nav
          aria-label="Разделы настроек"
          className="border-b border-slate-200 p-3 dark:border-border lg:border-b-0 lg:border-r"
        >
          <div className="flex gap-1 overflow-x-auto pb-1 lg:flex-col lg:overflow-visible lg:pb-0">
            {items.map((item) => {
              const Icon = item.icon;
              const selected = item.id === activeId;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setSection(item.id)}
                  className={cn(
                    "flex min-w-[9.5rem] shrink-0 items-start gap-2.5 rounded-xl border px-3 py-2.5 text-left transition lg:min-w-0 lg:w-full",
                    selected
                      ? "border-accent/35 bg-accent/10 text-fg/95"
                      : "border-transparent text-fg/80 hover:border-slate-200 hover:bg-slate-50 dark:hover:border-border dark:hover:bg-white/[0.04]"
                  )}
                >
                  <Icon
                    className={cn("mt-0.5 h-4 w-4 shrink-0", selected ? "text-accent" : "text-muted")}
                    aria-hidden
                  />
                  <span className="min-w-0">
                    <span className="block text-[12px] font-medium leading-tight">{item.label}</span>
                    <span className="mt-0.5 hidden text-[10px] leading-snug text-muted lg:block">
                      {item.description}
                    </span>
                  </span>
                </button>
              );
            })}
          </div>

          {!isAdmin ? (
            <p className="mt-3 hidden px-1 text-[10px] leading-relaxed text-muted lg:block">
              Интеграции, LLM, TLS, обновления и пользователи доступны только роли{" "}
              <span className="font-medium text-fg/80">admin</span>.
            </p>
          ) : null}
        </nav>

        <div className="min-w-0 p-5 sm:p-6">
          <div className="mb-5">
            <h2 className="text-sm font-medium text-fg/95">{active.label}</h2>
            <p className="mt-1 text-xs text-muted">{active.description}</p>
          </div>

          {activeId === "integrations" ? (
            isAdmin ? (
              <IntegrationSettingsPanel section="integrations" />
            ) : (
              <AdminOnlyNotice />
            )
          ) : null}

          {activeId === "textEngine" ? (
            isAdmin ? (
              <IntegrationSettingsPanel section="textEngine" />
            ) : (
              <AdminOnlyNotice />
            )
          ) : null}

          {activeId === "webTls" ? (isAdmin ? <WebTlsSettingsPanel embedded /> : <AdminOnlyNotice />) : null}

          {activeId === "updates" ? (isAdmin ? <PlatformUpdatePanel embedded /> : <AdminOnlyNotice />) : null}

          {activeId === "users" ? (isAdmin ? <UsersSettings embedded /> : <AdminOnlyNotice />) : null}

          {activeId === "appearance" ? <AppearanceSettings embedded /> : null}

          {activeId === "account" ? <SecuritySettings embedded /> : null}
        </div>
      </div>
    </div>
  );
}

function AdminOnlyNotice() {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50/80 px-4 py-3 text-sm text-muted dark:border-border dark:bg-white/[0.04]">
      Управление этим разделом доступно только роли <strong className="text-fg/85">admin</strong>.
    </div>
  );
}

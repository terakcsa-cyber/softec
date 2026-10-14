"use client";

import {
  Activity,
  KeyRound,
  Lock,
  Palette,
  Plug,
  RefreshCw,
  Sparkles,
  Users
} from "lucide-react";

export type SettingsSectionId =
  | "integrations"
  | "textEngine"
  | "webTls"
  | "updates"
  | "systemHealth"
  | "users"
  | "appearance"
  | "account";

export type SettingsNavItem = {
  id: SettingsSectionId;
  label: string;
  description: string;
  adminOnly: boolean;
  icon: typeof Plug;
};

export const SETTINGS_NAV: SettingsNavItem[] = [
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
    description: "Движок карточек, LibreTranslate и ключ дайджеста",
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
    id: "systemHealth",
    label: "Здоровье системы",
    description: "Очереди, DLQ, readiness и ручной запуск EPSS, NVD и БДУ",
    adminOnly: true,
    icon: Activity
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

const SECTION_IDS = new Set<string>(SETTINGS_NAV.map((item) => item.id));

export function isSettingsSection(value: string | null | undefined): value is SettingsSectionId {
  return typeof value === "string" && SECTION_IDS.has(value);
}

export function visibleSettingsNav(isAdmin: boolean) {
  return SETTINGS_NAV.filter((item) => (item.adminOnly ? isAdmin : true));
}

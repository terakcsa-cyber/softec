"use client";

import { visibleSettingsNav, type SettingsSectionId } from "@/components/dashboard/settings-nav";
import { cn } from "@/components/ui/cn";
import { useAuth } from "@/contexts/auth-context";

export function SettingsSectionList({
  active,
  onPick,
  labelledBy
}: {
  active: SettingsSectionId | null;
  onPick: (id: SettingsSectionId) => void;
  labelledBy?: string;
}) {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const items = visibleSettingsNav(isAdmin);

  return (
    <div role="menu" aria-labelledby={labelledBy} className="space-y-0.5 py-0.5">
      {items.map((item) => {
        const Icon = item.icon;
        const selected = active === item.id;
        return (
          <button
            key={item.id}
            type="button"
            role="menuitem"
            title={item.description}
            onClick={() => onPick(item.id)}
            className={cn(
              "flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-[12px] leading-tight",
              selected
                ? "bg-[color-mix(in_srgb,var(--vc-primary)_18%,transparent)] font-medium text-[var(--vc-text)]"
                : "text-[var(--vc-nav)] hover:bg-[var(--vc-hover)]"
            )}
          >
            <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden />
            <span className="truncate">{item.label}</span>
          </button>
        );
      })}
      {!isAdmin ? (
        <p className="px-2 pt-1 text-[10px] leading-snug text-[var(--vc-muted)]">
          Интеграции, LLM, TLS, обновления, здоровье системы и пользователи доступны только роли admin.
        </p>
      ) : null}
    </div>
  );
}

"use client";

import { SettingsSectionBody } from "@/components/dashboard/settings-panel";
import { SETTINGS_NAV } from "@/components/dashboard/settings-nav";
import { useAuth } from "@/contexts/auth-context";
import { IntegrationsView } from "./integrations-view";
import { useVc } from "./vc-context";

export function SettingsView() {
  const { settingsSection } = useVc();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const meta = SETTINGS_NAV.find((item) => item.id === settingsSection) ?? SETTINGS_NAV.find((item) => item.id === "appearance")!;

  if (settingsSection === "integrations" && isAdmin) return <IntegrationsView />;

  return (
    <section className="vc-settings rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-4 text-[var(--vc-text)]">
      <h2 className="text-[14px] font-semibold">{meta.label}</h2>
      <p className="mt-1 max-w-3xl text-[12px] leading-relaxed text-[var(--vc-muted)]">{meta.description}</p>
      <div className="mt-4 min-w-0">
        <SettingsSectionBody section={meta.id} appearance="vc" />
      </div>
    </section>
  );
}

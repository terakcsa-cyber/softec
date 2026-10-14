"use client";

import { IntegrationSettingsPanel } from "../dashboard/integration-settings-panel";

export function IntegrationsView() {
  return (
    <div className="space-y-3">
      <div>
        <h1 className="text-[20px] font-semibold tracking-tight">Интеграции</h1>
        <p className="max-w-3xl text-[12px] leading-5 text-[var(--vc-muted)]">
          NVD, VulnCheck, Telegram, MaxPatrol VM и БДУ. Статус источника — по сохранённым настройкам: секрет или адрес задан, не задан, либо последняя синхронизация вернула ошибку.
        </p>
      </div>
      <IntegrationSettingsPanel section="integrations" appearance="vc" />
    </div>
  );
}

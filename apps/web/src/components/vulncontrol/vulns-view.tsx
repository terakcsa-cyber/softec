"use client";

import { DetailDrawer } from "./detail-drawer";
import { LiveCveTable } from "./live-table";
import { VcSelect } from "./vc-pop";
import { useVc } from "./vc-context";
import { formatInt, useCatalogSummary, useExploitRadar, useVendorWindow } from "@/lib/vulncontrol/live";
import type { ExploitSignal, Severity, VulnStatus } from "@/lib/vulncontrol/types";

const TABS: Array<{
  id: string;
  label: string;
  color: string;
  patch: {
    tab?: "all" | "kev" | "epss";
    severity?: Severity | "all";
    kevAddedDays?: number | null;
    publishedDays?: number | null;
    exploitSignal?: ExploitSignal;
  };
}> = [
  { id: "all", label: "Все", color: "var(--vc-primary)", patch: { tab: "all", severity: "all", kevAddedDays: null, publishedDays: null, exploitSignal: "all" } },
  { id: "critical", label: "Критические", color: "var(--vc-critical)", patch: { tab: "all", severity: "critical", kevAddedDays: null, publishedDays: null, exploitSignal: "all" } },
  { id: "high", label: "Высокие", color: "var(--vc-high)", patch: { tab: "all", severity: "high", kevAddedDays: null, publishedDays: null, exploitSignal: "all" } },
  { id: "medium", label: "Средние", color: "var(--vc-medium)", patch: { tab: "all", severity: "medium", kevAddedDays: null, publishedDays: null, exploitSignal: "all" } },
  { id: "low", label: "Низкие", color: "var(--vc-low)", patch: { tab: "all", severity: "low", kevAddedDays: null, publishedDays: null, exploitSignal: "all" } },
  { id: "kev", label: "KEV / Exploited", color: "var(--vc-critical)", patch: { tab: "kev", severity: "all", kevAddedDays: null, publishedDays: null, exploitSignal: "all" } },
  { id: "newKev", label: "Новые CISA KEV", color: "var(--vc-critical)", patch: { tab: "kev", severity: "all", kevAddedDays: 7, publishedDays: null, exploitSignal: "all" } },
  { id: "epssSpike", label: "Скачок EPSS", color: "var(--vc-epss)", patch: { tab: "all", severity: "all", kevAddedDays: null, publishedDays: null, exploitSignal: "epss_spike" } },
  { id: "epss", label: "EPSS ≥ 0.7", color: "var(--vc-epss)", patch: { tab: "epss", severity: "all", kevAddedDays: null, publishedDays: null, exploitSignal: "all" } }
];

const SIGNAL_HINT: Record<Exclude<ExploitSignal, "all">, string> = {
  epss_spike: "скачок EPSS за 7 дней",
  has_poc: "есть PoC",
  has_public_exploit: "публичный эксплойт",
  vckev_only: "VulnCheck KEV вне CISA",
  new_vckev_7d: "новые VulnCheck KEV за 7 дней"
};

export function VulnsView() {
  const { query, setQuery } = useVc();
  const summary = useCatalogSummary();
  const radar = useExploitRadar();
  const vendors = useVendorWindow(query.range);
  const severity = summary.data?.severity;
  const counts: Record<string, number | undefined> = {
    all: summary.data?.totalCves,
    critical: severity?.critical,
    high: severity?.high,
    medium: severity?.medium,
    low: severity?.low,
    kev: summary.data?.kevCount,
    newKev: summary.data?.newCisaKev7dCount,
    epssSpike: radar.data?.epssSpikes,
    epss: summary.data?.highEpssCount
  };
  const active =
    query.exploitSignal === "epss_spike" ? "epssSpike"
      : query.exploitSignal !== "all" ? ""
        : query.tab === "kev" && query.kevAddedDays != null ? "newKev"
          : query.tab === "kev" ? "kev"
            : query.tab === "epss" ? "epss"
              : query.severity === "all" ? "all" : query.severity;
  const windowHint = [
    query.kevAddedDays != null ? `CISA KEV за ${query.kevAddedDays} дн.` : null,
    query.publishedDays != null ? `публикации за ${query.publishedDays} дн.` : null,
    query.exploitSignal !== "all" ? SIGNAL_HINT[query.exploitSignal] : null
  ].filter(Boolean).join(" · ");
  const vendorNames = unique([query.vendor !== "all" ? query.vendor : "", ...(vendors.data?.vendors.map((row) => row.vendor) ?? [])]);
  const productNames = unique([
    query.product !== "all" ? query.product : "",
    ...(vendors.data?.products ?? [])
      .filter((row) => query.vendor === "all" || row.vendor === query.vendor)
      .map((row) => row.product)
  ]);
  const statusValue: VulnStatus | "all" =
    query.status === "open" || query.status === "in_progress" ? "open" : query.status === "resolved" || query.status === "accepted_risk" ? "resolved" : "all";

  return (
    <div className="space-y-3">
      <div>
        <h1 className="text-[20px] font-semibold tracking-tight">Уязвимости</h1>
        <p className="text-[12px] text-[var(--vc-muted)]">Единый реестр CVE с приоритизацией, контекстом и управлением устранением</p>
      </div>
      {windowHint ? (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-[color-mix(in_srgb,var(--vc-primary)_35%,transparent)] bg-[color-mix(in_srgb,var(--vc-primary)_10%,transparent)] px-3 py-2 text-[12px]">
          <span>Срез из аналитики / дашборда: <span className="font-medium">{windowHint}</span></span>
          <button
            type="button"
            className="text-[var(--vc-link)] hover:underline"
            onClick={() => setQuery({
              kevAddedDays: null,
              publishedDays: null,
              exploitSignal: "all",
              tab: query.tab === "kev" && query.kevAddedDays != null ? "kev" : query.tab
            })}
          >
            Сбросить срез
          </button>
        </div>
      ) : null}
      <div className="flex gap-5 overflow-x-auto border-b border-[var(--vc-border)]">
        {TABS.map((tab) => {
          const on = active === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setQuery(tab.patch)}
              className={`relative inline-flex shrink-0 items-center gap-2 pb-2.5 text-[13px] ${on ? "font-medium text-[var(--vc-text)]" : "text-[var(--vc-muted)] hover:text-[var(--vc-text)]"}`}
            >
              {tab.label}
              <span
                className="rounded-md px-1.5 py-0.5 text-[11px] font-semibold tabular-nums text-white"
                style={{ background: on && tab.id === "all" ? "var(--vc-primary)" : tab.color }}
              >
                {counts[tab.id] == null ? "…" : formatInt(counts[tab.id])}
              </span>
              {on ? <span className="absolute inset-x-0 bottom-0 h-0.5 rounded-full bg-[#2f6bff]" /> : null}
            </button>
          );
        })}
      </div>
      <div className="flex flex-wrap gap-2">
        <FilterSelect
          value={query.severity}
          onChange={(value) => setQuery({ severity: value as Severity | "all" })}
          options={[["all", "Все уровни"], ["critical", "Критические"], ["high", "Высокие"], ["medium", "Средние"], ["low", "Низкие"]]}
        />
        <FilterSelect
          value={statusValue}
          onChange={(value) => setQuery({ status: value === "open" ? "open" : value === "resolved" ? "resolved" : "all" })}
          options={[["all", "Все статусы"], ["open", "Есть задача"], ["resolved", "Без задачи"]]}
        />
        <FilterSelect
          value={vendorNames.includes(query.vendor) ? query.vendor : "all"}
          onChange={(value) => setQuery({ vendor: value, product: "all" })}
          options={[["all", "Все вендоры"], ...vendorNames.map((name) => [name, name] as [string, string])]}
        />
        <FilterSelect
          value={productNames.includes(query.product) ? query.product : "all"}
          onChange={(value) => setQuery({ product: value })}
          options={[["all", "Все продукты"], ...productNames.map((name) => [name, name] as [string, string])]}
        />
      </div>
      <LiveCveTable registry />
      <DetailDrawer />
    </div>
  );
}

function FilterSelect({ value, onChange, options }: { value: string; onChange: (value: string) => void; options: Array<[string, string]> }) {
  return <VcSelect value={value} onChange={onChange} options={options} className="bg-[var(--vc-inset-2)]" />;
}

function unique(values: string[]) {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

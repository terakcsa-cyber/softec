"use client";

import type { ReactNode } from "react";
import { Donut, Ring } from "./charts";
import { DashPublicationTrend, DashRankBars, fillUtcDays, publicationWeekDelta } from "./dashboard-charts";
import { DetailDrawer } from "./detail-drawer";
import { LiveCveTable } from "./live-table";
import { useVc } from "./vc-context";
import {
  formatInt,
  useCatalogSummary,
  useExploitRadar,
  useVendorWindow,
  windowHoursFor
} from "@/lib/vulncontrol/live";
import type { ExploitSignal, Severity } from "@/lib/vulncontrol/types";

const SEVERITY_PICK: Severity[] = ["critical", "high", "medium", "low"];

export function DashboardView() {
  const { query, setQuery, setPage, setSelectedId } = useVc();
  const summary = useCatalogSummary();
  const vendors = useVendorWindow(query.range);
  const radar = useExploitRadar();
  const data = summary.data;
  const severity = data?.severity;
  const total = data?.totalCves ?? 0;
  const series = Array.isArray(data?.publishedByDay) ? data.publishedByDay : null;
  const span = query.range === "7d" ? 7 : 30;
  const days = series ? fillUtcDays(series, span) : [];
  const delta = series ? publicationWeekDelta(series) : null;
  const longRange = query.range === "90d" || query.range === "all";
  const vendorDays = Math.round(windowHoursFor(query.range) / 24);

  const slices = severity
    ? [
        { key: "critical", label: "Критические", value: severity.critical, pct: 0 },
        { key: "high", label: "Высокие", value: severity.high, pct: 0 },
        { key: "medium", label: "Средние", value: severity.medium, pct: 0 },
        { key: "low", label: "Низкие", value: severity.low, pct: 0 },
        ...(severity.unscored > 0 ? [{ key: "unscored", label: "Без CVSS", value: severity.unscored, pct: 0 }] : [])
      ]
    : [];
  const sliceSum = slices.reduce((sum, slice) => sum + slice.value, 0);

  const openSeverity = (key: Severity) => {
    setQuery({ severity: key, tab: "all", exploitSignal: "all", kevAddedDays: null, publishedDays: null });
    setPage("vulns");
  };

  const openSignal = (signal: ExploitSignal) => {
    setQuery({
      tab: "all",
      severity: "all",
      exploitSignal: signal,
      kevAddedDays: null,
      publishedDays: null,
      vendor: "all",
      product: "all",
      q: ""
    });
    setPage("vulns");
  };

  const radarRows = radar.data
    ? [
        {
          key: "spike",
          name: "Скачок EPSS",
          value: radar.data.epssSpikes,
          onPick: () => openSignal("epss_spike")
        },
        {
          key: "exploit",
          name: "Публичный эксплойт",
          value: radar.data.withPublicExploit,
          onPick: () => openSignal("has_public_exploit")
        },
        {
          key: "poc",
          name: "Есть PoC",
          value: radar.data.withPoc,
          onPick: () => openSignal("has_poc")
        },
        {
          key: "vckev",
          name: "VulnCheck KEV, не CISA",
          value: radar.data.vckevOnly,
          onPick: () => openSignal("vckev_only")
        },
        {
          key: "vckev7",
          name: "Новые VulnCheck KEV, 7 дн.",
          value: radar.data.newVckev7d,
          onPick: () => openSignal("new_vckev_7d")
        },
        {
          key: "epss",
          name: "EPSS ≥ 0.7",
          value: data?.highEpssCount ?? 0,
          onPick: () => {
            setQuery({ tab: "epss", severity: "all", exploitSignal: "all", kevAddedDays: null, publishedDays: null });
            setPage("vulns");
          }
        }
      ]
    : [];

  const spikeHighlights = (radar.data?.highlights ?? []).filter((row) => row.epss_spike).slice(0, 6);

  return (
    <div className="space-y-3">
      {summary.isError ? <p className="text-[12px] text-[var(--vc-danger-text)]">Сводка каталога не загрузилась.</p> : null}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-8">
        <Kpi label="Критические" hint="CVSS ≥ 9 · каталог" value={severity?.critical} total={total} color="var(--vc-critical)" onClick={() => openSeverity("critical")} />
        <Kpi label="Высокие" hint="CVSS 7–8.9 · каталог" value={severity?.high} total={total} color="var(--vc-high)" onClick={() => openSeverity("high")} />
        <Kpi label="Средние" hint="CVSS 4–6.9 · каталог" value={severity?.medium} total={total} color="var(--vc-medium)" onClick={() => openSeverity("medium")} />
        <Kpi label="Низкие" hint="CVSS < 4 · каталог" value={severity?.low} total={total} color="var(--vc-low)" onClick={() => openSeverity("low")} />
        <Kpi label="Всего CVE" hint="Записей в каталоге" value={data?.totalCves} color="var(--vc-purple)" onClick={() => { setQuery({ severity: "all", tab: "all", kevAddedDays: null, publishedDays: null, exploitSignal: "all" }); setPage("vulns"); }} />
        <Kpi label="CISA KEV" hint="Весь каталог KEV" value={data?.kevCount} total={total} color="var(--vc-kev)" onClick={() => { setQuery({ tab: "kev", severity: "all", kevAddedDays: null, publishedDays: null, exploitSignal: "all" }); setPage("vulns"); }} />
        <Kpi
          label="Новые CISA KEV"
          hint="Добавлено за 7 дн."
          value={data?.newCisaKev7dCount}
          color="var(--vc-critical)"
          onClick={() => { setQuery({ tab: "kev", severity: "all", kevAddedDays: 7, publishedDays: null, exploitSignal: "all", vendor: "all", product: "all", q: "" }); setPage("vulns"); }}
        />
        <Kpi
          label="Скачок EPSS"
          hint="Рост вероятности · 7 дн."
          value={radar.data?.epssSpikes}
          color="var(--vc-epss)"
          onClick={() => openSignal("epss_spike")}
        />
      </div>
      <p className="text-[11px] text-[var(--vc-muted)]">
        «Новые CISA KEV» и «Скачок EPSS» открывают рабочие срезы в реестре. Полосы Exploit intel тоже кликабельны. Период шапки меняет график публикаций и топ вендоров.
      </p>

      <div className="grid gap-3 xl:grid-cols-[minmax(0,1.05fr)_minmax(0,1.4fr)_minmax(0,1fr)]">
        <Panel title="Распределение по CVSS">
          {summary.isLoading ? <Pending /> : summary.isError ? <Failed /> : sliceSum > 0 ? (
            <Donut
              slices={slices}
              colors={["var(--vc-critical)", "var(--vc-high)", "var(--vc-medium)", "var(--vc-low)", "var(--vc-slate)"]}
              center={formatInt(data?.totalCves)}
              sub="CVE"
              svgClassName="h-[148px] w-[148px]"
              onPick={(key) => {
                if (!SEVERITY_PICK.includes(key as Severity)) return;
                openSeverity(key as Severity);
              }}
            />
          ) : <Empty />}
        </Panel>
        <Panel
          title="Публикации NVD"
          extra={delta ? <WeekDelta delta={delta} /> : <span className="text-[11px] text-[var(--vc-muted)]">{span === 7 ? "7 дней" : "30 дней"}</span>}
        >
          {summary.isLoading ? <Pending /> : summary.isError ? <Failed /> : series ? <DashPublicationTrend points={days} /> : <Empty />}
          {longRange ? <p className="mt-2 text-[11px] text-[var(--vc-muted)]">Ряд публикаций в API ограничен 30 днями.</p> : null}
        </Panel>
        <Panel title="Радар эксплуатации">
          {radar.isLoading ? <Pending /> : radar.isError ? <p className="text-[12px] text-[var(--vc-danger-text)]">Радар не загрузился.</p> : radar.data ? (
            <>
              <DashRankBars rows={radarRows} />
              <p className="mt-2 text-[11px] text-[var(--vc-muted)]">Клик по полосе открывает CVE с этим сигналом. Счётчики пересекаются.</p>
            </>
          ) : <Empty />}
        </Panel>
      </div>

      <div className="grid gap-3 xl:grid-cols-[1fr_1fr_minmax(0,0.95fr)]">
        <Panel
          title="Топ продуктов"
          extra={<span className="text-[11px] text-[var(--vc-muted)]">{vendors.data ? `за ${vendorDays} дн.` : ""}</span>}
        >
          {vendors.isLoading ? <Pending /> : vendors.isError ? <p className="text-[12px] text-[var(--vc-danger-text)]">Выборка продуктов не загрузилась.</p> : vendors.data?.products.length ? (
            <DashRankBars
              rows={vendors.data.products.filter((row) => row.product).slice(0, 6).map((row) => ({
                key: `${row.vendor}:${row.product}`,
                name: row.product,
                value: row.count,
                onPick: () => {
                  setQuery({ product: row.product, tab: "all", severity: "all" });
                  setPage("vulns");
                }
              }))}
            />
          ) : <Empty />}
          {vendors.data ? <p className="mt-2 text-[11px] text-[var(--vc-muted)]">Выборка {formatInt(vendors.data.sampledCves)} CVE за {vendorDays} дн.</p> : null}
          {longRange && vendors.data ? <p className="mt-1 text-[11px] text-[var(--vc-muted)]">Окно вендоров и продуктов в API — {vendorDays} дней, не весь выбранный период.</p> : null}
        </Panel>
        <Panel
          title="Топ вендоров"
          extra={<span className="text-[11px] text-[var(--vc-muted)]">{vendors.data ? `за ${vendorDays} дн.` : ""}</span>}
        >
          {vendors.isLoading ? <Pending /> : vendors.isError ? <p className="text-[12px] text-[var(--vc-danger-text)]">Выборка вендоров не загрузилась.</p> : vendors.data?.vendors.length ? (
            <DashRankBars
              rows={vendors.data.vendors.filter((row) => row.vendor).slice(0, 6).map((row) => ({
                key: row.vendor,
                name: row.vendor,
                value: row.count,
                onPick: () => {
                  setQuery({ vendor: row.vendor, tab: "all", severity: "all" });
                  setPage("vulns");
                }
              }))}
            />
          ) : <Empty />}
        </Panel>
        <Panel
          title="Горячие EPSS spike"
          extra={
            <button type="button" className="text-[11px] text-[var(--vc-link)] hover:underline" onClick={() => openSignal("epss_spike")}>
              Весь срез →
            </button>
          }
        >
          {radar.isLoading ? <Pending /> : spikeHighlights.length ? (
            <ul className="divide-y divide-[var(--vc-border)]">
              {spikeHighlights.map((row) => (
                <li key={row.cve_id}>
                  <button
                    type="button"
                    className="flex w-full items-center justify-between gap-2 py-1.5 text-left hover:bg-[var(--vc-hover)]"
                    onClick={() => {
                      setQuery({ tab: "all", severity: "all", exploitSignal: "epss_spike", q: "", kevAddedDays: null, publishedDays: null });
                      setSelectedId(row.cve_id);
                      setPage("vulns");
                    }}
                  >
                    <span className="truncate font-mono text-[12px] font-semibold text-[var(--vc-link)]">{row.cve_id}</span>
                    <span className="shrink-0 tabular-nums text-[11px] text-[var(--vc-muted)]">
                      {row.epss == null ? "—" : `${(row.epss * 100).toFixed(1)}%`}
                      {row.cvss_base != null ? ` · ${row.cvss_base.toFixed(1)}` : ""}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          ) : <Empty />}
        </Panel>
      </div>

      <div>
        <h2 className="mb-2 text-[13px] font-semibold">Приоритетные CVE</h2>
        <LiveCveTable caption="Первые 12 записей по риску. Полный реестр — в разделе «Уязвимости»." />
      </div>
      <DetailDrawer />
    </div>
  );
}

function WeekDelta({ delta }: { delta: { recent: number; previous: number; pct: number | null } }) {
  return (
    <span className="flex flex-wrap items-center justify-end gap-1.5 text-[11px]">
      <span className="tabular-nums text-[var(--vc-muted)]">7 дн.: {formatInt(delta.recent)}</span>
      {delta.pct == null ? (
        <span className="tabular-nums text-[var(--vc-muted)]">пред. 7 дн.: {formatInt(delta.previous)}</span>
      ) : (
        <DeltaChip pct={delta.pct} />
      )}
    </span>
  );
}

function DeltaChip({ pct }: { pct: number }) {
  const up = pct > 0;
  const down = pct < 0;
  const color = up ? "var(--vc-high)" : down ? "var(--vc-success)" : "var(--vc-muted)";
  const label = pct > 0 ? `+${pct}%` : `${pct}%`;
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full px-1.5 py-0.5 text-[10px] font-semibold tabular-nums"
      style={{ color, background: `color-mix(in srgb, ${color} 16%, transparent)` }}
      title="Последние 7 календарных суток UTC против предыдущих 7"
    >
      {up ? "▲" : down ? "▼" : "·"} {label}
      <span className="font-normal text-[var(--vc-muted)]">к пред. 7 дн.</span>
    </span>
  );
}

function shareOf(value: number, total: number) {
  if (total <= 0 || !Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, (value / total) * 100));
}

function shareLabel(pct: number) {
  if (pct > 0 && pct < 0.1) return "<0,1%";
  const digits = pct >= 10 ? 0 : 1;
  return `${new Intl.NumberFormat("ru-RU", { maximumFractionDigits: digits, minimumFractionDigits: digits }).format(pct)}%`;
}

function Kpi({
  label,
  hint,
  value,
  total,
  color,
  onClick
}: {
  label: string;
  hint: string;
  value: number | null | undefined;
  total?: number;
  color: string;
  onClick: () => void;
}) {
  const share = value != null && total != null && total > 0 ? shareOf(value, total) : null;
  return (
    <button
      type="button"
      onClick={onClick}
      className="relative min-h-[112px] overflow-hidden rounded-xl border bg-[var(--vc-surface)] px-3 py-3 text-left hover:border-[var(--vc-hover-border)]"
      style={{
        borderColor: `color-mix(in srgb, ${color} 42%, var(--vc-border))`,
        backgroundImage: `linear-gradient(165deg, color-mix(in srgb, ${color} 18%, transparent), transparent 68%)`
      }}
    >
      <span className="absolute inset-x-0 top-0 h-1" style={{ background: color }} />
      <span className="flex items-start justify-between gap-2">
        <span className="min-w-0">
          <span className="block text-[11px] text-[var(--vc-muted)]">{label}</span>
          <span className="mt-1 block text-[26px] font-semibold leading-none tabular-nums" style={{ color }}>
            {value == null ? "…" : formatInt(value)}
          </span>
        </span>
        {share != null ? (
          <span className="flex shrink-0 flex-col items-center" title="Доля каталога">
            <Ring pct={share} color={color} />
            <span className="-mt-0.5 text-[9px] tabular-nums text-[var(--vc-muted)]">{shareLabel(share)}</span>
          </span>
        ) : null}
      </span>
      <span className="mt-2 block text-[10px] text-[var(--vc-muted)]">{hint}</span>
      {share != null ? (
        <span className="mt-2 block h-1.5 overflow-hidden rounded-full bg-[var(--vc-track)]">
          <span className="block h-full rounded-full" style={{ width: `${share}%`, background: color }} />
        </span>
      ) : (
        <span className="mt-2 block h-1.5" />
      )}
    </button>
  );
}

function Panel({ title, extra, children }: { title: string; extra?: ReactNode; children: ReactNode }) {
  return (
    <section className="min-w-0 rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-3">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-2">
        <h2 className="text-[13px] font-semibold">{title}</h2>
        {extra}
      </div>
      {children}
    </section>
  );
}

function Pending() {
  return <p className="text-[12px] text-[var(--vc-muted)]">Загрузка…</p>;
}

function Empty() {
  return <p className="text-[12px] text-[var(--vc-muted)]">Нет данных</p>;
}

function Failed() {
  return <p className="text-[12px] text-[var(--vc-danger-text)]">Сводка каталога не загрузилась.</p>;
}

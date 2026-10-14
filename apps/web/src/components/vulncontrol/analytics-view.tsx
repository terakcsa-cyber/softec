"use client";

import { useMemo } from "react";
import { useRouter } from "next/navigation";
import { ArrowDownRight, ArrowRight, ArrowUpRight } from "lucide-react";
import { CountBars, Donut, FlowChart, HBars } from "./charts";
import { vulnerabilityPath } from "./vc-context";
import { useVc } from "./vc-context";
import {
  cvssBand,
  formatInt,
  useAnalyticsSeries,
  useCveList,
  useExploitRadar,
  useVendorWindow,
  type AnalyticsDay,
  type AnalyticsPulse,
  type LiveCve
} from "@/lib/vulncontrol/live";
import { EMPTY_QUERY } from "@/lib/vulncontrol/types";

type Direction = "up" | "down" | "flat";
type MetricKey = "published" | "critical" | "kev" | "network";

const VECTOR_LABEL: Record<string, string> = {
  NETWORK: "Сетевой",
  ADJACENT_NETWORK: "Смежная сеть",
  LOCAL: "Локальный",
  PHYSICAL: "Физический"
};

export function AnalyticsView() {
  const router = useRouter();
  const { query, setQuery, setPage } = useVc();
  const series = useAnalyticsSeries();
  const radar = useExploitRadar();
  const spikeList = useCveList(
    { ...EMPTY_QUERY, exploitSignal: "epss_spike" },
    { limit: 12, includeTotal: true }
  );
  const vendors = useVendorWindow(query.range === "7d" ? "7d" : "30d");
  const days = series.data?.days ?? [];
  const span = query.range === "7d" ? 7 : 15;
  const current = days.slice(-span);
  const previous = days.slice(-span * 2, -span);
  const chartDays = query.range === "7d" ? days.slice(-14) : days;
  const published = metric(current, previous, "published");
  const critical = metric(current, previous, "critical");
  const kev = metric(current, previous, "kev");
  const network = metric(current, previous, "network");
  const lead = useMemo(() => strongest([
    { label: "Публикации NVD", trend: published },
    { label: "CVSS ≥ 9", trend: critical },
    { label: "Новые записи CISA KEV", trend: kev },
    { label: "Сетевой вектор CVSS", trend: network }
  ]), [published, critical, kev, network]);
  const windowNote = query.range === "7d"
    ? "последние 7 дней против предыдущих 7"
    : "последние 15 дней против предыдущих 15";
  const vectors = vectorSlices(current);
  const vectorSum = vectors.reduce((acc, slice) => acc + slice.value, 0);
  const pulseTotal = series.data?.pulseTotal ?? series.data?.pulse.length ?? 0;
  const pulseShown = series.data?.pulse.length ?? 0;
  const spikeCount = radar.data?.epssSpikes ?? spikeList.data?.total ?? null;
  const spikeRows = spikeList.data?.items ?? [];

  function openVulns(patch: Parameters<typeof setQuery>[0]) {
    setQuery({
      q: "",
      vendor: "all",
      product: "all",
      status: "all",
      kevAddedDays: null,
      publishedDays: null,
      exploitSignal: "all",
      ...patch
    });
    setPage("vulns");
  }

  return (
    <div className="space-y-3">
      <section className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] px-4 py-3">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 className="text-[15px] font-semibold">Куда идёт каталог</h2>
            <p className="mt-1 text-[12px] text-[var(--vc-muted)]">
              {series.data ? lead : series.isError ? "Ряд не загрузился" : "Считаю тренд…"}
              {series.data ? ` · ${windowNote}` : ""}
            </p>
          </div>
          <span className="text-[11px] text-[var(--vc-muted)]">
            {series.data?.generatedAt ? `обновлено ${formatClock(series.data.generatedAt)}` : "лента обновляется раз в минуту"}
          </span>
        </div>
        <p className="mt-2 text-[11px] text-[var(--vc-muted)]">Карточки и столбцы кликабельны: открывают реестр CVE с тем же срезом.</p>
      </section>

      {query.range === "90d" || query.range === "all" ? (
        <p className="text-[11px] text-[var(--vc-muted)]">Ряд построен по последним 30 дням каталога.</p>
      ) : null}

      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
        <TrendCard
          label="Публикации"
          hint="NVD · клик → реестр"
          trend={published}
          color="var(--vc-primary)"
          onClick={() => openVulns({ tab: "all", severity: "all", publishedDays: span, kevAddedDays: null })}
        />
        <TrendCard
          label="CVSS ≥ 9"
          hint="среди новых · клик → реестр"
          trend={critical}
          color="var(--vc-critical)"
          onClick={() => openVulns({ tab: "all", severity: "critical", publishedDays: span, kevAddedDays: null })}
        />
        <TrendCard
          label="CISA KEV"
          hint="добавлено за окно · клик → реестр"
          trend={kev}
          color="var(--vc-high)"
          onClick={() => openVulns({ tab: "kev", severity: "all", kevAddedDays: span, publishedDays: null })}
        />
        <TrendCard
          label="Сетевой вектор"
          hint="CVSS Attack Vector"
          trend={network}
          color="var(--vc-low)"
          onClick={() => openVulns({ tab: "all", severity: "all", publishedDays: span, kevAddedDays: null })}
        />
      </div>

      <section className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)]">
        <div className="flex flex-wrap items-end justify-between gap-2 border-b border-[var(--vc-border)] px-3 py-2.5">
          <div>
            <h2 className="text-[13px] font-semibold">Скачок EPSS</h2>
            <p className="mt-0.5 text-[11px] text-[var(--vc-muted)]">
              CVE с резким ростом вероятности эксплуатации за 7 дней — приоритет triage, не «просто высокий EPSS».
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() => openVulns({ tab: "all", severity: "all", exploitSignal: "epss_spike" })}
              className="rounded-lg border border-[color-mix(in_srgb,var(--vc-epss)_40%,transparent)] bg-[color-mix(in_srgb,var(--vc-epss)_12%,transparent)] px-3 py-1.5 text-left"
            >
              <span className="block text-[10px] uppercase tracking-wide text-[var(--vc-muted)]">В каталоге</span>
              <span className="text-[18px] font-semibold tabular-nums" style={{ color: "var(--vc-epss)" }}>
                {spikeCount == null ? "…" : formatInt(spikeCount)}
              </span>
            </button>
            <button
              type="button"
              className="text-[11px] text-[var(--vc-link)] hover:underline"
              onClick={() => openVulns({ tab: "all", severity: "all", exploitSignal: "epss_spike" })}
            >
              Весь срез →
            </button>
          </div>
        </div>
        {spikeList.isLoading ? (
          <div className="px-3 py-3"><Pending /></div>
        ) : spikeRows.length ? (
          <SpikeTable items={spikeRows} onOpen={(cveId) => router.push(vulnerabilityPath(cveId))} />
        ) : (
          <div className="px-3 py-3"><Empty /></div>
        )}
      </section>

      <div className="grid gap-3 xl:grid-cols-[1.5fr_0.9fr]">
        <section className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-3">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-[13px] font-semibold">Публикации и критичные</h2>
            <button
              type="button"
              className="text-[11px] text-[var(--vc-link)] hover:underline"
              onClick={() => openVulns({ tab: "all", severity: "all", publishedDays: span, kevAddedDays: null })}
            >
              Открыть публикации окна →
            </button>
          </div>
          {series.isLoading ? <Pending /> : (
            <FlowChart
              direction={published.direction}
              points={chartDays.map((day) => ({ label: day.day, published: day.published, critical: day.critical }))}
            />
          )}
        </section>
        <section className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-3">
          <h2 className="mb-1 text-[13px] font-semibold">Вектор CVSS</h2>
          <p className="mb-3 text-[11px] text-[var(--vc-muted)]">Как описан доступ у CVE этого окна</p>
          {series.isLoading ? <Pending /> : vectorSum ? (
            <Donut
              slices={vectors}
              colors={["var(--vc-low)", "var(--vc-high)", "var(--vc-medium)", "var(--vc-critical)", "var(--vc-slate)"]}
              center={formatInt(vectorSum)}
              sub="CVE"
              onPick={() => openVulns({ tab: "all", severity: "all", publishedDays: span, kevAddedDays: null })}
            />
          ) : <Empty />}
        </section>
      </div>

      <section className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)]">
        <div className="flex flex-wrap items-end justify-between gap-2 border-b border-[var(--vc-border)] px-3 py-2.5">
          <div>
            <h2 className="text-[13px] font-semibold">Свежие публикации</h2>
            <p className="mt-0.5 text-[11px] text-[var(--vc-muted)]">
              {series.data
                ? `14 дней · до 3 сильных CVE на день · ${pulseShown} строк из ${formatInt(pulseTotal)}`
                : "последние 14 дней"}
            </p>
          </div>
          <button
            type="button"
            className="text-[11px] text-[var(--vc-link)] hover:underline"
            onClick={() => openVulns({ tab: "all", severity: "all", publishedDays: 14, kevAddedDays: null })}
          >
            Весь реестр за 14 дн. →
          </button>
        </div>
        {series.isLoading ? (
          <div className="px-3 py-3"><Pending /></div>
        ) : series.data?.pulse.length ? (
          <PulseTable
            items={series.data.pulse}
            onOpen={(cveId) => router.push(vulnerabilityPath(cveId))}
          />
        ) : (
          <div className="px-3 py-3"><Empty /></div>
        )}
      </section>

      <div className="grid gap-3 xl:grid-cols-2">
        <section className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-3">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-[13px] font-semibold">Новые CISA KEV по дням</h2>
            <button
              type="button"
              className="text-[11px] text-[var(--vc-link)] hover:underline"
              onClick={() => openVulns({ tab: "kev", severity: "all", kevAddedDays: span, publishedDays: null })}
            >
              Все за окно →
            </button>
          </div>
          {series.isLoading ? <Pending /> : (
            <CountBars
              points={chartDays.map((day) => ({ label: day.day, count: day.kev }))}
              onPick={() => openVulns({ tab: "kev", severity: "all", kevAddedDays: span, publishedDays: null })}
            />
          )}
          <p className="mt-2 text-[10px] text-[var(--vc-muted)]">Клик по столбцу открывает CVE, добавленные в CISA KEV за текущее окно аналитики.</p>
        </section>
        <section className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-3">
          <h2 className="mb-3 text-[13px] font-semibold">Вендоры окна</h2>
          {vendors.isLoading ? <Pending /> : vendors.data?.vendors.length ? (
            <HBars
              color="var(--vc-purple)"
              rows={vendors.data.vendors.slice(0, 6).map((row) => ({ name: row.vendor, value: row.count }))}
              onPick={(name) => openVulns({ vendor: name, tab: "all", severity: "all", publishedDays: span })}
            />
          ) : <Empty />}
        </section>
      </div>
    </div>
  );
}

function TrendCard({
  label,
  hint,
  trend,
  color,
  onClick
}: {
  label: string;
  hint: string;
  trend: ReturnType<typeof metric>;
  color: string;
  onClick?: () => void;
}) {
  const Icon = trend.direction === "up" ? ArrowUpRight : trend.direction === "down" ? ArrowDownRight : ArrowRight;
  const arrow = trend.direction === "up" ? "var(--vc-critical)" : trend.direction === "down" ? "var(--vc-success)" : "var(--vc-muted)";
  const body = (
    <>
      <div className="flex items-start justify-between gap-2">
        <div className="text-[11px] text-[var(--vc-muted)]">{label}</div>
        <Icon className="h-4 w-4" style={{ color: arrow }} aria-hidden />
      </div>
      <div className="mt-1 text-[22px] font-semibold tabular-nums" style={{ color }}>{formatInt(trend.current)}</div>
      <div className="mt-1 text-[11px] font-medium tabular-nums" style={{ color: arrow }}>{deltaText(trend)}</div>
      <div className="mt-0.5 text-[10px] text-[var(--vc-muted)]">{hint}</div>
    </>
  );
  if (!onClick) {
    return <section className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] px-3 py-3">{body}</section>;
  }
  return (
    <button
      type="button"
      onClick={onClick}
      className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] px-3 py-3 text-left transition hover:border-[color-mix(in_srgb,var(--vc-primary)_45%,transparent)] hover:bg-[var(--vc-hover)]"
    >
      {body}
    </button>
  );
}

function metric(current: AnalyticsDay[], previous: AnalyticsDay[], key: MetricKey) {
  const now = total(current, key);
  const before = total(previous, key);
  const delta = now - before;
  const direction: Direction = delta > 0 ? "up" : delta < 0 ? "down" : "flat";
  const pct = before > 0 ? Math.round((delta / before) * 1000) / 10 : null;
  return { current: now, previous: before, delta, pct, direction };
}

function total(days: AnalyticsDay[], key: MetricKey) {
  return days.reduce((acc, day) => acc + day[key], 0);
}

function deltaText(trend: ReturnType<typeof metric>) {
  if (trend.direction === "flat") return "как в прошлом окне";
  const sign = trend.delta > 0 ? "+" : "−";
  const pct = trend.pct == null ? "" : ` · ${trend.pct > 0 ? "+" : ""}${trend.pct}%`;
  return `${sign}${formatInt(Math.abs(trend.delta))}${pct}`;
}

function strongest(items: Array<{ label: string; trend: ReturnType<typeof metric> }>) {
  const ranked = [...items].sort((a, b) => {
    const ap = Math.abs(a.trend.pct ?? a.trend.delta);
    const bp = Math.abs(b.trend.pct ?? b.trend.delta);
    return bp - ap;
  });
  const top = ranked[0];
  if (!top || (top.trend.current === 0 && top.trend.previous === 0)) return "За окно движений нет";
  if (top.trend.direction === "flat") return `${top.label}: ${formatInt(top.trend.current)}, как в прошлом окне`;
  const verb = top.trend.direction === "up" ? "растёт" : "снижается";
  const pct = top.trend.pct == null ? "" : ` (${top.trend.pct > 0 ? "+" : ""}${top.trend.pct}%)`;
  return `${top.label} ${verb}: ${formatInt(top.trend.current)} против ${formatInt(top.trend.previous)}${pct}`;
}

function vectorSlices(days: AnalyticsDay[]) {
  const published = total(days, "published");
  const network = total(days, "network");
  const adjacent = days.reduce((acc, day) => acc + day.adjacent, 0);
  const local = days.reduce((acc, day) => acc + day.local, 0);
  const physical = days.reduce((acc, day) => acc + day.physical, 0);
  const unknown = Math.max(0, published - network - adjacent - local - physical);
  return [
    { key: "network", label: "Сетевой", value: network, pct: 0 },
    { key: "adjacent", label: "Смежная сеть", value: adjacent, pct: 0 },
    { key: "local", label: "Локальный", value: local, pct: 0 },
    { key: "physical", label: "Физический", value: physical, pct: 0 },
    ...(unknown ? [{ key: "unknown", label: "Без вектора", value: unknown, pct: 0 }] : [])
  ].filter((slice) => slice.value > 0);
}

function SpikeTable({ items, onOpen }: { items: LiveCve[]; onOpen: (cveId: string) => void }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full table-fixed border-separate border-spacing-0 text-left text-[12px]">
        <colgroup>
          <col className="w-[22%]" />
          <col className="w-[36%]" />
          <col className="w-[12%]" />
          <col className="w-[12%]" />
          <col className="w-[10%]" />
          <col className="w-[8%]" />
        </colgroup>
        <thead className="text-[10px] uppercase tracking-wide text-[var(--vc-muted)]">
          <tr>
            <th className="border-b border-[var(--vc-border)] bg-[var(--vc-table-head)] px-3 py-2 font-medium">CVE</th>
            <th className="border-b border-[var(--vc-border)] bg-[var(--vc-table-head)] px-3 py-2 font-medium">Продукт</th>
            <th className="border-b border-[var(--vc-border)] bg-[var(--vc-table-head)] px-3 py-2 font-medium">EPSS</th>
            <th className="border-b border-[var(--vc-border)] bg-[var(--vc-table-head)] px-3 py-2 font-medium">Δ 7д</th>
            <th className="border-b border-[var(--vc-border)] bg-[var(--vc-table-head)] px-3 py-2 font-medium">CVSS</th>
            <th className="border-b border-[var(--vc-border)] bg-[var(--vc-table-head)] px-3 py-2 text-right font-medium">Риск</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => {
            const product = [item.vp_product, item.vp_vendor].filter(Boolean).join(" · ") || "—";
            const band = cvssBand(item.cvss_base);
            const delta = item.epss_delta_7d;
            return (
              <tr key={item.cve_id} className="cursor-pointer hover:bg-[var(--vc-hover-row)]" onClick={() => onOpen(item.cve_id)}>
                <td className="border-b border-[var(--vc-line-mid)] px-3 py-2">
                  <div className="flex min-w-0 items-center gap-1.5">
                    <button
                      type="button"
                      className="truncate font-mono text-[12px] font-semibold text-[var(--vc-link)] hover:underline"
                      onClick={(event) => {
                        event.stopPropagation();
                        onOpen(item.cve_id);
                      }}
                    >
                      {item.cve_id}
                    </button>
                    {item.exploit_known ? <span className="shrink-0 rounded bg-[#ff4d5e] px-1 py-0.5 text-[9px] font-bold text-white">KEV</span> : null}
                  </div>
                </td>
                <td className="border-b border-[var(--vc-line-mid)] px-3 py-2">
                  <span className="block truncate" title={product}>{product}</span>
                </td>
                <td className="border-b border-[var(--vc-line-mid)] px-3 py-2 tabular-nums" style={{ color: "var(--vc-epss)" }}>
                  {item.epss == null ? "—" : `${(item.epss * 100).toFixed(1)}%`}
                </td>
                <td className="border-b border-[var(--vc-line-mid)] px-3 py-2 font-semibold tabular-nums" style={{ color: "var(--vc-high)" }}>
                  {delta == null ? "—" : `${delta > 0 ? "+" : ""}${(delta * 100).toFixed(1)} п.п.`}
                </td>
                <td className="border-b border-[var(--vc-line-mid)] px-3 py-2">
                  {band ? (
                    <span className="inline-flex rounded-md px-1.5 py-0.5 text-[11px] font-semibold tabular-nums text-white" style={{ background: band.color }}>
                      {item.cvss_base == null ? "—" : item.cvss_base.toFixed(1)}
                    </span>
                  ) : "—"}
                </td>
                <td className="border-b border-[var(--vc-line-mid)] px-3 py-2 text-right">
                  <span
                    className="inline-flex min-w-[2.2rem] justify-center rounded-md px-1.5 py-0.5 text-[12px] font-bold tabular-nums text-white"
                    style={{ background: riskTone(item.risk_score) }}
                  >
                    {item.risk_score == null ? "—" : Math.round(item.risk_score)}
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function PulseTable({ items, onOpen }: { items: AnalyticsPulse[]; onOpen: (cveId: string) => void }) {
  const groups = useMemo(() => groupPulseByDay(items), [items]);
  return (
    <div className="max-h-[440px] overflow-y-auto overflow-x-hidden">
      <table className="w-full table-fixed border-separate border-spacing-0 text-left text-[12px]">
        <colgroup>
          <col className="w-[22%]" />
          <col className="w-[38%]" />
          <col className="w-[10%]" />
          <col className="w-[10%]" />
          <col className="w-[12%]" />
          <col className="w-[8%]" />
        </colgroup>
        <thead className="sticky top-0 z-[1] text-[10px] uppercase tracking-wide text-[var(--vc-muted)]">
          <tr>
            <th className="border-b border-[var(--vc-border)] bg-[var(--vc-table-head)] px-3 py-2 font-medium">CVE</th>
            <th className="border-b border-[var(--vc-border)] bg-[var(--vc-table-head)] px-3 py-2 font-medium">Продукт</th>
            <th className="border-b border-[var(--vc-border)] bg-[var(--vc-table-head)] px-3 py-2 font-medium">CVSS</th>
            <th className="border-b border-[var(--vc-border)] bg-[var(--vc-table-head)] px-3 py-2 font-medium">Риск</th>
            <th className="border-b border-[var(--vc-border)] bg-[var(--vc-table-head)] px-3 py-2 font-medium">Вектор</th>
            <th className="border-b border-[var(--vc-border)] bg-[var(--vc-table-head)] px-3 py-2 text-right font-medium">Время</th>
          </tr>
        </thead>
        <tbody>
          {groups.map((group) => (
            <PulseDayGroup key={group.key} group={group} onOpen={onOpen} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PulseDayGroup({
  group,
  onOpen
}: {
  group: { key: string; label: string; items: AnalyticsPulse[] };
  onOpen: (cveId: string) => void;
}) {
  return (
    <>
      <tr>
        <td colSpan={6} className="border-b border-[var(--vc-border)] bg-[color-mix(in_srgb,var(--vc-table-head)_70%,transparent)] px-3 py-1.5">
          <div className="flex items-center justify-between gap-2 text-[11px]">
            <span className="font-semibold text-[var(--vc-text)]">{group.label}</span>
            <span className="tabular-nums text-[var(--vc-muted)]">{group.items.length} CVE</span>
          </div>
        </td>
      </tr>
      {group.items.map((item) => {
        const band = cvssBand(item.cvss);
        const product = [item.product, item.vendor].filter(Boolean).join(" · ") || "—";
        const vector = item.attackVector ? (VECTOR_LABEL[item.attackVector] ?? item.attackVector) : "—";
        return (
          <tr
            key={item.cveId}
            className="cursor-pointer hover:bg-[var(--vc-hover-row)]"
            onClick={() => onOpen(item.cveId)}
          >
            <td className="border-b border-[var(--vc-line-mid)] px-3 py-2 align-middle">
              <div className="flex min-w-0 items-center gap-1.5">
                <button
                  type="button"
                  className="truncate font-mono text-[12px] font-semibold text-[var(--vc-link)] hover:underline"
                  onClick={(event) => {
                    event.stopPropagation();
                    onOpen(item.cveId);
                  }}
                >
                  {item.cveId}
                </button>
                {item.kev ? (
                  <span className="shrink-0 rounded bg-[#ff4d5e] px-1 py-0.5 text-[9px] font-bold text-white">KEV</span>
                ) : null}
              </div>
            </td>
            <td className="border-b border-[var(--vc-line-mid)] px-3 py-2 align-middle">
              <span className="block truncate text-[12px] text-[var(--vc-text)]" title={product}>{product}</span>
            </td>
            <td className="border-b border-[var(--vc-line-mid)] px-3 py-2 align-middle">
              {band ? (
                <span className="inline-flex rounded-md px-1.5 py-0.5 text-[11px] font-semibold tabular-nums text-white" style={{ background: band.color }}>
                  {item.cvss == null ? "—" : item.cvss.toFixed(1)}
                </span>
              ) : (
                <span className="text-[var(--vc-muted)]">—</span>
              )}
            </td>
            <td className="border-b border-[var(--vc-line-mid)] px-3 py-2 align-middle">
              <span
                className="inline-flex min-w-[2.2rem] justify-center rounded-md px-1.5 py-0.5 text-[12px] font-bold tabular-nums text-white"
                style={{ background: riskTone(item.risk) }}
              >
                {item.risk == null ? "—" : Math.round(item.risk)}
              </span>
            </td>
            <td className="border-b border-[var(--vc-line-mid)] px-3 py-2 align-middle">
              <span className="block truncate text-[11px] text-[var(--vc-muted)]" title={vector}>{vector}</span>
            </td>
            <td className="border-b border-[var(--vc-line-mid)] px-3 py-2 align-middle text-right tabular-nums text-[11px] text-[var(--vc-muted)]">
              {pulseClock(item.publishedAt)}
            </td>
          </tr>
        );
      })}
    </>
  );
}

function groupPulseByDay(items: AnalyticsPulse[]) {
  const map = new Map<string, AnalyticsPulse[]>();
  for (const item of items) {
    const key = dayKey(item.publishedAt);
    const bucket = map.get(key);
    if (bucket) bucket.push(item);
    else map.set(key, [item]);
  }
  const formatter = new Intl.DateTimeFormat("ru-RU", {
    weekday: "short",
    day: "2-digit",
    month: "short"
  });
  return [...map.entries()].map(([key, rows]) => {
    const date = key === "unknown" ? null : new Date(`${key}T12:00:00.000Z`);
    const label = !date || Number.isNaN(date.getTime())
      ? "Без даты"
      : formatter.format(date).replace(/\./g, "");
    return { key, label, items: rows };
  });
}

function dayKey(iso: string | null) {
  if (!iso) return "unknown";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "unknown";
  return date.toISOString().slice(0, 10);
}

function pulseClock(iso: string | null) {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("ru-RU", { hour: "2-digit", minute: "2-digit" }).format(date);
}

function riskTone(score: number | null) {
  if (score == null) return "var(--vc-slate)";
  if (score >= 90) return "var(--vc-critical)";
  if (score >= 70) return "var(--vc-high)";
  if (score >= 40) return "var(--vc-medium)";
  return "var(--vc-success)";
}

function formatClock(iso: string) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  return new Intl.DateTimeFormat("ru-RU", { hour: "2-digit", minute: "2-digit" }).format(date);
}

function Pending() {
  return <p className="text-[12px] text-[var(--vc-muted)]">Загрузка…</p>;
}

function Empty() {
  return <p className="text-[12px] text-[var(--vc-muted)]">Нет данных за это окно</p>;
}

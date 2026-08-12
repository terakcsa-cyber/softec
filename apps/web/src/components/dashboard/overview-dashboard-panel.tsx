"use client";

import { useMemo, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Activity,
  ArrowRight,
  ChevronRight,
  Clock,
  Inbox,
  Loader2,
  Radar,
  RefreshCw,
  ShieldAlert
} from "lucide-react";
import { cn } from "../ui/cn";
import { LiveNumber } from "../ui/live-number";
import type { HotCveRow } from "./critical-24h-board";
import { computeCvePriority } from "@/lib/cve-priority";
import { VocTriageCheckpoint, processedCardClass } from "./voc-triage-checkpoint";
import { ExploitIntelBadges } from "./exploit-intel-badges";
import { cveRefKey } from "@/lib/voc-ref-keys";
import { useVocTriage } from "@/lib/voc-triage-context";
import { VendorLandscape } from "./vendor-landscape";
import { ReadinessBar, type ReadinessPayload } from "./readiness-bar";
import { apiFetch } from "@/lib/api-fetch";
import { useLiveQueryOptions } from "@/lib/live-refresh";
import {
  EXPLOIT_RADAR_FILTER_LABELS,
  type ExploitRadarFilter,
  type ExploitRadarStats
} from "@/lib/exploit-intel-client";
import { fetchVocKpis } from "@/lib/voc-shift-api";
import { fetchVocQueue } from "@/lib/voc-api";

export type SummaryStats = {
  totalCves: number;
  cvesLastHourCount?: number;
  cvesPublishedLast24hCount?: number;
  maxPublishedAt?: string | null;
  totalBduCount?: number;
  bduPublishedLast24hCount?: number;
  cveBduLinkCount?: number;
  maxBduPublicationAt?: string | null;
  kevCount: number;
  epssCount: number;
  cvssCount: number;
  scoredCount: number;
  aiEnrichedCount?: number;
  /** Hot-window (published last 24h) coverage — preferred “актуальность” denominator. */
  hot24CveCount?: number;
  hot24AiEnrichedCount?: number;
  hot24ScoredCount?: number;
  hot24EpssCount?: number;
  hot24CvssCount?: number;
  freshness?: {
    nvdWatermarkTs?: string | null;
    epssIngestTs?: string | null;
    kevIngestTs?: string | null;
    riskScoreComputedAt?: string | null;
    bduIngestTs?: string | null;
  };
};

function pct(n: number, d: number) {
  if (d <= 0 || !Number.isFinite(n) || !Number.isFinite(d)) return 0;
  return Math.min(100, Math.round((n / d) * 1000) / 10);
}

function fmtTs(iso: string | null | undefined) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

function fmtRel(iso: string | null | undefined) {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return "—";
  const h = (Date.now() - t) / 3_600_000;
  if (h < 0) return "сейчас";
  if (h < 1) return `${Math.max(1, Math.round(h * 60))}м`;
  if (h < 48) return `${h.toFixed(1)}ч`;
  return `${(h / 24).toFixed(1)}д`;
}

function freshnessTone(iso: string | null | undefined): string {
  if (!iso) return "text-muted";
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return "text-muted";
  const h = (Date.now() - t) / 3_600_000;
  if (h <= 24) return "text-ok";
  if (h <= 72) return "text-warn";
  return "text-danger";
}

function intelHealthScore(p: { risk: number; epss: number; cvss: number; ai: number }): number {
  const w = { risk: 0.32, epss: 0.26, cvss: 0.22, ai: 0.2 };
  return Math.round((p.risk * w.risk + p.epss * w.epss + p.cvss * w.cvss + p.ai * w.ai) * 10) / 10;
}

function healthLabel(score: number): { label: string; cls: string } {
  if (score >= 85) return { label: "Отлично", cls: "text-ok" };
  if (score >= 65) return { label: "Хорошо", cls: "text-accent" };
  if (score >= 40) return { label: "Средне", cls: "text-warn" };
  return { label: "Слабо", cls: "text-danger" };
}

function computePerimeterScore(it: HotCveRow): { score: number; reasons: string[] } {
  let s = 0;
  const reasons: string[] = [];
  const add = (n: number, r: string) => {
    s += n;
    reasons.push(r);
  };
  if (it.perimeter_product) add(22, "edge/web/VPN продукт (CPE)");
  if (it.cvss_av_network) add(25, "CVSS AV:N (network)");
  if (it.cvss_av_network && it.cvss_pr_none) add(18, "CVSS PR:N (без привилегий)");
  if (it.cvss_av_network && it.cvss_ui_none) add(12, "CVSS UI:N (без пользователя)");
  if (it.cvss_av_network && it.cvss_ac_low) add(8, "CVSS AC:L (низкая сложность)");
  if (it.exploit_known) add(15, "KEV (известная эксплуатация)");
  if (typeof it.epss === "number" && it.epss >= 0.6) add(10, "EPSS ≥ 0.60");
  else if (typeof it.epss === "number" && it.epss >= 0.3) add(6, "EPSS ≥ 0.30");
  return { score: Math.max(0, Math.min(100, Math.round(s))), reasons };
}

function CoverageTrack({
  label,
  value,
  total,
  tone,
  hint
}: {
  label: string;
  value: number;
  total: number;
  tone: string;
  hint?: string;
}) {
  const p = pct(value, total);
  return (
    <div className="min-w-0" title={hint}>
      <div className="mb-1 flex items-baseline justify-between gap-2 text-[11px]">
        <span className="text-muted">{label}</span>
        <span className="tabular-nums text-fg/85">
          <LiveNumber value={p} fractionDigits={1} suffix="%" />
          <span className="mx-1.5 text-border" aria-hidden>
            ·
          </span>
          <span className="text-muted">
            <LiveNumber value={value} />
            <span className="mx-0.5 opacity-70">/</span>
            <LiveNumber value={total} />
          </span>
        </span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-slate-200/80 dark:bg-white/[0.06]">
        <motion.div
          className={cn("h-full rounded-full", tone)}
          initial={{ width: "0%" }}
          animate={{ width: `${p}%` }}
          transition={{ type: "spring", stiffness: 90, damping: 22 }}
        />
      </div>
    </div>
  );
}

function SectionHead({
  title,
  hint,
  action
}: {
  title: string;
  hint?: string;
  action?: ReactNode;
}) {
  return (
    <div className="mb-3 flex flex-wrap items-start justify-between gap-2">
      <div className="min-w-0">
        <div className="text-[13px] font-semibold tracking-tight text-fg/95">{title}</div>
        {hint ? <p className="mt-0.5 text-[11px] leading-relaxed text-muted">{hint}</p> : null}
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}

function LinkChip({
  label,
  onClick
}: {
  label: string;
  onClick?: () => void;
}) {
  if (!onClick) return null;
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex items-center gap-1 text-[11px] text-accent hover:underline"
    >
      {label}
      <ChevronRight className="h-3 w-3" />
    </button>
  );
}

export function OverviewDashboardPanel({
  data,
  loading,
  error,
  vendors,
  onVendorSelect,
  onProductSelect,
  onOpenSystemHealth,
  onOpenCve,
  onOpenVoc,
  onOpenVulns,
  onOpenThreat,
  topPriorityCves,
  topPriorityLoading,
  onTopPriorityCveClick,
  vendorsLoading,
  dashboardHighlightCveIds: _dashboardHighlightCveIds,
  onRefresh,
  refreshing,
  onExploitFilter,
  exploitFilter
}: {
  data: SummaryStats | undefined;
  loading: boolean;
  error: Error | null;
  vendors?: {
    windowHours: number;
    sampledCves: number;
    sampledBdu?: number;
    sampledTotal?: number;
    usedBdu?: number;
    method?: string;
    usedCpe?: number;
    usedFallback?: number;
    vendors: { vendor: string; count: number }[];
    products: { vendor: string; product: string; count: number }[];
  };
  onVendorSelect?: (vendor: string) => void;
  onProductSelect?: (vendor: string, product: string) => void;
  onOpenSystemHealth?: () => void;
  onOpenCve?: (cveId: string) => void;
  onOpenVoc?: () => void;
  onOpenVulns?: () => void;
  onOpenThreat?: () => void;
  topPriorityCves?: HotCveRow[];
  topPriorityLoading?: boolean;
  onTopPriorityCveClick?: (cveId: string) => void;
  vendorsLoading?: boolean;
  dashboardHighlightCveIds?: ReadonlySet<string> | null;
  onRefresh?: () => void;
  refreshing?: boolean;
  onExploitFilter?: (filter: ExploitRadarFilter) => void;
  exploitFilter?: ExploitRadarFilter | null;
}) {
  const { isDone } = useVocTriage();
  const live = useLiveQueryOptions();

  const readinessQ = useQuery({
    queryKey: ["stats", "readiness", "overview"],
    queryFn: async () => {
      const res = await apiFetch("/api/stats/readiness", { cache: "no-store" });
      if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
      return (await res.json()) as ReadinessPayload;
    },
    ...live
  });

  const exploitQ = useQuery({
    queryKey: ["stats", "exploit-radar", "overview"],
    queryFn: async () => {
      const res = await apiFetch("/api/stats/exploit-radar", { cache: "no-store" });
      if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
      return (await res.json()) as ExploitRadarStats;
    },
    ...live
  });

  const vocKpiQ = useQuery({
    queryKey: ["voc", "kpis", "overview", 8],
    queryFn: () => fetchVocKpis(8),
    ...live
  });

  const vocQueueQ = useQuery({
    queryKey: ["voc", "queue", "overview", "open", 8],
    queryFn: () => fetchVocQueue({ status: "open", limit: 8 }),
    ...live
  });

  const metrics = useMemo(() => {
    if (!data) return null;
    const total = data.totalCves;
    const ai = data.aiEnrichedCount ?? 0;
    const hotTotal = data.hot24CveCount ?? data.cvesPublishedLast24hCount ?? 0;
    const hotAi = data.hot24AiEnrichedCount ?? 0;
    const hotScored = data.hot24ScoredCount ?? 0;
    const hotEpss = data.hot24EpssCount ?? 0;
    const hotCvss = data.hot24CvssCount ?? 0;
    const useHot = hotTotal > 0;
    const pRisk = pct(useHot ? hotScored : data.scoredCount, useHot ? hotTotal : total);
    // EPSS daily feed lags new NVD publishes by ~1 day — hot-24h EPSS≈0 is normal, not a broken sync.
    const pEpssCorpus = pct(data.epssCount, total);
    const pEpssHot = pct(hotEpss, hotTotal);
    const pCvss = pct(useHot ? hotCvss : data.cvssCount, useHot ? hotTotal : total);
    const pAi = pct(useHot ? hotAi : ai, useHot ? hotTotal : total);
    const health = intelHealthScore({ risk: pRisk, epss: pEpssCorpus, cvss: pCvss, ai: pAi });
    const corpusAiPct = pct(ai, total);
    return {
      total,
      ai,
      hotTotal,
      hotAi,
      hotScored,
      hotEpss,
      hotCvss,
      useHot,
      pRisk,
      pEpss: pEpssCorpus,
      pEpssHot,
      pCvss,
      pAi,
      health,
      corpusAiPct
    };
  }, [data]);

  const priorityRows = useMemo(() => {
    return (topPriorityCves ?? []).slice(0, 14).map((it) => {
      const p = computeCvePriority(it);
      const per = computePerimeterScore(it);
      return { it, p, per };
    });
  }, [topPriorityCves]);

  const severityPulse = useMemo(() => {
    const rows = topPriorityCves ?? [];
    let critical = 0;
    let high = 0;
    let kev = 0;
    let perimeter = 0;
    for (const it of rows) {
      const p = computeCvePriority(it);
      if (p.level === "critical") critical += 1;
      else if (p.level === "high") high += 1;
      if (it.exploit_known) kev += 1;
      if (computePerimeterScore(it).score >= 55) perimeter += 1;
    }
    return { critical, high, kev, perimeter, n: rows.length };
  }, [topPriorityCves]);

  if (error) {
    return (
      <div className="rounded-xl border border-danger/30 bg-danger/10 p-5 text-sm text-danger">
        <div className="font-medium">Дашборд недоступен</div>
        <div className="mt-1 opacity-90">{error.message}</div>
      </div>
    );
  }

  if (loading || !data || !metrics) {
    return (
      <div className="space-y-4">
        <div className="h-5 w-48 animate-pulse rounded bg-slate-200/80 dark:bg-white/10" />
        <div className="h-24 animate-pulse rounded-xl bg-slate-200/50 dark:bg-white/[0.05]" />
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
          <div className="h-72 animate-pulse rounded-xl bg-slate-200/50 dark:bg-white/[0.05]" />
          <div className="h-72 animate-pulse rounded-xl bg-slate-200/50 dark:bg-white/[0.05]" />
        </div>
      </div>
    );
  }

  const { total, ai, health, hotTotal, hotAi, hotScored, hotEpss, hotCvss, useHot, corpusAiPct } = metrics;
  const hl = healthLabel(health);
  const exploit = exploitQ.data;
  const vocKpi = vocKpiQ.data;
  const vocItems = vocQueueQ.data?.items ?? [];

  const exploitTiles: { filter: ExploitRadarFilter; value: number }[] = [
    { filter: "vckev_only", value: exploit?.vckevOnly ?? 0 },
    { filter: "epss_spike", value: exploit?.epssSpikes ?? 0 },
    { filter: "new_vckev_7d", value: exploit?.newVckev7d ?? 0 },
    { filter: "has_poc", value: exploit?.withPoc ?? 0 },
    { filter: "has_public_exploit", value: exploit?.withPublicExploit ?? 0 }
  ];

  return (
    <div className="space-y-5">
      {/* Header + readiness — first viewport anchor */}
      <div className="space-y-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-base font-semibold tracking-tight">Обзор</h1>
              <span className={cn("text-[11px] font-medium tabular-nums", hl.cls)}>
                {useHot
                  ? `зрелость 24ч ${pct(hotAi, hotTotal).toFixed(0)}% · ${hl.label}`
                  : `покрытие ${health.toFixed(0)} · ${hl.label}`}
              </span>
            </div>
            <p className="mt-1 max-w-2xl text-[12px] leading-relaxed text-muted">
              Оперативная картина: что требует внимания, сигналы эксплуатации, очередь VOC и свежесть источников.
            </p>
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            <nav className="hidden items-center gap-1 sm:flex" aria-label="Быстрый переход">
              {[
                { label: "VOC", onClick: onOpenVoc },
                { label: "Уязвимости", onClick: onOpenVulns },
                { label: "Threat", onClick: onOpenThreat },
                { label: "Здоровье", onClick: onOpenSystemHealth }
              ]
                .filter((x) => x.onClick)
                .map((x) => (
                  <button
                    key={x.label}
                    type="button"
                    onClick={x.onClick}
                    className="rounded-md px-2 py-1 text-[11px] text-muted transition hover:bg-slate-100 hover:text-fg dark:hover:bg-white/[0.06]"
                  >
                    {x.label}
                  </button>
                ))}
            </nav>
            {onRefresh ? (
              <button
                type="button"
                title="Обновить сводку и приоритеты"
                onClick={() => onRefresh()}
                disabled={refreshing}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-lg border border-border bg-white px-2.5 py-1.5 text-[11px] text-fg/90",
                  "hover:bg-slate-50 dark:bg-black/20 dark:hover:bg-black/35",
                  refreshing && "cursor-wait opacity-80"
                )}
              >
                {refreshing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
                Обновить
              </button>
            ) : null}
          </div>
        </div>

        <button
          type="button"
          onClick={onOpenSystemHealth}
          disabled={!onOpenSystemHealth}
          className={cn(
            "block w-full text-left",
            onOpenSystemHealth && "cursor-pointer transition hover:opacity-95"
          )}
        >
          <ReadinessBar data={readinessQ.data} loading={readinessQ.isLoading} compact />
        </button>

        {/* Compact corpus pulse — not a card grid */}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-border/70 pb-3 text-[11px] text-muted">
          <span>
            CVE{" "}
            <span className="font-semibold tabular-nums text-fg/90">
              <LiveNumber value={total} />
            </span>
            {typeof data.cvesPublishedLast24hCount === "number" ? (
              <span className="ml-1 tabular-nums">(+{data.cvesPublishedLast24hCount.toLocaleString()} /24ч)</span>
            ) : null}
          </span>
          <span className="text-border">·</span>
          <span>
            БДУ{" "}
            <span className="font-semibold tabular-nums text-fg/90">
              <LiveNumber value={data.totalBduCount ?? 0} />
            </span>
            {typeof data.bduPublishedLast24hCount === "number" ? (
              <span className="ml-1 tabular-nums">(+{data.bduPublishedLast24hCount.toLocaleString()} /24ч)</span>
            ) : null}
          </span>
          <span className="text-border">·</span>
          <span>
            KEV{" "}
            <span className="font-semibold tabular-nums text-fg/90">
              <LiveNumber value={data.kevCount} />
            </span>
          </span>
          <span className="text-border">·</span>
          <span>
            ИИ{" "}
            <span className="font-semibold tabular-nums text-fg/90">
              <LiveNumber value={useHot ? hotAi : ai} />
            </span>
            {useHot ? (
              <span className="ml-1 tabular-nums">
                / {hotTotal.toLocaleString()} за 24ч ({pct(hotAi, hotTotal)}%)
              </span>
            ) : null}
          </span>
          <span className="text-border">·</span>
          <span>
            Risk scored{" "}
            <span className="font-semibold tabular-nums text-fg/90">
              <LiveNumber value={data.scoredCount} />
            </span>
          </span>
          {severityPulse.n > 0 ? (
            <>
              <span className="text-border">·</span>
              <span className="inline-flex flex-wrap items-center gap-2">
                <span className="text-danger tabular-nums">crit {severityPulse.critical}</span>
                <span className="text-warn tabular-nums">high {severityPulse.high}</span>
                <span className="tabular-nums">KEV {severityPulse.kev}</span>
                <span className="tabular-nums">периметр {severityPulse.perimeter}</span>
              </span>
            </>
          ) : null}
        </div>
      </div>

      {/* Main composition: attention + signals */}
      <div className="grid gap-5 lg:grid-cols-[minmax(0,1.4fr)_minmax(280px,0.95fr)] lg:items-start">
        <section className="min-w-0">
          <SectionHead
            title="Очередь приоритетов"
            hint="Топ по bank-priority + периметр (KEV / EPSS / CVSS AV:N). Клик открывает карточку CVE."
            action={<LinkChip label="Все уязвимости" onClick={onOpenVulns} />}
          />

          {topPriorityLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 8 }).map((_, i) => (
                <div key={i} className="h-9 animate-pulse rounded-md bg-slate-200/60 dark:bg-white/[0.04]" />
              ))}
            </div>
          ) : priorityRows.length ? (
            <div className="overflow-hidden rounded-lg border border-border/80">
              <div className="grid grid-cols-[minmax(0,1.15fr)_64px_64px_72px_56px] gap-2 border-b border-border/70 bg-slate-50/80 px-3 py-1.5 text-[10px] uppercase tracking-wide text-muted dark:bg-white/[0.03] sm:grid-cols-[minmax(0,1.4fr)_72px_72px_80px_64px_72px]">
                <div>CVE</div>
                <div className="text-right">Prio</div>
                <div className="hidden text-right sm:block">Перим.</div>
                <div className="text-right">EPSS</div>
                <div className="text-right">CVSS</div>
                <div className="text-right">Risk</div>
              </div>
              <ul className="divide-y divide-border/60">
                {priorityRows.map(({ it, p, per }) => {
                  const cveId = String(it.cve_id);
                  const done = isDone(cveRefKey(cveId));
                  const epss =
                    typeof it.epss === "number" && Number.isFinite(it.epss)
                      ? `${(it.epss * 100).toFixed(1)}%`
                      : "—";
                  const cvss =
                    typeof it.cvss_base === "number" && Number.isFinite(it.cvss_base)
                      ? it.cvss_base.toFixed(1)
                      : "—";
                  const prioCls =
                    p.level === "critical"
                      ? "text-danger"
                      : p.level === "high"
                        ? "text-warn"
                        : "text-fg/80";
                  const vendorLine = [it.vp_vendor, it.vp_product].filter(Boolean).join(" / ") || "—";
                  const short = it.short_ru || it.short_description || "";
                  return (
                    <li key={cveId}>
                      <button
                        type="button"
                        onClick={() => onTopPriorityCveClick?.(cveId)}
                        title={p.reasons.join(" • ")}
                        className={cn(
                          "grid w-full grid-cols-[minmax(0,1.15fr)_64px_64px_72px_56px] items-center gap-2 px-3 py-2 text-left transition",
                          "hover:bg-slate-50 dark:hover:bg-white/[0.03]",
                          "sm:grid-cols-[minmax(0,1.4fr)_72px_72px_80px_64px_72px]",
                          done && "opacity-70",
                          processedCardClass(done)
                        )}
                      >
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <VocTriageCheckpoint refKey={cveRefKey(cveId)} title={cveId} compact />
                            <span className="truncate text-[12px] font-semibold tracking-tight">{cveId}</span>
                            {it.exploit_known ? (
                              <span className="shrink-0 text-[9px] font-medium uppercase tracking-wide text-danger">
                                KEV
                              </span>
                            ) : null}
                            <ExploitIntelBadges item={it} compact />
                          </div>
                          <div className="mt-0.5 truncate text-[10px] text-muted">
                            {vendorLine}
                            {short ? ` — ${short}` : ""}
                          </div>
                        </div>
                        <div className={cn("text-right text-[12px] font-semibold tabular-nums", prioCls)}>
                          {p.score}
                        </div>
                        <div
                          className="hidden text-right text-[12px] tabular-nums text-fg/80 sm:block"
                          title={per.reasons.join(" • ")}
                        >
                          {per.score}
                        </div>
                        <div className="text-right text-[11px] tabular-nums text-fg/80">{epss}</div>
                        <div className="text-right text-[11px] tabular-nums text-fg/80">{cvss}</div>
                        <div className="text-right text-[11px] font-medium tabular-nums text-fg/85">
                          {it.risk_score ?? "—"}
                        </div>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          ) : (
            <div className="rounded-lg border border-dashed border-border px-3 py-8 text-center text-sm text-muted">
              Пока нет данных по приоритетам.
            </div>
          )}
        </section>

        <aside className="space-y-5">
          {/* Exploit signals */}
          <section>
            <SectionHead
              title="Радар эксплуатации"
              hint="Сигналы «в дикой природе»: VCK-only, EPSS spike, PoC."
              action={
                onOpenThreat ? (
                  <LinkChip label="Threat feed" onClick={onOpenThreat} />
                ) : exploit?.lastVckevIngestAt ? (
                  <span className="text-[10px] text-muted" title={fmtTs(exploit.lastVckevIngestAt)}>
                    sync {fmtRel(exploit.lastVckevIngestAt)}
                  </span>
                ) : null
              }
            />
            {exploitQ.isError ? (
              <p className="text-xs text-danger">Не удалось загрузить радар</p>
            ) : (
              <>
                <div className="grid grid-cols-5 gap-px overflow-hidden rounded-lg border border-border/80 bg-border/80">
                  {exploitTiles.map((t) => {
                    const meta = EXPLOIT_RADAR_FILTER_LABELS[t.filter];
                    const active = exploitFilter === t.filter;
                    return (
                      <button
                        key={t.filter}
                        type="button"
                        title={meta.hint}
                        onClick={() => onExploitFilter?.(t.filter)}
                        className={cn(
                          "bg-white px-1.5 py-2 text-center transition dark:bg-black/25",
                          "hover:bg-accent/5",
                          active && "bg-accent/10 ring-1 ring-inset ring-accent/30"
                        )}
                      >
                        <div className="text-[9px] uppercase tracking-wide text-muted">{meta.title}</div>
                        <div className="mt-0.5 text-base font-semibold tabular-nums">
                          {exploitQ.isLoading ? "…" : <LiveNumber value={t.value} />}
                        </div>
                      </button>
                    );
                  })}
                </div>
                {(exploit?.highlights?.length ?? 0) > 0 ? (
                  <ul className="mt-2 divide-y divide-border/50 rounded-lg border border-border/70">
                    {exploit!.highlights!.slice(0, 6).map((row) => (
                      <li key={row.cve_id}>
                        <button
                          type="button"
                          onClick={() => onOpenCve?.(row.cve_id)}
                          className="flex w-full items-center justify-between gap-2 px-2.5 py-1.5 text-left hover:bg-slate-50 dark:hover:bg-white/[0.03]"
                        >
                          <div className="min-w-0">
                            <div className="truncate text-[12px] font-semibold">{row.cve_id}</div>
                            <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
                              <ExploitIntelBadges item={row} compact />
                              <span className="text-[10px] tabular-nums text-muted">
                                EPSS{" "}
                                {typeof row.epss === "number" ? `${(row.epss * 100).toFixed(1)}%` : "—"}
                              </span>
                            </div>
                          </div>
                          <Radar className="h-3.5 w-3.5 shrink-0 text-muted" />
                        </button>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </>
            )}
          </section>

          {/* VOC pulse */}
          <section>
            <SectionHead
              title="VOC / Inbox"
              hint="Пульс очереди смены за 8ч и открытые элементы."
              action={<LinkChip label="Открыть VOC" onClick={onOpenVoc} />}
            />
            {vocKpiQ.isError && vocQueueQ.isError ? (
              <p className="text-xs text-muted">VOC пока недоступен</p>
            ) : (
              <div className="space-y-2">
                <div className="grid grid-cols-4 gap-2 text-center">
                  {[
                    {
                      label: "Open",
                      value: vocKpi?.triage.open ?? vocQueueQ.data?.stats?.open ?? 0,
                      cls: "text-warn"
                    },
                    {
                      label: "P1",
                      value: vocKpi?.queue.p1Open ?? 0,
                      cls: "text-danger"
                    },
                    {
                      label: "Claimed",
                      value: vocKpi?.triage.claimed ?? 0,
                      cls: "text-accent"
                    },
                    {
                      label: "Done",
                      value: vocKpi?.triage.done ?? 0,
                      cls: "text-ok"
                    }
                  ].map((c) => (
                    <div
                      key={c.label}
                      className="rounded-md border border-border/70 bg-slate-50/60 px-1.5 py-2 dark:bg-white/[0.03]"
                    >
                      <div className="text-[9px] uppercase tracking-wide text-muted">{c.label}</div>
                      <div className={cn("mt-0.5 text-sm font-semibold tabular-nums", c.cls)}>
                        {vocKpiQ.isLoading ? "…" : <LiveNumber value={c.value} />}
                      </div>
                    </div>
                  ))}
                </div>
                {(vocKpi?.cases.slaBreached ?? 0) > 0 || (vocKpi?.queue.watchlistHits ?? 0) > 0 ? (
                  <div className="flex flex-wrap gap-3 text-[11px] text-muted">
                    {(vocKpi?.cases.slaBreached ?? 0) > 0 ? (
                      <span className="inline-flex items-center gap-1 text-danger">
                        <ShieldAlert className="h-3 w-3" />
                        SLA breach {vocKpi!.cases.slaBreached}
                      </span>
                    ) : null}
                    {(vocKpi?.queue.watchlistHits ?? 0) > 0 ? (
                      <span>Watchlist hits {vocKpi!.queue.watchlistHits}</span>
                    ) : null}
                    {typeof vocKpi?.tg.total24h === "number" ? (
                      <span>TG /24ч {vocKpi.tg.total24h}</span>
                    ) : null}
                  </div>
                ) : null}
                {vocQueueQ.isLoading ? (
                  <div className="space-y-1.5">
                    {Array.from({ length: 4 }).map((_, i) => (
                      <div key={i} className="h-8 animate-pulse rounded-md bg-slate-200/50 dark:bg-white/[0.04]" />
                    ))}
                  </div>
                ) : vocItems.length ? (
                  <ul className="divide-y divide-border/50 rounded-lg border border-border/70">
                    {vocItems.slice(0, 6).map((item) => (
                      <li key={item.refKey}>
                        <button
                          type="button"
                          onClick={() => {
                            if (item.source === "cve") onOpenCve?.(item.refId);
                            else onOpenVoc?.();
                          }}
                          className="flex w-full items-start justify-between gap-2 px-2.5 py-1.5 text-left hover:bg-slate-50 dark:hover:bg-white/[0.03]"
                        >
                          <div className="min-w-0">
                            <div className="flex items-center gap-1.5">
                              <span
                                className={cn(
                                  "rounded px-1 py-0.5 text-[9px] font-medium uppercase",
                                  item.vocPriority === "p1"
                                    ? "bg-danger/15 text-danger"
                                    : item.vocPriority === "p2"
                                      ? "bg-warn/15 text-warn"
                                      : "bg-slate-200/70 text-muted dark:bg-white/10"
                                )}
                              >
                                {item.vocPriority}
                              </span>
                              <span className="truncate text-[12px] font-medium">{item.refId}</span>
                            </div>
                            <div className="mt-0.5 truncate text-[10px] text-muted">{item.title || item.subtitle}</div>
                          </div>
                          <Inbox className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted" />
                        </button>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div className="rounded-lg border border-dashed border-border px-3 py-4 text-center text-[11px] text-muted">
                    Открытых элементов в очереди нет
                  </div>
                )}
              </div>
            )}
          </section>
        </aside>
      </div>

      {/* Coverage + freshness — supporting detail */}
      <section className="rounded-lg border border-border/80 px-4 py-3.5">
        <div className="mb-3 flex flex-wrap items-end justify-between gap-2">
          <div>
            <div className="text-[13px] font-semibold tracking-tight">Покрытие интеллектом</div>
            <p className="mt-0.5 text-[11px] text-muted">
              {useHot
                ? `Risk / CVSS / ИИ — среди CVE за 24ч (знаменатель ${hotTotal.toLocaleString()}). EPSS — по всей базе: дневной feed отстаёт от свежих публикаций.`
                : "Доля CVE с risk score / EPSS / CVSS / ИИ относительно всей базы."}
            </p>
          </div>
          <div className={cn("text-[12px] font-medium tabular-nums", hl.cls)}>
            индекс <LiveNumber value={health} /> / 100 · {hl.label}
          </div>
        </div>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <CoverageTrack
            label={useHot ? "Risk score · 24ч" : "Risk score"}
            value={useHot ? hotScored : data.scoredCount}
            total={useHot ? hotTotal : total}
            tone="bg-accent"
            hint="CVE с risk_score / знаменатель окна"
          />
          <CoverageTrack
            label="EPSS · база"
            value={data.epssCount}
            total={total}
            tone="bg-warn"
            hint={
              useHot
                ? `Полный корпус EPSS. За 24ч с EPSS: ${hotEpss.toLocaleString()} / ${hotTotal.toLocaleString()} (часто ≈0 — feed лагает ~сутки, это норма).`
                : "CVE с EPSS / вся база"
            }
          />
          <CoverageTrack
            label={useHot ? "CVSS · 24ч" : "CVSS"}
            value={useHot ? hotCvss : data.cvssCount}
            total={useHot ? hotTotal : total}
            tone="bg-ok"
            hint="CVE с CVSS / знаменатель окна"
          />
          <CoverageTrack
            label={useHot ? "ИИ‑зрелость · 24ч" : "ИИ‑обогащение"}
            value={useHot ? hotAi : ai}
            total={useHot ? hotTotal : total}
            tone="bg-fg/40"
            hint="CVE с зрелым enrichment_ai / знаменатель окна"
          />
        </div>
        {useHot && total > 0 ? (
          <p className="mt-2 text-[10px] text-muted">
            Вся база (вторично): ИИ{" "}
            <span className="tabular-nums text-fg/75">
              {corpusAiPct}% · {ai.toLocaleString()} / {total.toLocaleString()}
            </span>
            {" · "}
            EPSS за 24ч{" "}
            <span className="tabular-nums text-fg/75">
              {metrics.pEpssHot}% · {hotEpss.toLocaleString()} / {hotTotal.toLocaleString()}
            </span>{" "}
            — низкое значение у свежих CVE ожидаемо, пока FIRST/EPSS не догонит scoreDate.
          </p>
        ) : null}

        <div className="mt-4 flex flex-wrap items-center gap-x-1 gap-y-2 border-t border-border/60 pt-3 text-[11px]">
          <span className="mr-2 inline-flex items-center gap-1 text-muted">
            <Clock className="h-3.5 w-3.5" />
            Актуальность
          </span>
          {(
            [
              ["NVD", data.freshness?.nvdWatermarkTs],
              ["БДУ", data.freshness?.bduIngestTs],
              ["EPSS", data.freshness?.epssIngestTs],
              ["KEV", data.freshness?.kevIngestTs],
              ["Risk", data.freshness?.riskScoreComputedAt]
            ] as const
          ).map(([k, v], i) => (
            <span key={k} className="inline-flex items-center gap-1">
              {i > 0 ? <span className="mx-1.5 text-border">·</span> : null}
              <span className="text-muted">{k}</span>
              <span className={cn("font-medium tabular-nums", freshnessTone(v))} title={fmtTs(v)}>
                {fmtRel(v)}
              </span>
            </span>
          ))}
          {onOpenSystemHealth ? (
            <button
              type="button"
              onClick={onOpenSystemHealth}
              className="ml-auto inline-flex items-center gap-1 text-accent hover:underline"
            >
              <Activity className="h-3.5 w-3.5" />
              Здоровье системы
              <ArrowRight className="h-3 w-3" />
            </button>
          ) : null}
        </div>
      </section>

      {vendorsLoading ? (
        <div className="space-y-3">
          <div className="h-5 w-48 animate-pulse rounded bg-slate-200/80 dark:bg-white/10" />
          <div className="h-56 animate-pulse rounded-xl bg-slate-200/50 dark:bg-white/[0.05]" />
        </div>
      ) : (
        <VendorLandscape
          windowHours={vendors?.windowHours ?? 24}
          sampledCves={vendors?.sampledCves ?? 0}
          sampledBdu={vendors?.sampledBdu}
          sampledTotal={vendors?.sampledTotal}
          method={vendors?.method}
          usedCpe={vendors?.usedCpe}
          usedFallback={vendors?.usedFallback}
          usedBdu={vendors?.usedBdu}
          vendors={vendors?.vendors ?? []}
          products={vendors?.products ?? []}
          onVendorSelect={onVendorSelect}
          onProductSelect={onProductSelect}
        />
      )}
    </div>
  );
}

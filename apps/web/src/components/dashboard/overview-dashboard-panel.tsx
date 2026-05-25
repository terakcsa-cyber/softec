"use client";

import { useId, useMemo } from "react";
import { motion } from "framer-motion";
import { Activity, Clock, Database, Landmark, Loader2, RefreshCw, Shield, Sparkles, TrendingUp } from "lucide-react";
import { cn } from "../ui/cn";
import { Bdu24hBoard, type HotBduRow } from "./bdu-24h-board";
import { Critical24hBoard, type HotCveRow } from "./critical-24h-board";
import { VendorLandscape } from "./vendor-landscape";
import { computeCvePriority } from "@/lib/cve-priority";

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

function healthLabel(score: number): { label: string; cls: string } {
  if (score >= 85) return { label: "Отлично", cls: "text-ok" };
  if (score >= 65) return { label: "Хорошо", cls: "text-accent" };
  if (score >= 40) return { label: "Средне", cls: "text-warn" };
  return { label: "Слабо", cls: "text-danger" };
}

/** Weighted blend: risk & intel coverage matter most for this product. */
function intelHealthScore(p: {
  risk: number;
  epss: number;
  cvss: number;
  ai: number;
}): number {
  const w = { risk: 0.32, epss: 0.26, cvss: 0.22, ai: 0.2 };
  const raw =
    p.risk * w.risk + p.epss * w.epss + p.cvss * w.cvss + p.ai * w.ai;
  return Math.round(raw * 10) / 10;
}

function AnimatedMetricBar({
  label,
  value,
  total,
  gradientClass,
  delay = 0
}: {
  label: string;
  value: number;
  total: number;
  gradientClass: string;
  delay?: number;
}) {
  const p = pct(value, total);
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2 text-[11px]">
        <span className="text-muted">{label}</span>
        <span className="tabular-nums text-fg/85">
          {value.toLocaleString()}
          <span className="text-muted"> / {total.toLocaleString()}</span>
          <span className="ml-1.5 font-medium text-fg/95">{p}%</span>
        </span>
      </div>
      <div className="relative h-2.5 overflow-hidden rounded-full bg-white/[0.06] ring-1 ring-white/[0.06]">
        <motion.div
          className={cn("h-full rounded-full bg-gradient-to-r shadow-[0_0_12px_rgba(99,102,241,0.25)]", gradientClass)}
          initial={{ width: "0%" }}
          animate={{ width: `${p}%` }}
          transition={{ type: "spring", stiffness: 70, damping: 22, delay }}
        />
      </div>
    </div>
  );
}

function HealthRing({ score }: { score: number }) {
  const uid = useId();
  const gradId = `health-grad-${uid}`;
  const glowId = `health-glow-${uid}`;
  const r = 54;
  const stroke = 9;
  const c = 2 * Math.PI * r;
  const clamped = Math.min(100, Math.max(0, score));
  const offset = c * (1 - clamped / 100);

  const hl = healthLabel(clamped);

  return (
    <div className="relative flex flex-col items-center justify-center">
      <svg width="140" height="140" viewBox="0 0 140 140" className="drop-shadow-[0_0_20px_rgba(99,102,241,0.15)]">
        <defs>
          <linearGradient id={gradId} x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="rgb(34, 197, 94)" stopOpacity="0.95" />
            <stop offset="45%" stopColor="rgb(99, 102, 241)" stopOpacity="0.95" />
            <stop offset="100%" stopColor="rgb(236, 72, 153)" stopOpacity="0.85" />
          </linearGradient>
          <filter id={glowId} x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="3" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <circle
          cx="70"
          cy="70"
          r={r}
          fill="none"
          stroke="rgba(255,255,255,0.08)"
          strokeWidth={stroke}
        />
        <motion.circle
          cx="70"
          cy="70"
          r={r}
          fill="none"
          stroke={`url(#${gradId})`}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          filter={`url(#${glowId})`}
          transform="rotate(-90 70 70)"
          initial={{ strokeDashoffset: c }}
          animate={{ strokeDashoffset: offset }}
          transition={{ type: "spring", stiffness: 60, damping: 18, mass: 0.8 }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center pt-1">
        <motion.div
          className="text-3xl font-semibold tabular-nums tracking-tight text-fg/95"
          initial={{ opacity: 0, scale: 0.92 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.15 }}
        >
          {clamped}
        </motion.div>
        <div className={cn("text-[10px] font-medium uppercase tracking-wider", hl.cls)}>{hl.label}</div>
      </div>
    </div>
  );
}

type BarDatum = { key: string; pct: number; color: string };

function CoverageBarsChart({ data }: { data: BarDatum[] }) {
  const w = 320;
  const h = 120;
  const pad = 14;
  const slot = (w - pad * 2) / data.length;
  const barW = Math.max(18, slot - 10);
  const baseY = h - 26;
  const maxBarH = h - 50;

  return (
    <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} className="overflow-visible" preserveAspectRatio="xMidYMid meet">
      {data.map((d, i) => {
        const x = pad + i * slot + (slot - barW) / 2;
        const barH = (maxBarH * d.pct) / 100;
        const y = baseY - barH;
        const hFill = Math.max(barH, 3);
        return (
          <g key={d.key}>
            <rect
              x={x}
              y={baseY - maxBarH}
              width={barW}
              height={maxBarH}
              rx={6}
              fill="rgba(255,255,255,0.05)"
              stroke="rgba(255,255,255,0.06)"
              strokeWidth={1}
            />
            <motion.rect
              x={x}
              width={barW}
              rx={6}
              fill={d.color}
              initial={{ y: baseY - 3, height: 3 }}
              animate={{ y: baseY - hFill, height: hFill }}
              transition={{ type: "spring", stiffness: 85, damping: 18, delay: 0.06 * i }}
            />
            <text
              x={x + barW / 2}
              y={h - 8}
              textAnchor="middle"
              fill="rgba(255,255,255,0.5)"
              style={{ fontSize: 10 }}
            >
              {d.key}
            </text>
            <text
              x={x + barW / 2}
              y={y - 4}
              textAnchor="middle"
              fill="rgba(255,255,255,0.65)"
              style={{ fontSize: 9 }}
              className="tabular-nums"
            >
              {d.pct.toFixed(1)}%
            </text>
          </g>
        );
      })}
    </svg>
  );
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

  // Clamp to [0..100]
  const score = Math.max(0, Math.min(100, Math.round(s)));
  return { score, reasons };
}

export function OverviewDashboardPanel({
  data,
  loading,
  error,
  vendors,
  onVendorSelect,
  onProductSelect,
  queueHealth,
  onOpenDlq,
  hotCves,
  hotLoading,
  onHotCveClick,
  hotBdu,
  hotBduLoading,
  onHotBduClick,
  dashboardHighlightBduIds,
  topPriorityCves,
  topPriorityLoading,
  onTopPriorityCveClick,
  vendorsLoading,
  dashboardHighlightCveIds,
  onRefresh,
  refreshing
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
  queueHealth?: unknown;
  onOpenDlq?: () => void;
  hotCves?: HotCveRow[];
  hotLoading?: boolean;
  onHotCveClick?: (cveId: string) => void;
  hotBdu?: HotBduRow[];
  hotBduLoading?: boolean;
  onHotBduClick?: (bduId: string) => void;
  dashboardHighlightBduIds?: ReadonlySet<string> | null;
  topPriorityCves?: HotCveRow[];
  topPriorityLoading?: boolean;
  onTopPriorityCveClick?: (cveId: string) => void;
  vendorsLoading?: boolean;
  /** Подсветка карточек, для которых открыто модальное окно. */
  dashboardHighlightCveIds?: ReadonlySet<string> | null;
  onRefresh?: () => void;
  refreshing?: boolean;
}) {
  const qh = (queueHealth ?? null) as null | {
    ok?: boolean;
    error?: unknown;
    queues?: Record<string, { messages?: number; consumers?: number }>;
    llm?: {
      configured?: boolean;
      ok?: boolean;
      endpoint?: string | null;
      model?: string | null;
      ms?: number;
      status?: number;
      error?: string;
      requiresApiKey?: boolean;
      hasApiKey?: boolean;
      authReady?: boolean;
      authHint?: string | null;
    };
    nvd?: {
      configured?: boolean;
      ok?: boolean;
      apiProbeOk?: boolean;
      endpoint?: string | null;
      ms?: number;
      status?: number;
      error?: string | null;
      hasApiKey?: boolean;
      watermarkTs?: string | null;
      watermarkEnd?: string | null;
      lastProcessed?: number | null;
      lastAttemptProcessed?: number | null;
      watermarkPartial?: boolean;
      ingestStale?: boolean;
      ingestStaleHint?: string | null;
    };
    bdu?: {
      configured?: boolean;
      ok?: boolean;
      sourceProbeOk?: boolean;
      endpoint?: string | null;
      ms?: number;
      status?: number;
      error?: string | null;
      tlsInsecure?: boolean;
      recordCount?: number;
      cveLinkCount?: number;
      maxBduId?: string | null;
      maxPublicationAt?: string | null;
      lastIngestAt?: string | null;
      lastIngestRecords?: number | null;
      lastIngestMaxBduId?: string | null;
      lastIngestUsedFallback?: boolean | null;
      ingestStale?: boolean;
      ingestStaleHint?: string | null;
    };
  };
  const metrics = useMemo(() => {
    if (!data) return null;
    const total = data.totalCves;
    const ai = data.aiEnrichedCount ?? 0;
    const pRisk = pct(data.scoredCount, total);
    const pEpss = pct(data.epssCount, total);
    const pCvss = pct(data.cvssCount, total);
    const pAi = pct(ai, total);
    const health = intelHealthScore({
      risk: pRisk,
      epss: pEpss,
      cvss: pCvss,
      ai: pAi
    });
    const bars: BarDatum[] = [
      { key: "Риск", pct: pRisk, color: "rgba(99, 102, 241, 0.85)" },
      { key: "EPSS", pct: pEpss, color: "rgba(245, 158, 11, 0.9)" },
      { key: "CVSS", pct: pCvss, color: "rgba(34, 197, 94, 0.85)" },
      { key: "ИИ", pct: pAi, color: "rgba(236, 72, 153, 0.75)" }
    ];
    return { total, ai, pRisk, pEpss, pCvss, pAi, health, bars };
  }, [data]);

  if (error) {
    return (
      <div className="glass rounded-2xl border border-danger/30 bg-danger/10 p-6 text-sm text-danger">
        <div className="font-medium">Дашборд недоступен</div>
        <div className="mt-1 opacity-90">{error.message}</div>
      </div>
    );
  }

  if (loading || !data || !metrics) {
    return (
      <div className="glass rounded-2xl p-4">
        <div className="space-y-3">
          <div className="h-4 w-40 animate-pulse rounded bg-white/10" />
          <div className="h-36 animate-pulse rounded-xl bg-white/5" />
          <div className="h-32 animate-pulse rounded-xl bg-white/5" />
        </div>
      </div>
    );
  }

  const { total, ai, health, bars } = metrics;

  return (
    <div className="space-y-8">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-sm font-semibold tracking-tight">Обзор платформы</div>
          <div className="mt-1 text-xs text-muted">
            Заполнение scoring, EPSS, CVSS и ИИ по корпусу CVE, реестр БДУ ФСТЭК и актуальность источников.
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {onRefresh ? (
            <button
              type="button"
              title="Обновить сводку и горячие CVE"
              onClick={() => onRefresh()}
              disabled={refreshing}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-xl border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-[11px] text-fg/90",
                "hover:bg-slate-100 dark:border-border dark:bg-black/20 dark:hover:bg-black/35",
                refreshing && "cursor-wait opacity-80"
              )}
            >
              {refreshing ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <RefreshCw className="h-3.5 w-3.5" />
              )}
              Обновить
            </button>
          ) : null}
          <div className="flex items-center gap-1.5 rounded-full border border-slate-200 bg-white px-2.5 py-1 text-[11px] text-muted shadow-inner dark:border-border dark:bg-black/35">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-ok/70 opacity-60" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-ok" />
            </span>
            Онлайн
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        {[
          { icon: Database, label: "CVE", value: total, sub: "в базе" },
          {
            icon: Landmark,
            label: "БДУ",
            value: data.totalBduCount ?? 0,
            sub:
              typeof data.bduPublishedLast24hCount === "number"
                ? `${data.bduPublishedLast24hCount.toLocaleString()} за 24ч`
                : "ФСТЭК"
          },
          { icon: Shield, label: "KEV", value: data.kevCount, sub: "строк каталога" },
          { icon: Sparkles, label: "ИИ", value: ai, sub: "обогащено" },
          { icon: Activity, label: "Scoring", value: data.scoredCount, sub: "модель риска" }
        ].map((c, i) => (
          <motion.div
            key={c.label}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.04 * i }}
            className="rounded-xl border border-slate-200/90 bg-gradient-to-br from-white to-slate-50 p-3 ring-1 ring-slate-200/60 dark:border-border dark:from-white/[0.07] dark:to-white/[0.02] dark:ring-white/[0.05]"
          >
            <div className="flex items-center gap-2 text-[11px] text-muted">
              <c.icon className="h-3.5 w-3.5 opacity-90" />
              {c.label}
            </div>
            <div className="mt-1.5 text-xl font-semibold tabular-nums tracking-tight text-fg/95">
              {c.value.toLocaleString()}
            </div>
            <div className="mt-0.5 text-[10px] text-muted/90">{c.sub}</div>
          </motion.div>
        ))}
      </div>

      <section className="rounded-2xl border border-slate-200/90 bg-slate-50/80 p-5 ring-1 ring-slate-200/60 dark:border-border dark:bg-black/20 dark:ring-white/[0.05]">
        <Critical24hBoard
          items={hotCves}
          loading={Boolean(hotLoading)}
          highlightedCveIds={dashboardHighlightCveIds}
          maxPublishedAt={data?.maxPublishedAt}
          onCveClick={onHotCveClick ?? (() => undefined)}
        />
      </section>

      <section className="rounded-2xl border border-teal-200/80 bg-teal-50/50 p-5 ring-1 ring-teal-200/50 dark:border-teal-900/40 dark:bg-teal-950/20 dark:ring-teal-800/30">
        <Bdu24hBoard
          items={hotBdu}
          loading={Boolean(hotBduLoading)}
          highlightedBduIds={dashboardHighlightBduIds}
          maxPublicationAt={data?.maxBduPublicationAt}
          publishedLast24hCount={data?.bduPublishedLast24hCount}
          onBduClick={onHotBduClick ?? (() => undefined)}
        />
        {typeof data.cveBduLinkCount === "number" ? (
          <p className="mt-4 text-[11px] text-muted">
            Связей CVE↔БДУ в базе:{" "}
            <span className="font-medium tabular-nums text-fg/85">{data.cveBduLinkCount.toLocaleString()}</span>
          </p>
        ) : null}
      </section>

      <section className="rounded-2xl border border-slate-200/90 bg-white p-5 ring-1 ring-slate-200/60 dark:border-border dark:bg-black/15 dark:ring-white/[0.05]">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="text-sm font-medium">ТОП‑20 по приоритету (банк / наружу / 443‑класс)</div>
            <div className="mt-1 text-[11px] leading-relaxed text-muted">
              Подборка для triage: bank‑priority + небольшой буст за периметр‑сигналы (KEV/EPSS/CVSS). В первую очередь —
              уязвимости, которые чаще всего реально эксплуатируются “снаружи”.
            </div>
          </div>
          <div className="shrink-0 text-[11px] text-muted">
            {topPriorityLoading ? "Загрузка…" : topPriorityCves?.length ? `${topPriorityCves.length}` : "—"}
          </div>
        </div>

        {topPriorityLoading ? (
          <div className="mt-4 grid grid-cols-1 gap-2 md:grid-cols-2">
            {Array.from({ length: 6 }).map((_, i) => (
              <div
                key={i}
                className="h-16 animate-pulse rounded-xl border border-slate-200/80 bg-slate-50 dark:border-white/[0.06] dark:bg-white/[0.03]"
              />
            ))}
          </div>
        ) : topPriorityCves?.length ? (
          <div className="mt-4 grid grid-cols-1 gap-2 md:grid-cols-2">
            {topPriorityCves.slice(0, 20).map((it) => {
              const p = computeCvePriority(it as any);
              const per = computePerimeterScore(it);
              const pillCls =
                p.level === "critical"
                  ? "border-danger/30 bg-danger/15 text-danger"
                  : p.level === "high"
                    ? "border-warn/30 bg-warn/15 text-warn"
                    : p.level === "medium"
                      ? "border-accent/30 bg-accent/10 text-fg/80"
                      : "border-ok/30 bg-ok/10 text-ok";
              const perCls =
                per.score >= 80
                  ? "border-danger/30 bg-danger/10 text-danger"
                  : per.score >= 55
                    ? "border-warn/30 bg-warn/10 text-warn"
                    : per.score >= 30
                      ? "border-accent/30 bg-accent/10 text-fg/80"
                      : "border-slate-200 bg-slate-50 text-fg/75 dark:border-white/10 dark:bg-white/5";
              const epss =
                typeof (it as any).epss === "number" && Number.isFinite((it as any).epss)
                  ? `${(((it as any).epss as number) * 100).toFixed(2)}%`
                  : "—";
              const cvss =
                typeof (it as any).cvss_base === "number" && Number.isFinite((it as any).cvss_base)
                  ? ((it as any).cvss_base as number).toFixed(1)
                  : "—";
              return (
                <button
                  key={(it as any).cve_id}
                  onClick={() => onTopPriorityCveClick?.(String((it as any).cve_id))}
                  className={cn(
                    "w-full rounded-xl border border-slate-200 bg-gradient-to-br from-white to-slate-50 p-3 text-left shadow-sm transition hover:from-slate-50 hover:to-slate-100/60",
                    "dark:border-white/[0.06] dark:from-white/[0.04] dark:to-white/[0.01] dark:shadow-none dark:hover:from-white/[0.06] dark:hover:to-white/[0.02]"
                  )}
                  title={p.reasons.join(" • ")}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate text-sm font-semibold tracking-tight">{String((it as any).cve_id)}</div>
                      <div className="mt-1 line-clamp-2 text-[11px] leading-snug text-fg/80">
                        {[
                          (it as any).vp_vendor ?? null,
                          (it as any).vp_product ?? null
                        ].filter(Boolean).join(" / ") || "—"}{" "}
                        {(it as any).short_ru
                          ? `— ${String((it as any).short_ru)}`
                          : (it as any).short_description
                            ? `— ${String((it as any).short_description)}`
                            : ""}
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-muted">
                        <span className={cn("rounded-full border px-2 py-0.5 tabular-nums", pillCls)}>
                          Приоритет {p.score}
                        </span>
                        <span
                          className={cn("rounded-full border px-2 py-0.5 tabular-nums", perCls)}
                          title={per.reasons.join(" • ")}
                        >
                          Периметр {per.score}
                        </span>
                        <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 tabular-nums dark:border-white/10 dark:bg-white/5">
                          EPSS <span className="text-fg/80">{epss}</span>
                        </span>
                        <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 tabular-nums dark:border-white/10 dark:bg-white/5">
                          CVSS <span className="text-fg/80">{cvss}</span>
                        </span>
                        {(it as any).exploit_known ? (
                          <span className="rounded-full border border-danger/30 bg-danger/15 px-2 py-0.5 text-danger">
                            KEV
                          </span>
                        ) : null}
                      </div>
                    </div>
                    <div className="shrink-0 rounded-full border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] font-medium tabular-nums text-fg/80 dark:border-white/10 dark:bg-white/5">
                      {(it as any).risk_score ?? "—"}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        ) : (
          <div className="mt-4 text-sm text-muted">Пока нет данных.</div>
        )}
      </section>

      <div className="relative overflow-hidden rounded-2xl border border-slate-200/90 bg-gradient-to-br from-white via-slate-50 to-indigo-100/40 p-4 ring-1 ring-slate-200/70 dark:border-border dark:from-black/40 dark:via-black/25 dark:to-indigo-950/20 dark:ring-white/[0.06]">
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.35] dark:hidden"
          style={{
            backgroundImage: `radial-gradient(circle at 1px 1px, rgba(15,23,42,0.06) 1px, transparent 0)`,
            backgroundSize: "18px 18px"
          }}
        />
        <div
          className="pointer-events-none absolute inset-0 hidden opacity-[0.35] dark:block"
          style={{
            backgroundImage: `radial-gradient(circle at 1px 1px, rgba(255,255,255,0.07) 1px, transparent 0)`,
            backgroundSize: "18px 18px"
          }}
        />
        <div className="relative grid gap-4 lg:grid-cols-[minmax(0,1fr)_200px] lg:items-center">
          <div>
            <div className="mb-1 flex items-center gap-2 text-xs font-medium text-fg/90">
              <TrendingUp className="h-3.5 w-3.5 text-accent" />
              Покрытие интеллектом
            </div>
            <p className="mb-4 text-[11px] leading-relaxed text-muted">
              Сводный индекс по заполнению risk score, EPSS, CVSS и ИИ. Столбцы — доля CVE, где поле есть, относительно
              всей базы.
            </p>
            <div className="rounded-xl border border-slate-200 bg-white p-3 shadow-sm backdrop-blur-sm dark:border-white/[0.06] dark:bg-black/25 dark:shadow-none">
              <CoverageBarsChart data={bars} />
            </div>
          </div>
          <div className="flex flex-col items-center justify-center border-t border-slate-200/90 pt-4 lg:border-l lg:border-t-0 lg:pt-0 lg:pl-4 dark:border-white/[0.06]">
            <div className="text-[10px] font-medium uppercase tracking-wider text-muted">Индекс покрытия</div>
            <HealthRing score={health} />
            <div className="mt-1 text-center text-[10px] text-muted">
              Взвешенный балл <span className="font-mono text-fg/80">{health}</span> / 100
            </div>
          </div>
        </div>

        <div className="relative mt-4 space-y-3.5 border-t border-slate-200/90 pt-4 dark:border-white/[0.06]">
          <AnimatedMetricBar
            label="Risk score посчитан"
            value={data.scoredCount}
            total={total}
            gradientClass="from-indigo-500/90 via-indigo-400/70 to-violet-400/50"
            delay={0}
          />
          <AnimatedMetricBar
            label="EPSS есть"
            value={data.epssCount}
            total={total}
            gradientClass="from-amber-500/90 via-amber-400/60 to-orange-400/45"
            delay={0.06}
          />
          <AnimatedMetricBar
            label="CVSS base есть"
            value={data.cvssCount}
            total={total}
            gradientClass="from-emerald-500/85 via-emerald-400/55 to-teal-400/45"
            delay={0.12}
          />
          <AnimatedMetricBar
            label="ИИ‑обогащение"
            value={ai}
            total={total}
            gradientClass="from-fuchsia-500/75 via-pink-400/55 to-rose-400/40"
            delay={0.18}
          />
        </div>
      </div>

      <div className="rounded-2xl border border-border bg-white p-4 shadow-sm dark:bg-black/15 dark:shadow-none">
        <div className="mb-3 flex items-center gap-2 text-xs font-medium text-fg/90">
          <Clock className="h-3.5 w-3.5 text-muted" />
          Актуальность данных
        </div>
        <dl className="grid gap-2 text-[11px] sm:grid-cols-2">
          {(
            [
              ["NVD ingest", data.freshness?.nvdWatermarkTs],
              ["БДУ ФСТЭК ingest", data.freshness?.bduIngestTs],
              ["Лента EPSS", data.freshness?.epssIngestTs],
              ["Каталог KEV", data.freshness?.kevIngestTs],
              ["Последний risk score", data.freshness?.riskScoreComputedAt]
            ] as const
          ).map(([k, v]) => (
            <div
              key={k}
              className="flex justify-between gap-2 rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-2 dark:border-white/[0.04] dark:bg-black/25"
            >
              <dt className="text-muted">{k}</dt>
              <dd className="text-right font-mono text-[10px] text-fg/85">{fmtTs(v)}</dd>
            </div>
          ))}
        </dl>
      </div>

      <div className="rounded-2xl border border-border bg-white p-4 shadow-sm dark:bg-black/15 dark:shadow-none">
        <div className="mb-3 flex items-center gap-2 text-xs font-medium text-fg/90">
          <Activity className="h-3.5 w-3.5 text-muted" />
          Очереди
          {onOpenDlq ? (
            <button
              onClick={onOpenDlq}
              className="ml-auto rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-fg/85 hover:bg-slate-100 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
              title="Открыть DLQ"
            >
              DLQ
            </button>
          ) : null}
        </div>
        {qh?.ok ? (
          <div className="grid gap-2 text-[11px] sm:grid-cols-2">
            {[
              ["ai.enrich depth", qh.queues?.enrich?.messages],
              ["ai.score depth", qh.queues?.score?.messages],
              ["dlq.ai.enrich", qh.queues?.dlqEnrich?.messages],
              ["dlq.ai.score", qh.queues?.dlqScore?.messages]
            ].map(([k, v]) => (
              <div
                key={k}
                className="flex justify-between gap-2 rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-2 dark:border-white/[0.04] dark:bg-black/25"
              >
                <div className="text-muted">{k}</div>
                <div className="tabular-nums text-fg/85">{typeof v === "number" ? v.toLocaleString() : "—"}</div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-[11px] text-muted">
            {qh?.error ? `Очереди недоступны: ${String(qh.error)}` : "Загрузка…"}
          </div>
        )}

        {qh?.ok && qh?.llm ? (
          <div className="mt-3 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-[11px] dark:border-white/[0.04] dark:bg-black/25">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-muted">
                LLM{" "}
                {qh.llm.configured === false ? (
                  <span className="text-danger">не настроен</span>
                ) : qh.llm.ok ? (
                  <span className="text-ok">OK</span>
                ) : (
                  <span className="text-danger">DOWN</span>
                )}
              </div>
              <div className="font-mono tabular-nums text-fg/80">{typeof qh.llm.ms === "number" ? `${qh.llm.ms}ms` : "—"}</div>
            </div>
            {qh.llm.endpoint ? <div className="mt-1 truncate font-mono text-[10px] text-fg/80">{qh.llm.endpoint}</div> : null}
            <div className="mt-1 flex flex-wrap items-center gap-2 text-[10px] text-muted">
              {qh.llm.model ? <span>model: {qh.llm.model}</span> : null}
              {typeof qh.llm.status === "number" ? <span>status: {qh.llm.status}</span> : null}
              {qh.llm.error ? <span className="truncate text-danger">{String(qh.llm.error)}</span> : null}
            </div>
            {qh.llm.authReady === false && qh.llm.authHint ? (
              <div className="mt-2 rounded-lg border border-warn/30 bg-warn/10 px-2 py-1.5 text-[10px] text-warn">
                {qh.llm.authHint}
              </div>
            ) : null}
          </div>
        ) : null}

        {qh?.ok && qh?.nvd ? (
          <div className="mt-3 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-[11px] dark:border-white/[0.04] dark:bg-black/25">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-muted">
                NVD{" "}
                {qh.nvd.ok ? (
                  <span className="text-ok">OK</span>
                ) : (
                  <span className="text-danger">DOWN</span>
                )}
                {qh.nvd.apiProbeOk === false && qh.nvd.ok ? (
                  <span className="ml-1 text-warn">· API probe медленный</span>
                ) : null}
                {qh.nvd.ingestStale ? <span className="ml-1 text-warn">· ingest устарел</span> : null}
              </div>
              <div className="font-mono tabular-nums text-fg/80">{typeof qh.nvd.ms === "number" ? `${qh.nvd.ms}ms` : "—"}</div>
            </div>
            {qh.nvd.endpoint ? <div className="mt-1 truncate font-mono text-[10px] text-fg/80">{qh.nvd.endpoint}</div> : null}
            <div className="mt-1 flex flex-wrap items-center gap-2 text-[10px] text-muted">
              {qh.nvd.hasApiKey ? <span>API key: да</span> : <span>API key: нет (лимиты жёстче)</span>}
              {typeof qh.nvd.status === "number" ? <span>HTTP: {qh.nvd.status}</span> : null}
              {typeof qh.nvd.lastProcessed === "number" ? (
                <span>
                  посл. успешный цикл: {qh.nvd.lastProcessed.toLocaleString()} CVE
                  {qh.nvd.watermarkPartial ? " (частично)" : ""}
                </span>
              ) : typeof qh.nvd.lastAttemptProcessed === "number" ? (
                <span>посл. попытка: {qh.nvd.lastAttemptProcessed.toLocaleString()} CVE</span>
              ) : null}
              {qh.nvd.watermarkEnd ? <span>окно до: {fmtTs(qh.nvd.watermarkEnd)}</span> : null}
              {qh.nvd.watermarkTs ? <span>запись: {fmtTs(qh.nvd.watermarkTs)}</span> : null}
            </div>
            {qh.nvd.error && !qh.nvd.ok ? (
              <div className="mt-1 text-[10px] text-danger">{String(qh.nvd.error)}</div>
            ) : qh.nvd.error && qh.nvd.ok ? (
              <div className="mt-1 text-[10px] text-warn">{String(qh.nvd.error)}</div>
            ) : null}
            {qh.nvd.ingestStale && qh.nvd.ingestStaleHint ? (
              <div className="mt-2 rounded-lg border border-warn/30 bg-warn/10 px-2 py-1.5 text-[10px] text-warn">
                {qh.nvd.ingestStaleHint}
              </div>
            ) : null}
          </div>
        ) : null}

        {qh?.ok && qh?.bdu ? (
          <div className="mt-3 rounded-xl border border-teal-200/80 bg-teal-50/80 px-3 py-2 text-[11px] dark:border-teal-900/50 dark:bg-teal-950/25">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-muted">
                БДУ ФСТЭК{" "}
                {qh.bdu.ok ? (
                  <span className="text-ok">OK</span>
                ) : (
                  <span className="text-danger">DOWN</span>
                )}
                {qh.bdu.sourceProbeOk === false && qh.bdu.ok ? (
                  <span className="ml-1 text-warn">· источник медленный</span>
                ) : null}
                {qh.bdu.ingestStale ? <span className="ml-1 text-warn">· ingest устарел</span> : null}
                {qh.bdu.lastIngestUsedFallback ? (
                  <span className="ml-1 text-warn">· зеркало</span>
                ) : null}
              </div>
              <div className="font-mono tabular-nums text-fg/80">{typeof qh.bdu.ms === "number" ? `${qh.bdu.ms}ms` : "—"}</div>
            </div>
            {qh.bdu.endpoint ? <div className="mt-1 truncate font-mono text-[10px] text-fg/80">{qh.bdu.endpoint}</div> : null}
            <div className="mt-1 flex flex-wrap items-center gap-2 text-[10px] text-muted">
              {typeof qh.bdu.recordCount === "number" ? (
                <span>записей: {qh.bdu.recordCount.toLocaleString()}</span>
              ) : null}
              {typeof qh.bdu.cveLinkCount === "number" ? (
                <span>связей CVE: {qh.bdu.cveLinkCount.toLocaleString()}</span>
              ) : null}
              {typeof qh.bdu.status === "number" ? <span>HTTP: {qh.bdu.status}</span> : null}
              {qh.bdu.tlsInsecure ? <span className="text-warn">TLS insecure</span> : null}
              {qh.bdu.maxBduId ? <span>max id: {qh.bdu.maxBduId}</span> : null}
              {typeof qh.bdu.lastIngestRecords === "number" ? (
                <span>посл. цикл: {qh.bdu.lastIngestRecords.toLocaleString()} записей</span>
              ) : null}
              {qh.bdu.lastIngestAt ? <span>ingest: {fmtTs(qh.bdu.lastIngestAt)}</span> : null}
              {qh.bdu.maxPublicationAt ? <span>публ.: {fmtTs(qh.bdu.maxPublicationAt)}</span> : null}
            </div>
            {qh.bdu.error && !qh.bdu.ok ? (
              <div className="mt-1 text-[10px] text-danger">{String(qh.bdu.error)}</div>
            ) : qh.bdu.error && qh.bdu.ok ? (
              <div className="mt-1 text-[10px] text-warn">{String(qh.bdu.error)}</div>
            ) : null}
            {qh.bdu.ingestStale && qh.bdu.ingestStaleHint ? (
              <div className="mt-2 rounded-lg border border-warn/30 bg-warn/10 px-2 py-1.5 text-[10px] text-warn">
                {qh.bdu.ingestStaleHint}
              </div>
            ) : null}
          </div>
        ) : null}
      </div>

      {vendorsLoading ? (
        <div className="space-y-3">
          <div className="h-5 w-48 animate-pulse rounded bg-slate-200/80 dark:bg-white/10" />
          <div className="h-64 animate-pulse rounded-2xl bg-slate-200/50 dark:bg-white/[0.05]" />
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

      <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50/80 p-4 text-xs text-muted dark:border-white/10 dark:bg-black/10">
        <span className="font-medium text-fg/80">Подсказка:</span> клик по CVE открывает плавающее окно; клик по БДУ — модуль «Уязвимости» с карточкой
        ФСТЭК. Мониторинг БДУ — в блоке «Очереди» и в «Настройки → Интеграции».
      </div>
    </div>
  );
}

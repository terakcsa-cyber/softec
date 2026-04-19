"use client";

import { useId, useMemo } from "react";
import { motion } from "framer-motion";
import { Activity, Clock, Database, Shield, Sparkles, TrendingUp } from "lucide-react";
import { cn } from "../ui/cn";
import { Critical24hBoard, type HotCveRow } from "./critical-24h-board";
import { VendorLandscape } from "./vendor-landscape";

export type SummaryStats = {
  totalCves: number;
  cvesLastHourCount?: number;
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
  vendorsLoading,
  dashboardHighlightCveIds
}: {
  data: SummaryStats | undefined;
  loading: boolean;
  error: Error | null;
  vendors?: {
    windowHours: number;
    sampledCves: number;
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
  vendorsLoading?: boolean;
  /** Подсветка карточек, для которых открыто модальное окно. */
  dashboardHighlightCveIds?: ReadonlySet<string> | null;
}) {
  const qh = (queueHealth ?? null) as null | {
    ok?: boolean;
    error?: unknown;
    queues?: Record<string, { messages?: number; consumers?: number }>;
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
            Заполнение scoring, EPSS, CVSS и ИИ по корпусу CVE — плюс актуальность источников.
          </div>
        </div>
        <div className="flex items-center gap-1.5 rounded-full border border-border bg-black/35 px-2.5 py-1 text-[11px] text-muted shadow-inner">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-ok/70 opacity-60" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-ok" />
          </span>
          Онлайн
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[
          { icon: Database, label: "CVE", value: total, sub: "в базе" },
          { icon: Shield, label: "KEV", value: data.kevCount, sub: "строк каталога" },
          { icon: Sparkles, label: "ИИ", value: ai, sub: "обогащено" },
          { icon: Activity, label: "Scoring", value: data.scoredCount, sub: "модель риска" }
        ].map((c, i) => (
          <motion.div
            key={c.label}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.04 * i }}
            className="rounded-xl border border-border bg-gradient-to-br from-white/[0.07] to-white/[0.02] p-3 ring-1 ring-white/[0.04]"
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

      <section className="rounded-2xl border border-border bg-black/20 p-5 ring-1 ring-white/[0.05]">
        <Critical24hBoard
          items={hotCves}
          loading={Boolean(hotLoading)}
          highlightedCveIds={dashboardHighlightCveIds}
          onCveClick={onHotCveClick ?? (() => undefined)}
        />
      </section>

      <div className="relative overflow-hidden rounded-2xl border border-border bg-gradient-to-br from-black/40 via-black/25 to-indigo-950/20 p-4 ring-1 ring-white/[0.06]">
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.35]"
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
            <div className="rounded-xl border border-white/[0.06] bg-black/25 p-3 backdrop-blur-sm">
              <CoverageBarsChart data={bars} />
            </div>
          </div>
          <div className="flex flex-col items-center justify-center border-t border-white/[0.06] pt-4 lg:border-l lg:border-t-0 lg:pt-0 lg:pl-4">
            <div className="text-[10px] font-medium uppercase tracking-wider text-muted">Индекс покрытия</div>
            <HealthRing score={health} />
            <div className="mt-1 text-center text-[10px] text-muted">
              Взвешенный балл <span className="font-mono text-fg/80">{health}</span> / 100
            </div>
          </div>
        </div>

        <div className="relative mt-4 space-y-3.5 border-t border-white/[0.06] pt-4">
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

      <div className="rounded-2xl border border-border bg-black/15 p-4">
        <div className="mb-3 flex items-center gap-2 text-xs font-medium text-fg/90">
          <Clock className="h-3.5 w-3.5 text-muted" />
          Актуальность данных
        </div>
        <dl className="grid gap-2 text-[11px] sm:grid-cols-2">
          {(
            [
              ["NVD ingest", data.freshness?.nvdWatermarkTs],
              ["Лента EPSS", data.freshness?.epssIngestTs],
              ["Каталог KEV", data.freshness?.kevIngestTs],
              ["Последний risk score", data.freshness?.riskScoreComputedAt]
            ] as const
          ).map(([k, v]) => (
            <div
              key={k}
              className="flex justify-between gap-2 rounded-lg border border-white/[0.04] bg-black/25 px-2.5 py-2"
            >
              <dt className="text-muted">{k}</dt>
              <dd className="text-right font-mono text-[10px] text-fg/85">{fmtTs(v)}</dd>
            </div>
          ))}
        </dl>
      </div>

      <div className="rounded-2xl border border-border bg-black/15 p-4">
        <div className="mb-3 flex items-center gap-2 text-xs font-medium text-fg/90">
          <Activity className="h-3.5 w-3.5 text-muted" />
          Очереди
          {onOpenDlq ? (
            <button
              onClick={onOpenDlq}
              className="ml-auto rounded-lg border border-border bg-black/20 px-2 py-1 text-[11px] text-fg/85 hover:bg-black/30"
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
                className="flex justify-between gap-2 rounded-lg border border-white/[0.04] bg-black/25 px-2.5 py-2"
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
      </div>

      {vendorsLoading ? (
        <div className="space-y-3">
          <div className="h-5 w-48 animate-pulse rounded bg-white/10" />
          <div className="h-64 animate-pulse rounded-2xl bg-white/[0.05]" />
        </div>
      ) : (
        <VendorLandscape
          windowHours={vendors?.windowHours ?? 24}
          sampledCves={vendors?.sampledCves ?? 0}
          method={vendors?.method}
          usedCpe={vendors?.usedCpe}
          usedFallback={vendors?.usedFallback}
          vendors={vendors?.vendors ?? []}
          products={vendors?.products ?? []}
          onVendorSelect={onVendorSelect}
          onProductSelect={onProductSelect}
        />
      )}

      <div className="rounded-2xl border border-border border-dashed border-white/10 bg-black/10 p-4 text-xs text-muted">
        <span className="font-medium text-fg/80">Подсказка:</span>             клик по CVE в блоке за 24ч открывает плавающее окно с разбором (можно открыть несколько и двигать).
        В модуле «Уязвимости» список слева и панель справа.
      </div>
    </div>
  );
}

"use client";

import { useMemo } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, Flame, ShieldAlert, Target, Zap } from "lucide-react";
import { cn } from "../ui/cn";

export type HotCveRow = {
  cve_id: string;
  published_at: string | null;
  modified_at: string | null;
  risk_score: number | null;
  epss?: number | null;
  cvss_base?: number | null;
  exploit_known?: boolean;
  critical_reasons?: string[] | null;
  ai_ready?: boolean;
};

function riskAccent(score: number | null | undefined): { border: string; glow: string; label: string } {
  if (score == null) return { border: "border-slate-300 dark:border-white/10", glow: "", label: "нет оценки" };
  if (score >= 85) return { border: "border-danger/50", glow: "shadow-[0_0_24px_rgba(239,68,68,0.12)]", label: "критично" };
  if (score >= 70) return { border: "border-warn/45", glow: "shadow-[0_0_20px_rgba(245,158,11,0.1)]", label: "высокий" };
  if (score >= 40) return { border: "border-accent/35", glow: "", label: "средний" };
  return { border: "border-slate-300 dark:border-white/12", glow: "", label: "низкий" };
}

export function Critical24hBoard({
  items,
  loading,
  highlightedCveIds,
  onCveClick
}: {
  items: HotCveRow[] | undefined;
  loading: boolean;
  /** CVE, для которых открыто модальное окно на дашборде. */
  highlightedCveIds?: ReadonlySet<string> | null;
  onCveClick: (cveId: string) => void;
}) {
  const stats = useMemo(() => {
    const arr = items ?? [];
    const kev = arr.filter((i) => i.exploit_known).length;
    const highEpss = arr.filter((i) => typeof i.epss === "number" && i.epss >= 0.5).length;
    const criticalCvss = arr.filter((i) => typeof i.cvss_base === "number" && i.cvss_base >= 9).length;
    return { total: arr.length, kev, highEpss, criticalCvss };
  }, [items]);

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-24 animate-pulse rounded-2xl bg-slate-200/70 dark:bg-white/[0.06]" />
          ))}
        </div>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="h-36 animate-pulse rounded-2xl bg-slate-200/50 dark:bg-white/[0.05]" />
          ))}
        </div>
      </div>
    );
  }

  const list = items ?? [];

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="text-base font-semibold tracking-tight text-fg/95">Угрозы за последние 24 часа</div>
          <p className="mt-1 max-w-2xl text-[12px] leading-relaxed text-muted">
            CVE с датой публикации в окне 24ч, от новых к старым по времени публикации. Клик открывает отдельное окно поверх (несколько
            окон можно открыть и перетаскивать за заголовок).
          </p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[
          {
            icon: Target,
            label: "В окне 24ч",
            value: stats.total,
            sub: "записей в выборке",
            tone: "from-indigo-500/20 to-violet-600/10"
          },
          {
            icon: ShieldAlert,
            label: "KEV",
            value: stats.kev,
            sub: "в каталоге CISA",
            tone: "from-rose-500/20 to-red-600/10"
          },
          {
            icon: Zap,
            label: "CVSS ≥ 9",
            value: stats.criticalCvss,
            sub: "критический вектор",
            tone: "from-amber-500/15 to-orange-600/10"
          },
          {
            icon: Flame,
            label: "EPSS ≥ 0.5",
            value: stats.highEpss,
            sub: "высокая вероятность",
            tone: "from-fuchsia-500/15 to-pink-600/10"
          }
        ].map((c, i) => (
          <motion.div
            key={c.label}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.04 * i }}
            className={cn(
              "relative overflow-hidden rounded-2xl border border-slate-200/90 bg-gradient-to-br p-4 ring-1 ring-slate-200/60",
              "dark:border-white/[0.08] dark:ring-white/[0.04]",
              c.tone
            )}
          >
            <div className="flex items-center gap-2 text-[11px] font-medium text-muted">
              <c.icon className="h-3.5 w-3.5 opacity-90" />
              {c.label}
            </div>
            <div className="mt-2 text-3xl font-semibold tabular-nums tracking-tight text-fg/95">{c.value}</div>
            <div className="mt-0.5 text-[10px] text-muted/90">{c.sub}</div>
          </motion.div>
        ))}
      </div>

      {stats.total === 0 ? (
        <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 px-4 py-8 text-center text-sm text-muted dark:border-border dark:bg-black/10">
          За последние 24 часа нет опубликованных CVE в базе — проверьте ingest NVD или расширьте окно во вкладке
          «Уязвимости».
        </div>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {list.map((it, idx) => {
            const ra = riskAccent(it.risk_score);
            const epssPct =
              typeof it.epss === "number" && Number.isFinite(it.epss) ? `${(it.epss * 100).toFixed(1)}%` : "—";
            const cvss =
              typeof it.cvss_base === "number" && Number.isFinite(it.cvss_base) ? it.cvss_base.toFixed(1) : "—";
            const reasons = Array.isArray(it.critical_reasons) ? it.critical_reasons.slice(0, 3) : [];
            const isOpen = highlightedCveIds?.has(it.cve_id) ?? false;
            return (
              <motion.div
                key={it.cve_id}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.03 * Math.min(idx, 12) }}
                className="min-w-0"
              >
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onCveClick(it.cve_id);
                  }}
                  className={cn(
                    "group relative z-[1] w-full cursor-pointer rounded-2xl border bg-gradient-to-br p-4 text-left",
                    "from-slate-100 to-slate-200/70 hover:from-slate-50 hover:to-slate-100",
                    "dark:from-white/[0.07] dark:to-black/30 dark:hover:from-white/[0.09] dark:hover:to-black/25",
                    "pointer-events-auto transition hover:border-accent/35 active:scale-[0.99]",
                    isOpen && "border-accent/50 ring-2 ring-accent/25",
                    ra.border,
                    !isOpen && ra.glow
                  )}
                >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="font-mono text-sm font-semibold tracking-tight text-fg/95 group-hover:text-fg">
                      {it.cve_id}
                    </div>
                    <div className="mt-1 text-[10px] text-muted">
                      {it.published_at
                        ? new Date(it.published_at).toLocaleString()
                        : it.modified_at
                          ? `изм. ${new Date(it.modified_at).toLocaleString()}`
                          : "нет даты"}
                    </div>
                  </div>
                  <span
                    className={cn(
                      "shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-medium",
                      it.risk_score != null && it.risk_score >= 70
                        ? "border-danger/35 bg-danger/10 text-danger"
                        : "border-slate-200 bg-white text-fg/80 shadow-sm dark:border-white/10 dark:bg-white/5 dark:shadow-none"
                    )}
                  >
                    {it.risk_score != null ? `${it.risk_score}` : "—"}
                  </span>
                </div>

                <div className="mt-3 flex flex-wrap gap-1.5">
                  {it.exploit_known ? (
                    <span className="rounded-full border border-danger/35 bg-danger/10 px-2 py-0.5 text-[10px] text-danger">
                      KEV
                    </span>
                  ) : null}
                  <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[10px] tabular-nums text-fg/85 dark:border-white/10 dark:bg-black/30">
                    EPSS {epssPct}
                  </span>
                  <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[10px] tabular-nums text-fg/85 dark:border-white/10 dark:bg-black/30">
                    CVSS {cvss}
                  </span>
                  <span className="rounded-full border border-slate-200/90 px-2 py-0.5 text-[10px] text-muted dark:border-white/8">
                    {ra.label}
                  </span>
                </div>

                {reasons.length > 0 ? (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {reasons.map((r) => (
                      <span
                        key={r}
                        className="rounded-md border border-accent/25 bg-accent/10 px-1.5 py-0.5 text-[10px] text-fg/85"
                      >
                        {r}
                      </span>
                    ))}
                  </div>
                ) : null}

                {it.ai_ready ? (
                  <div className="mt-2 text-[10px] text-muted">ИИ‑сводка готова</div>
                ) : (
                  <div className="mt-2 flex items-center gap-1 text-[10px] text-muted/80">
                    <AlertTriangle className="h-3 w-3 opacity-70" />
                    ИИ в очереди или отключён
                  </div>
                )}

                <div className="pointer-events-none absolute right-3 bottom-3 text-[10px] font-medium text-accent/80 opacity-0 transition group-hover:opacity-100">
                  Открыть →
                </div>
                </button>
              </motion.div>
            );
          })}
        </div>
      )}
    </div>
  );
}

"use client";

import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, Flame, ShieldAlert, Target, Zap } from "lucide-react";
import { cn } from "../ui/cn";
import { VocTriageCheckpoint, processedCardClass } from "./voc-triage-checkpoint";
import { cveRefKey } from "@/lib/voc-ref-keys";
import { useVocTriage } from "@/lib/voc-triage-context";

export type HotCveRow = {
  cve_id: string;
  published_at: string | null;
  modified_at: string | null;
  risk_score: number | null;
  epss?: number | null;
  cvss_base?: number | null;
  vp_vendor?: string | null;
  vp_product?: string | null;
  short_description?: string | null;
  short_ru?: string | null;
  cvss_av_network?: boolean;
  cvss_pr_none?: boolean;
  cvss_ui_none?: boolean;
  cvss_ac_low?: boolean;
  perimeter_product?: boolean;
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

type HotCategory = "all24h" | "kev" | "cvss9" | "epss05";

function categoryTone(cat: HotCategory) {
  if (cat === "kev") return { grad: "from-rose-500/15 to-red-600/10", ring: "ring-danger/15", border: "border-danger/30" };
  if (cat === "cvss9") return { grad: "from-amber-500/12 to-orange-600/10", ring: "ring-warn/15", border: "border-warn/30" };
  if (cat === "epss05") return { grad: "from-fuchsia-500/12 to-pink-600/10", ring: "ring-accent/15", border: "border-accent/30" };
  return { grad: "from-indigo-500/12 to-violet-600/10", ring: "ring-accent/10", border: "border-accent/25" };
}

function cardTone(it: HotCveRow) {
  // Per-card "signal" coloring for the default 24h view.
  // Priority: KEV > CVSS>=9 > EPSS>=0.5 > default.
  const isKev = Boolean(it.exploit_known);
  const isCvss9 = typeof it.cvss_base === "number" && it.cvss_base >= 9;
  const isEpss = typeof it.epss === "number" && it.epss >= 0.5;
  if (isKev) return { ring: "ring-danger/15", border: "border-danger/30" };
  if (isCvss9) return { ring: "ring-warn/15", border: "border-warn/30" };
  if (isEpss) return { ring: "ring-accent/15", border: "border-accent/30" };
  return { ring: "ring-accent/10", border: "border-accent/25" };
}

function filterByCategory(list: HotCveRow[], cat: HotCategory): HotCveRow[] {
  if (cat === "kev") return list.filter((i) => Boolean(i.exploit_known));
  if (cat === "cvss9") return list.filter((i) => typeof i.cvss_base === "number" && i.cvss_base >= 9);
  if (cat === "epss05") return list.filter((i) => typeof i.epss === "number" && i.epss >= 0.5);
  return list;
}

function sortByCategory(list: HotCveRow[], cat: HotCategory): HotCveRow[] {
  const byPublishedDesc = (a: HotCveRow, b: HotCveRow) => {
    const ta = a.published_at ?? "";
    const tb = b.published_at ?? "";
    return tb.localeCompare(ta);
  };
  // Главная показывает не ленту, а triage-очередь: сначала максимальная вероятность эксплуатации.
  if (cat === "all24h") {
    return [...list].sort((a, b) => {
      const ea = typeof a.epss === "number" ? a.epss : -1;
      const eb = typeof b.epss === "number" ? b.epss : -1;
      if (eb !== ea) return eb - ea;
      const ra = typeof a.risk_score === "number" ? a.risk_score : -1;
      const rb = typeof b.risk_score === "number" ? b.risk_score : -1;
      if (rb !== ra) return rb - ra;
      const ca = typeof a.cvss_base === "number" ? a.cvss_base : -1;
      const cb = typeof b.cvss_base === "number" ? b.cvss_base : -1;
      if (cb !== ca) return cb - ca;
      const ta = a.published_at ?? "";
      const tb = b.published_at ?? "";
      return tb.localeCompare(ta);
    });
  }
  if (cat === "kev") {
    return [...list].sort((a, b) => {
      const ka = a.exploit_known ? 1 : 0;
      const kb = b.exploit_known ? 1 : 0;
      if (kb !== ka) return kb - ka;
      const ra = typeof a.risk_score === "number" ? a.risk_score : -1;
      const rb = typeof b.risk_score === "number" ? b.risk_score : -1;
      if (rb !== ra) return rb - ra;
      return byPublishedDesc(a, b);
    });
  }
  if (cat === "cvss9") {
    return [...list].sort((a, b) => {
      const ca = typeof a.cvss_base === "number" ? a.cvss_base : -1;
      const cb = typeof b.cvss_base === "number" ? b.cvss_base : -1;
      if (cb !== ca) return cb - ca;
      return byPublishedDesc(a, b);
    });
  }
  if (cat === "epss05") {
    return [...list].sort((a, b) => {
      const ea = typeof a.epss === "number" ? a.epss : -1;
      const eb = typeof b.epss === "number" ? b.epss : -1;
      if (eb !== ea) return eb - ea;
      return byPublishedDesc(a, b);
    });
  }
  return [...list].sort(byPublishedDesc);
}

export function Critical24hBoard({
  items,
  loading,
  highlightedCveIds,
  maxPublishedAt,
  onCveClick
}: {
  items: HotCveRow[] | undefined;
  loading: boolean;
  /** CVE, для которых открыто модальное окно на дашборде. */
  highlightedCveIds?: ReadonlySet<string> | null;
  /** Последняя дата публикации в NVD в базе (для пустого блока). */
  maxPublishedAt?: string | null;
  onCveClick: (cveId: string) => void;
}) {
  const [cat, setCat] = useState<HotCategory>("all24h");
  const { isDone } = useVocTriage();
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
  const filtered = useMemo(() => {
    const base = filterByCategory(list, cat);
    return sortByCategory(base, cat);
  }, [list, cat]);
  const tone = categoryTone(cat);

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="text-base font-semibold tracking-tight text-fg/95">Срочные CVE за последние 24 часа</div>
          <p className="mt-1 max-w-2xl text-[12px] leading-relaxed text-muted">
            Только новые CVE с сильным сигналом: KEV, EPSS ≥ 50% или CVSS ≥ 9. Это короткий список для немедленного
            внимания, без общей шумной ленты.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {(
          [
          {
            key: "all24h",
            icon: Target,
            label: "Срочные",
            value: stats.total,
            sub: "KEV / EPSS / CVSS",
            tone: "from-indigo-500/20 to-violet-600/10"
          },
          {
            key: "kev",
            icon: ShieldAlert,
            label: "KEV",
            value: stats.kev,
            sub: "в каталоге CISA",
            tone: "from-rose-500/20 to-red-600/10"
          },
          {
            key: "cvss9",
            icon: Zap,
            label: "CVSS ≥ 9",
            value: stats.criticalCvss,
            sub: "критический вектор",
            tone: "from-amber-500/15 to-orange-600/10"
          },
          {
            key: "epss05",
            icon: Flame,
            label: "EPSS ≥ 0.5",
            value: stats.highEpss,
            sub: "эксплуатации",
            tone: "from-fuchsia-500/15 to-pink-600/10"
          }
        ] as const
        ).map((c, i) => {
          const active = cat === (c.key as HotCategory);
          return (
          <motion.button
            type="button"
            onClick={() => setCat(c.key as HotCategory)}
            key={c.label}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.04 * i }}
            className={cn(
              "relative overflow-hidden rounded-2xl border border-slate-200/90 bg-gradient-to-br p-4 ring-1 ring-slate-200/60 text-left",
              "dark:border-white/[0.08] dark:ring-white/[0.04]",
              c.tone,
              active && "ring-2 ring-accent/25 border-accent/30"
            )}
          >
            <div className="flex items-center gap-2 text-[11px] font-medium text-muted">
              <c.icon className="h-3.5 w-3.5 opacity-90" />
              {c.label}
            </div>
            <div className="mt-2 text-3xl font-semibold tabular-nums tracking-tight text-fg/95">{c.value}</div>
            <div className="mt-0.5 text-[10px] text-muted/90">{c.sub}</div>
          </motion.button>
        );
        })}
      </div>

      {stats.total === 0 ? (
        <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 px-4 py-8 text-center text-sm text-muted dark:border-border dark:bg-black/10">
          <p>
            За последние 24 часа нет CVE с сильным сигналом:{" "}
            <span className="font-medium text-fg/85">KEV</span>,{" "}
            <span className="font-medium text-fg/85">EPSS ≥ 50%</span> или{" "}
            <span className="font-medium text-fg/85">CVSS ≥ 9</span>.
          </p>
          {maxPublishedAt ? (
            <p className="mt-2 text-[12px]">
              Последняя публикация в базе:{" "}
              <span className="font-medium text-fg/80">{new Date(maxPublishedAt).toLocaleString()}</span>
            </p>
          ) : null}
          <p className="mt-2 text-[11px] leading-relaxed">
            Это нормально: на главной теперь показываем только действительно срочные события, а не всю NVD-ленту.
          </p>
        </div>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {filtered.map((it, idx) => {
            const ra = riskAccent(it.risk_score);
            const epssPct =
              typeof it.epss === "number" && Number.isFinite(it.epss) ? `${(it.epss * 100).toFixed(1)}%` : "—";
            const cvss =
              typeof it.cvss_base === "number" && Number.isFinite(it.cvss_base) ? it.cvss_base.toFixed(1) : "—";
            const reasons = Array.isArray(it.critical_reasons) ? it.critical_reasons.slice(0, 3) : [];
            const isOpen = highlightedCveIds?.has(it.cve_id) ?? false;
            const per = cat === "all24h" ? cardTone(it) : tone;
            const processedKey = cveRefKey(it.cve_id);
            const done = isDone(processedKey);
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
                    done && "border-ok/25",
                    processedCardClass(done),
                    ra.border,
                    !isOpen && ra.glow,
                    // Color cards: default view uses per-card signal tones; category views use category tone.
                    cn("ring-1", per.ring, per.border)
                  )}
                >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <VocTriageCheckpoint refKey={processedKey} title={it.cve_id} compact />
                      <div className="font-mono text-sm font-semibold tracking-tight text-fg/95 group-hover:text-fg">
                        {it.cve_id}
                      </div>
                    </div>
                    <div className="mt-1 line-clamp-2 text-[11px] leading-snug text-fg/80">
                      {[it.vp_vendor, it.vp_product].filter(Boolean).join(" / ") || "—"}{" "}
                      {it.short_ru ? `— ${it.short_ru}` : it.short_description ? `— ${it.short_description}` : ""}
                    </div>
                    <div className="mt-1 text-[10px] text-muted">
                      {it.published_at
                        ? `опубл. ${new Date(it.published_at).toLocaleString()}`
                        : "нет даты публикации"}
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

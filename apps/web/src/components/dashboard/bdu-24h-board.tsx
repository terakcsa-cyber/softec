"use client";

import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Flame, Link2, ShieldAlert, Target, Zap } from "lucide-react";
import { cn } from "../ui/cn";
import type { BduListItem } from "./bdu-card";
import { bduRiskScore } from "@/lib/bdu-priority";
import { ScrollableBoardGrid } from "./scrollable-board-grid";
import { VocTriageCheckpoint, processedCardClass } from "./voc-triage-checkpoint";
import { bduRefKey } from "@/lib/voc-ref-keys";
import { useVocTriage } from "@/lib/voc-triage-context";

export type HotBduRow = BduListItem;

type HotCategory = "all24h" | "exploit" | "cvss9" | "linked";

function parsePubMs(d: string | null | undefined): number {
  if (!d) return 0;
  const m = /^(\d{2})\.(\d{2})\.(\d{4})$/.exec(d.trim());
  if (!m) return 0;
  const t = Date.UTC(Number(m[3]), Number(m[2]) - 1, Number(m[1]));
  return Number.isFinite(t) ? t : 0;
}

function byPublishedDesc(a: HotBduRow, b: HotBduRow) {
  return parsePubMs(b.publicationDate) - parsePubMs(a.publicationDate);
}

function byUrgencyDesc(a: HotBduRow, b: HotBduRow) {
  const ra = bduRiskScore(a) ?? -1;
  const rb = bduRiskScore(b) ?? -1;
  if (rb !== ra) return rb - ra;
  const ca = typeof a.cvssScore === "number" ? a.cvssScore : -1;
  const cb = typeof b.cvssScore === "number" ? b.cvssScore : -1;
  if (cb !== ca) return cb - ca;
  return byPublishedDesc(a, b);
}

function filterByCategory(list: HotBduRow[], cat: HotCategory): HotBduRow[] {
  if (cat === "all24h") return list;
  if (cat === "exploit") return list.filter((i) => i.hasExploit);
  if (cat === "cvss9") return list.filter((i) => typeof i.cvssScore === "number" && i.cvssScore >= 9);
  return list.filter((i) => (i.linkedCveIds?.length ?? 0) > 0 || (i.cveIds?.length ?? 0) > 0);
}

function categoryTone(cat: HotCategory) {
  if (cat === "exploit") return { ring: "ring-danger/20", border: "border-danger/25" };
  if (cat === "cvss9") return { ring: "ring-amber-500/20", border: "border-amber-500/25" };
  if (cat === "linked") return { ring: "ring-indigo-500/20", border: "border-indigo-500/25" };
  return { ring: "ring-accent/15", border: "border-accent/20" };
}

export function Bdu24hBoard({
  items,
  loading,
  highlightedBduIds,
  maxPublicationAt,
  publishedLast24hCount,
  onBduClick
}: {
  items: HotBduRow[] | undefined;
  loading: boolean;
  highlightedBduIds?: ReadonlySet<string> | null;
  maxPublicationAt?: string | null;
  publishedLast24hCount?: number;
  onBduClick: (bduId: string) => void;
}) {
  const [cat, setCat] = useState<HotCategory>("all24h");
  const { isDone } = useVocTriage();
  const stats = useMemo(() => {
    const arr = items ?? [];
    const exploit = arr.filter((i) => i.hasExploit).length;
    const cvss9 = arr.filter((i) => typeof i.cvssScore === "number" && i.cvssScore >= 9).length;
    const linked = arr.filter(
      (i) => (i.linkedCveIds?.length ?? 0) > 0 || (i.cveIds?.length ?? 0) > 0
    ).length;
    return { total: arr.length, exploit, cvss9, linked };
  }, [items]);

  const list = useMemo(() => items ?? [], [items]);
  const filtered = useMemo(() => {
    const base = filterByCategory(list, cat);
    return [...base].sort(cat === "all24h" ? byUrgencyDesc : byPublishedDesc);
  }, [list, cat]);
  const tone = categoryTone(cat);

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

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="text-base font-semibold tracking-tight text-fg/95">Срочные БДУ ФСТЭК за последние 24 часа</div>
          <p className="mt-1 max-w-2xl text-[12px] leading-relaxed text-muted">
            Только записи БДУ из окна 24ч с сильным сигналом: exploit, CVSS ≥ 9 или связь с CVE из KEV / EPSS ≥ 50%.
            Всего БДУ с датой <span className="font-medium text-fg/80">publication_date</span> за 24ч:{" "}
            {typeof publishedLast24hCount === "number"
              ? publishedLast24hCount.toLocaleString()
              : stats.total.toLocaleString()}{" "}
            в базе, но здесь оставлены только срочные.
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
              sub: "exploit / KEV / EPSS",
              tone: "from-teal-500/15 to-emerald-600/10"
            },
            {
              key: "exploit",
              icon: ShieldAlert,
              label: "Эксплойт",
              value: stats.exploit,
              sub: "has_exploit",
              tone: "from-rose-500/20 to-red-600/10"
            },
            {
              key: "cvss9",
              icon: Zap,
              label: "CVSS ≥ 9",
              value: stats.cvss9,
              sub: "критический вектор",
              tone: "from-amber-500/15 to-orange-600/10"
            },
            {
              key: "linked",
              icon: Link2,
              label: "С CVE",
              value: stats.linked,
              sub: "связь с NVD",
              tone: "from-indigo-500/15 to-violet-600/10"
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
            За последние 24 часа (дата публикации или обновления в выгрузке ФСТЭК) нет срочных БДУ:
            exploit, <span className="font-medium text-fg/85">CVSS ≥ 9</span> или связь с CVE.
          </p>
          <p className="mt-2 text-[11px] leading-relaxed">
            Синк БДУ с bdu.fstec.ru — каждые 30 минут. Если лента пуста, проверьте ingest и доступ к ФСТЭК.
          </p>
          {maxPublicationAt ? (
            <p className="mt-2 text-[12px]">
              Последняя публикация в базе:{" "}
              <span className="font-medium text-fg/80">{new Date(maxPublicationAt).toLocaleString()}</span>
            </p>
          ) : null}
          <p className="mt-2 text-[11px] leading-relaxed">
            Полная выгрузка остаётся доступна в модуле уязвимостей; главная показывает только срочный слой.
          </p>
        </div>
      ) : (
        <ScrollableBoardGrid maxHeightClass="max-h-[min(30rem,calc(100vh-17rem))]">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {filtered.map((it, idx) => {
            const risk = bduRiskScore(it);
            const cvss =
              typeof it.cvssScore === "number" && Number.isFinite(it.cvssScore) ? it.cvssScore.toFixed(1) : "—";
            const linked = it.linkedCveIds ?? [];
            const registry = it.cveIds ?? [];
            const isOpen = highlightedBduIds?.has(it.bduId) ?? false;
            const processedKey = bduRefKey(it.bduId);
            const done = isDone(processedKey);
            return (
              <motion.div
                key={it.bduId}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.03 * Math.min(idx, 12) }}
                className="min-w-0"
              >
                <button
                  type="button"
                  onClick={() => onBduClick(it.bduId)}
                  className={cn(
                    "group relative z-[1] w-full cursor-pointer rounded-2xl border bg-gradient-to-br p-4 text-left",
                    "from-slate-100 to-slate-200/70 hover:from-slate-50 hover:to-slate-100",
                    "dark:from-white/[0.07] dark:to-black/30 dark:hover:from-white/[0.09] dark:hover:to-black/25",
                    "pointer-events-auto transition hover:border-accent/35 active:scale-[0.99]",
                    isOpen && "border-accent/50 ring-2 ring-accent/25",
                    done && "border-ok/25",
                    processedCardClass(done),
                    cn("ring-1", tone.ring, tone.border)
                  )}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <VocTriageCheckpoint refKey={processedKey} title={`BDU:${it.bduId}`} compact />
                        <div className="font-mono text-sm font-semibold tracking-tight text-fg/95 group-hover:text-fg">
                          {it.bduId}
                        </div>
                      </div>
                      <div className="mt-1 line-clamp-2 text-[11px] leading-snug text-fg/80">{it.name || "—"}</div>
                      <div className="mt-1 text-[10px] text-muted">
                        {it.publicationDate
                          ? `опубл. ${it.publicationDate}`
                          : it.identifyDate
                            ? `выявл. ${it.identifyDate}`
                            : "нет даты"}
                      </div>
                    </div>
                    <span
                      className={cn(
                        "shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-medium",
                        risk != null && risk >= 70
                          ? "border-danger/35 bg-danger/10 text-danger"
                          : "border-slate-200 bg-white text-fg/80 shadow-sm dark:border-white/10 dark:bg-white/5 dark:shadow-none"
                      )}
                    >
                      {risk != null ? `${risk}` : "—"}
                    </span>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {it.hasExploit ? (
                      <span className="rounded-full border border-danger/35 bg-danger/10 px-2 py-0.5 text-[10px] text-danger">
                        эксплойт
                      </span>
                    ) : null}
                    {it.severity ? (
                      <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 text-[10px] text-fg/80 dark:border-white/10 dark:bg-white/5">
                        {it.severity}
                      </span>
                    ) : null}
                    <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 text-[10px] text-muted dark:border-white/10 dark:bg-white/5">
                      CVSS {cvss}
                    </span>
                    {linked.length > 0 ? (
                      <span className="rounded-full border border-indigo-500/30 bg-indigo-500/10 px-2 py-0.5 text-[10px] text-indigo-200">
                        CVE {linked.slice(0, 2).join(", ")}
                        {linked.length > 2 ? "…" : ""}
                      </span>
                    ) : registry.length > 0 ? (
                      <span className="rounded-full border border-slate-200/80 bg-slate-50 px-2 py-0.5 text-[10px] text-muted dark:border-white/10 dark:bg-white/5">
                        в реестре: {registry.slice(0, 2).join(", ")}
                      </span>
                    ) : null}
                  </div>
                </button>
              </motion.div>
            );
          })}
          </div>
        </ScrollableBoardGrid>
      )}

      {stats.total > 0 && filtered.length === 0 ? (
        <div className="flex items-center gap-2 rounded-xl border border-dashed border-slate-300 px-4 py-6 text-sm text-muted dark:border-white/10">
          <Flame className="h-4 w-4 shrink-0 opacity-70" />
          В этой категории за 24ч записей нет — переключите фильтр.
        </div>
      ) : null}
    </div>
  );
}

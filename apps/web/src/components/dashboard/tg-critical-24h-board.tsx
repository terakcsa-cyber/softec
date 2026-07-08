"use client";

import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { ExternalLink, Flame, MessageCircle, Radio, ShieldAlert } from "lucide-react";
import { cn } from "../ui/cn";
import { ScrollableBoardGrid } from "./scrollable-board-grid";
import type { TgCriticalRow } from "@/lib/tg-feed-critical";
import { VocTriageCheckpoint, processedCardClass } from "./voc-triage-checkpoint";
import { tgRefKey } from "@/lib/voc-ref-keys";
import { useVocTriage } from "@/lib/voc-triage-context";

type TgCategory = "all" | "kev" | "text" | "multi";

function fmtPub(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("ru-RU", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit"
  });
}

function filterRows(rows: TgCriticalRow[], cat: TgCategory): TgCriticalRow[] {
  if (cat === "kev") return rows.filter((r) => r.cveIntel.some((c) => c.exploit_known));
  if (cat === "text") return rows.filter((r) => r.reasons.some((x) => x.includes("сигнал в тексте")));
  if (cat === "multi") return rows.filter((r) => (r.item.cveIds?.length ?? 0) >= 2);
  return rows;
}

function scoreTone(score: number): string {
  if (score >= 80) return "border-danger/40 bg-danger/10 text-danger";
  if (score >= 55) return "border-warn/35 bg-warn/10 text-warn";
  if (score >= 35) return "border-accent/30 bg-accent/10 text-fg/85";
  return "border-slate-200 bg-slate-50 text-fg/75 dark:border-white/10 dark:bg-white/5";
}

export function TgCritical24hBoard({
  rows,
  loading,
  channelCount,
  fetchedAt,
  errors,
  onCveClick,
  onOpenPost
}: {
  rows: TgCriticalRow[] | undefined;
  loading: boolean;
  channelCount?: number;
  fetchedAt?: string | null;
  errors?: { url: string; error: string }[];
  onCveClick?: (cveId: string) => void;
  onOpenPost?: (link: string) => void;
}) {
  const [cat, setCat] = useState<TgCategory>("all");
  const { isDone } = useVocTriage();
  const list = rows ?? [];

  const stats = useMemo(() => {
    const kev = list.filter((r) => r.cveIntel.some((c) => c.exploit_known)).length;
    const text = list.filter((r) => r.reasons.some((x) => x.includes("сигнал в тексте"))).length;
    const multi = list.filter((r) => (r.item.cveIds?.length ?? 0) >= 2).length;
    return { total: list.length, kev, text, multi };
  }, [list]);

  const filtered = useMemo(() => filterRows(list, cat), [list, cat]);

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-20 animate-pulse rounded-2xl bg-slate-200/70 dark:bg-white/[0.06]" />
          ))}
        </div>
        <div className="h-48 animate-pulse rounded-2xl bg-slate-200/50 dark:bg-white/[0.05]" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="flex items-center gap-2 text-base font-semibold tracking-tight text-fg/95">
            <Radio className="h-4 w-4 text-sky-500" />
            Горящие сигналы из Telegram за 24 часа
          </div>
          <p className="mt-1 max-w-3xl text-[12px] leading-relaxed text-muted">
            Агрегация из {typeof channelCount === "number" ? channelCount : "—"} каналов ИБ: посты за сутки с CVE и
            критичными маркерами (KEV, EPSS, CVSS, 0-day, RCE, активная эксплуатация).
            {fetchedAt ? (
              <>
                {" "}
                Обновлено: <span className="font-mono text-[11px] text-fg/75">{fmtPub(fetchedAt)}</span>.
              </>
            ) : null}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {(
          [
            { key: "all", icon: Flame, label: "Горящие", value: stats.total, sub: "за 24ч" },
            { key: "kev", icon: ShieldAlert, label: "KEV в посте", value: stats.kev, sub: "CISA каталог" },
            { key: "text", icon: MessageCircle, label: "Сигнал в тексте", value: stats.text, sub: "0-day / RCE" },
            { key: "multi", icon: Radio, label: "Несколько CVE", value: stats.multi, sub: "массовые" }
          ] as const
        ).map((c, i) => {
          const active = cat === c.key;
          return (
            <motion.button
              key={c.key}
              type="button"
              onClick={() => setCat(c.key)}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.03 * i }}
              className={cn(
                "rounded-2xl border border-slate-200/90 bg-gradient-to-br from-sky-500/10 to-indigo-600/5 p-3 text-left ring-1 ring-slate-200/60",
                "dark:border-white/[0.08] dark:ring-white/[0.04]",
                active && "ring-2 ring-sky-400/30 border-sky-400/35"
              )}
            >
              <div className="flex items-center gap-2 text-[11px] font-medium text-muted">
                <c.icon className="h-3.5 w-3.5 opacity-90" />
                {c.label}
              </div>
              <div className="mt-1.5 text-2xl font-semibold tabular-nums tracking-tight text-fg/95">{c.value}</div>
              <div className="text-[10px] text-muted/90">{c.sub}</div>
            </motion.button>
          );
        })}
      </div>

      {stats.total === 0 ? (
        <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 px-4 py-8 text-center text-sm text-muted dark:border-border dark:bg-black/10">
          <p>За последние 24 часа критичных сигналов из Telegram не найдено.</p>
          <p className="mt-2 text-[11px] leading-relaxed">
            Лента опрашивается каждые ~30 секунд. Если каналы недоступны — проверьте сеть и доступ к t.me.
          </p>
          {errors?.length ? (
            <p className="mt-2 text-[11px] text-warn">{errors[0]?.error}</p>
          ) : null}
        </div>
      ) : (
        <ScrollableBoardGrid
          empty={null}
          maxHeightClass="max-h-[min(32rem,calc(100vh-16rem))]"
        >
          <div className="grid gap-2.5 sm:grid-cols-2">
            {filtered.map((row, idx) => {
              const { item, score, reasons, cveIntel } = row;
              const preview = (item.descriptionText || item.title || "").trim();
              const processedKey = tgRefKey(item.id);
              const done = isDone(processedKey);
              return (
                <motion.article
                  key={item.id}
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.02 * Math.min(idx, 10) }}
                  className={cn(
                    "rounded-2xl border border-slate-200/90 bg-gradient-to-br from-white to-slate-50/90 p-3.5 ring-1 ring-slate-200/50",
                    "dark:border-white/[0.08] dark:from-white/[0.05] dark:to-black/25 dark:ring-white/[0.04]",
                    done && "border-ok/25",
                    processedCardClass(done)
                  )}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <VocTriageCheckpoint refKey={processedKey} title={item.title || item.id} compact />
                        <span className="rounded-full border border-sky-400/30 bg-sky-500/10 px-2 py-0.5 text-[10px] font-medium text-sky-700 dark:text-sky-300">
                          @{item.channel.slug}
                        </span>
                        <span className="text-[10px] text-muted">{fmtPub(item.pubDate)}</span>
                      </div>
                      <h3 className="mt-1.5 line-clamp-2 text-[12px] font-medium leading-snug text-fg/92">
                        {item.title || preview.slice(0, 140) || "Пост без заголовка"}
                      </h3>
                    </div>
                    <span className={cn("shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-semibold tabular-nums", scoreTone(score))}>
                      {score}
                    </span>
                  </div>

                  {preview && item.title ? (
                    <p className="mt-2 line-clamp-2 text-[11px] leading-relaxed text-muted">{preview}</p>
                  ) : null}

                  <div className="mt-2.5 flex flex-wrap gap-1.5">
                    {cveIntel.slice(0, 4).map((cve) => (
                      <button
                        key={cve.cve_id}
                        type="button"
                        onClick={() => onCveClick?.(cve.cve_id)}
                        className={cn(
                          "rounded-full border px-2 py-0.5 font-mono text-[10px] transition hover:-translate-y-px",
                          cve.exploit_known
                            ? "border-danger/35 bg-danger/10 text-danger"
                            : typeof cve.epss === "number" && cve.epss >= 0.5
                              ? "border-warn/35 bg-warn/10 text-warn"
                              : "border-accent/30 bg-accent/10 text-fg/85"
                        )}
                        title={[
                          cve.vp_vendor,
                          cve.vp_product,
                          typeof cve.epss === "number" ? `EPSS ${(cve.epss * 100).toFixed(1)}%` : null,
                          typeof cve.cvss_base === "number" ? `CVSS ${cve.cvss_base.toFixed(1)}` : null
                        ]
                          .filter(Boolean)
                          .join(" • ")}
                      >
                        {cve.cve_id}
                      </button>
                    ))}
                    {item.cveIds
                      .filter((id) => !cveIntel.some((c) => c.cve_id === id))
                      .slice(0, 3)
                      .map((id) => (
                        <button
                          key={id}
                          type="button"
                          onClick={() => onCveClick?.(id)}
                          className="rounded-full border border-slate-200 bg-white px-2 py-0.5 font-mono text-[10px] text-fg/80 dark:border-white/10 dark:bg-white/5"
                        >
                          {id}
                        </button>
                      ))}
                  </div>

                  {reasons.length > 0 ? (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {reasons.slice(0, 4).map((r) => (
                        <span
                          key={r}
                          className="rounded-md border border-accent/20 bg-accent/8 px-1.5 py-0.5 text-[9px] text-fg/80"
                        >
                          {r}
                        </span>
                      ))}
                    </div>
                  ) : null}

                  <div className="mt-3 flex items-center justify-end">
                    <button
                      type="button"
                      onClick={() => (onOpenPost ? onOpenPost(item.link) : window.open(item.link, "_blank", "noopener,noreferrer"))}
                      className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2 py-1 text-[10px] text-fg/80 hover:bg-slate-50 dark:border-white/10 dark:bg-black/20 dark:hover:bg-black/35"
                    >
                      <ExternalLink className="h-3 w-3" />
                      Открыть в TG
                    </button>
                  </div>
                </motion.article>
              );
            })}
          </div>
        </ScrollableBoardGrid>
      )}

      {stats.total > 0 && filtered.length === 0 ? (
        <div className="rounded-xl border border-dashed border-slate-300 px-4 py-5 text-sm text-muted dark:border-white/10">
          В выбранной категории за 24ч записей нет.
        </div>
      ) : null}
    </div>
  );
}

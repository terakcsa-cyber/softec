"use client";

import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { ArrowRight, ExternalLink, Globe, Newspaper, RefreshCw, Rss, Sparkles } from "lucide-react";
import { apiFetch } from "@/lib/api-fetch";
import type { FstecFeedItem } from "@/lib/fstec-rss";
import type { LocalBduEnrichmentStatus } from "@/lib/fstec-feed-enrich";
import { cn } from "../ui/cn";

export type FstecNewsPanelProps = {
  /** Та же перетаскиваемая карточка CVE, что и по клику на «горячие» CVE за 24ч на дашборде. */
  onOpenCve?: (cveId: string) => void;
};

type FeedResponse = {
  items: FstecFeedItem[];
  source: {
    url: string;
    fetchedAt: string;
    kind?: "telegram" | "rss";
    channel?: string;
    localBduEnrichment?: LocalBduEnrichmentStatus;
  };
  error?: string;
};

function fmtPubDate(isoOrRfc: string | null): string {
  if (!isoOrRfc) return "—";
  const d = new Date(isoOrRfc);
  if (Number.isNaN(d.getTime())) return isoOrRfc;
  return d.toLocaleString("ru-RU", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  });
}

export function FstecNewsPanel({ onOpenCve }: FstecNewsPanelProps) {
  const q = useQuery({
    queryKey: ["fstec", "feed"],
    queryFn: async () => {
      const res = await apiFetch("/api/fstec/feed", { cache: "no-store" });
      const body = (await res.json()) as FeedResponse;
      if (!res.ok) {
        throw new Error(body.error ?? `Ошибка загрузки (${res.status})`);
      }
      return body;
    },
    staleTime: 60_000
  });

  const enrich = q.data?.source.localBduEnrichment;

  return (
    <div className="glass rounded-2xl p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 space-y-1">
          <div className="flex items-center gap-2 text-sm font-semibold tracking-tight">
            <Newspaper className="h-4 w-4 shrink-0 text-accent" aria-hidden />
            ФСТЭК · лента БДУ
          </div>
          <p className="max-w-2xl text-xs leading-relaxed text-muted">
            Канал <span className="text-fg/80">@bdufstecru</span> (БДУ ФСТЭК). Лента с{" "}
            <span className="text-fg/80">t.me/s/…</span>. Если в тексте есть{" "}
            <span className="font-mono text-[10px] text-fg/85">BDU:…</span> и{" "}
            <span className="font-mono text-[10px] text-fg/85">CVE-…</span>, а CVE уже в вашей базе — покажем связку;
            по кнопке откроется та же плавающая карточка CVE, что на дашборде для «за 24 часа».
          </p>
        </div>
        <button
          type="button"
          onClick={() => void q.refetch()}
          disabled={q.isFetching}
          className={cn(
            "inline-flex shrink-0 items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-fg/90 shadow-sm",
            "hover:bg-slate-50 disabled:opacity-50 dark:border-border dark:bg-black/25 dark:shadow-none dark:hover:bg-black/35"
          )}
        >
          <RefreshCw className={cn("h-3.5 w-3.5", q.isFetching && "animate-spin")} aria-hidden />
          Обновить
        </button>
      </div>

      {enrich === "unavailable" ? (
        <div className="mt-4 rounded-xl border border-warn/35 bg-warn/10 px-3 py-2.5 text-[11px] leading-snug text-warn">
          Связка с локальной базой недоступна: API не ответил. Убедитесь, что backend запущен и для web заданы{" "}
          <code className="rounded bg-slate-100 px-1 font-mono text-[10px] dark:bg-black/30">UPSTREAM_API_BASE</code> или{" "}
          <code className="rounded bg-slate-100 px-1 font-mono text-[10px] dark:bg-black/30">NEXT_PUBLIC_API_BASE</code>
          (в dev по умолчанию пробуем <span className="font-mono">127.0.0.1:4001/api</span>).
        </div>
      ) : null}

      <div className="mt-5 flex items-center gap-2 border-t border-slate-200/90 pt-4 text-[11px] text-muted dark:border-white/[0.06]">
        {q.data?.source.kind === "rss" ? (
          <Rss className="h-3.5 w-3.5 shrink-0" aria-hidden />
        ) : (
          <Globe className="h-3.5 w-3.5 shrink-0" aria-hidden />
        )}
        <span className="truncate">
          {q.data?.source.kind === "rss" ? "Источник RSS:" : "Источник (Telegram):"}{" "}
          {q.data?.source.url ? (
            <a
              href={q.data.source.url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-accent hover:underline"
            >
              {q.data.source.url}
            </a>
          ) : (
            "—"
          )}
          {q.data?.source.channel ? (
            <span className="text-muted"> · {q.data.source.channel}</span>
          ) : null}
        </span>
        {q.data?.source.fetchedAt ? (
          <span className="ml-auto shrink-0 tabular-nums text-muted">
            загружено {fmtPubDate(q.data.source.fetchedAt)}
          </span>
        ) : null}
      </div>

      <div className="mt-4 max-h-[min(560px,calc(100vh-220px))] space-y-3 overflow-y-auto pr-1">
        {q.isLoading ? (
          <div className="space-y-3">
            {Array.from({ length: 5 }).map((_, i) => (
              <div
                key={i}
                className="animate-pulse rounded-xl border border-slate-200 bg-slate-50 p-4 dark:border-white/[0.06] dark:bg-black/20"
              >
                <div className="h-3 w-2/3 rounded bg-slate-200/80 dark:bg-white/10" />
                <div className="mt-3 h-2 w-full rounded bg-slate-200/60 dark:bg-white/[0.06]" />
                <div className="mt-2 h-2 w-4/5 rounded bg-slate-200/60 dark:bg-white/[0.06]" />
              </div>
            ))}
          </div>
        ) : q.isError ? (
          <div className="rounded-xl border border-danger/30 bg-danger/10 p-4 text-sm text-danger">
            {q.error instanceof Error ? q.error.message : "Не удалось загрузить ленту"}
          </div>
        ) : !q.data?.items?.length ? (
          <div className="rounded-xl border border-border bg-slate-50 p-6 text-center text-sm text-muted dark:bg-black/20">
            Записей пока нет — проверьте доступность t.me или настройки FSTEC_TG_CHANNEL / RSS.
          </div>
        ) : (
          q.data.items.map((item, idx) => (
            <motion.article
              key={item.id}
              layout={false}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.22, delay: Math.min(idx * 0.04, 0.4) }}
              className={cn(
                "rounded-xl border border-slate-200/90 bg-gradient-to-br from-white to-slate-50 p-4 shadow-sm dark:border-white/[0.07] dark:from-black/35 dark:to-black/20",
                "transition-[box-shadow,border-color] duration-200 hover:border-accent/30 hover:shadow-md",
                item.localBduLinks?.length ? "ring-1 ring-accent/20" : ""
              )}
            >
              <div className="flex flex-wrap items-start justify-between gap-2 gap-y-1">
                <h3 className="min-w-0 flex-1 text-sm font-medium leading-snug text-fg/95">{item.title || "Без заголовка"}</h3>
                <time
                  className="shrink-0 tabular-nums text-[11px] text-muted"
                  dateTime={item.pubDate ?? undefined}
                >
                  {fmtPubDate(item.pubDate)}
                </time>
              </div>
              {item.descriptionText ? (
                <p className="mt-2 line-clamp-6 whitespace-pre-wrap text-[13px] leading-relaxed text-fg/80">
                  {item.descriptionText}
                </p>
              ) : null}
              {item.localBduLinks && item.localBduLinks.length > 0 ? (
                <div className="mt-3 flex flex-wrap gap-2">
                  {item.localBduLinks.map((l) => (
                    <div
                      key={`${l.cveId}-${l.bduId}`}
                      className="flex w-full min-w-0 flex-col gap-2 rounded-xl border border-accent/30 bg-accent/[0.12] px-2.5 py-2 text-[11px] text-fg/90 sm:flex-row sm:items-center sm:justify-between sm:gap-3"
                    >
                      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
                        <Sparkles className="h-3.5 w-3.5 shrink-0 text-accent" aria-hidden />
                        <span className="text-muted">в базе</span>
                        <span className="font-mono tabular-nums text-fg/95">{l.cveId}</span>
                        <span className="text-muted">·</span>
                        <span className="truncate">
                          BDU:<span className="font-mono">{l.bduId}</span>
                        </span>
                      </div>
                      {onOpenCve ? (
                        <button
                          type="button"
                          onClick={() => onOpenCve(l.cveId)}
                          className={cn(
                            "inline-flex w-full shrink-0 items-center justify-center gap-1 rounded-lg border border-accent/40 bg-white px-2.5 py-1.5 text-[10px] font-medium uppercase tracking-wide text-accent shadow-sm sm:w-auto dark:bg-black/25 dark:shadow-none",
                            "hover:bg-accent/15 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-accent"
                          )}
                        >
                          Карточка CVE
                          <ArrowRight className="h-3 w-3" aria-hidden />
                        </button>
                      ) : null}
                    </div>
                  ))}
                </div>
              ) : null}
              {item.link ? (
                <a
                  href={item.link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="mt-3 inline-flex items-center gap-1.5 text-xs font-medium text-accent hover:underline"
                >
                  Открыть в Telegram
                  <ExternalLink className="h-3 w-3" aria-hidden />
                </a>
              ) : null}
            </motion.article>
          ))
        )}
      </div>
    </div>
  );
}

"use client";

import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { ArrowRight, ExternalLink, Globe, Loader2, Newspaper, RefreshCw, Rss, Sparkles, Volume2 } from "lucide-react";
import { apiFetch } from "@/lib/api-fetch";
import type { FstecFeedItem } from "@/lib/fstec-rss";
import type { LocalBduEnrichmentStatus } from "@/lib/fstec-feed-enrich";
import { useEffect, useMemo, useRef, useState } from "react";
import { cn } from "../ui/cn";

export type FstecNewsPanelProps = {
  /** Та же перетаскиваемая карточка CVE, что и по клику на «горячие» CVE за 24ч на дашборде. */
  onOpenCve?: (cveId: string) => void;
  /** Полная карточка BDU в модуле «Уязвимости» (как CVE). */
  onOpenBdu?: (bduId: string) => void;
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

export function FstecNewsPanel({ onOpenCve, onOpenBdu }: FstecNewsPanelProps) {
  const [toast, setToast] = useState<{ title: string; body?: string } | null>(null);
  const toastTimer = useRef<number | null>(null);
  const [soundEnabled, setSoundEnabled] = useState(true);

  const storageKey = "vip:fstec:lastSeenId";

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
    staleTime: 60_000,
    refetchInterval: 60_000,
    refetchIntervalInBackground: true
  });

  const newest = useMemo(() => {
    const items = (q.data?.items ?? []) as FstecFeedItem[];
    return items.length > 0 ? items[0] : null;
  }, [q.data?.items]);

  useEffect(() => {
    if (!newest?.id) return;
    // Global notifier handles notifications across modules.
    try {
      if (localStorage.getItem("vip:live:global") === "1") return;
    } catch {
      // ignore
    }
    let last = "";
    try {
      last = localStorage.getItem(storageKey) ?? "";
    } catch {
      last = "";
    }
    // First load: don't notify, just mark.
    if (!last) {
      try {
        localStorage.setItem(storageKey, newest.id);
      } catch {
        // ignore
      }
      return;
    }
    if (last === newest.id) return;

    try {
      localStorage.setItem(storageKey, newest.id);
    } catch {
      // ignore
    }

    // Show toast + optional beep.
    setToast({
      title: "ФСТЭК: новая публикация",
      body: newest.title || "Новая запись в ленте БДУ"
    });

    if (toastTimer.current) window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(null), 7000);

    if (soundEnabled) {
      try {
        const Ctx = (window.AudioContext ||
          (window as Window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext) as
          | typeof AudioContext
          | undefined;
        if (Ctx) {
          const ctx = new Ctx();
          const o = ctx.createOscillator();
          const g = ctx.createGain();
          o.type = "sine";
          o.frequency.value = 880;
          g.gain.value = 0.0001;
          o.connect(g);
          g.connect(ctx.destination);
          o.start();
          const now = ctx.currentTime;
          g.gain.setValueAtTime(0.0001, now);
          g.gain.linearRampToValueAtTime(0.08, now + 0.02);
          g.gain.exponentialRampToValueAtTime(0.0001, now + 0.16);
          o.stop(now + 0.18);
          o.onended = () => void ctx.close().catch(() => undefined);
        }
      } catch {
        // ignore audio errors
      }
    }
  }, [newest?.id, newest?.title, soundEnabled]);

  useEffect(() => {
    return () => {
      if (toastTimer.current) window.clearTimeout(toastTimer.current);
    };
  }, []);

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
            <span className="font-mono text-[10px] text-fg/85">CVE-…</span> — связка с CVE в базе или отдельная карточка из реестра БДУ
            (полная XML-выгрузка ФСТЭК). CVE в базе открывается плавающей карточкой, как на дашборде.
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <button
            type="button"
            title={soundEnabled ? "Звук: включён" : "Звук: выключен"}
            onClick={() => setSoundEnabled((v) => !v)}
            className={cn(
              "inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-fg/90 shadow-sm",
              "hover:bg-slate-50 dark:border-border dark:bg-black/25 dark:shadow-none dark:hover:bg-black/35"
            )}
          >
            <Volume2 className={cn("h-3.5 w-3.5", !soundEnabled && "opacity-40")} aria-hidden />
            {soundEnabled ? "Звук" : "Без звука"}
          </button>
          <button
            type="button"
            onClick={() => void q.refetch()}
            disabled={q.isFetching}
            className={cn(
              "inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-fg/90 shadow-sm",
              "hover:bg-slate-50 disabled:opacity-50 dark:border-border dark:bg-black/25 dark:shadow-none dark:hover:bg-black/35"
            )}
          >
            {q.isFetching ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
            ) : (
              <RefreshCw className="h-3.5 w-3.5" aria-hidden />
            )}
            Обновить
          </button>
        </div>
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
              {item.registryBduLinks && item.registryBduLinks.length > 0 ? (
                <div className="mt-3 flex flex-col gap-2">
                  {item.registryBduLinks.map((l) => (
                    <div
                      key={l.bduId}
                      className="flex w-full min-w-0 flex-col gap-2 rounded-xl border border-amber-200/60 bg-amber-50/80 px-2.5 py-2 text-[11px] dark:border-amber-500/25 dark:bg-amber-950/20 sm:flex-row sm:items-center sm:justify-between"
                    >
                      <div className="min-w-0">
                        <span className="font-mono text-fg/95">BDU:{l.bduId}</span>
                        <span className="ml-2 text-muted">{l.name}</span>
                      </div>
                      {onOpenBdu ? (
                        <button
                          type="button"
                          onClick={() => onOpenBdu(l.bduId)}
                          className={cn(
                            "inline-flex w-full shrink-0 items-center justify-center gap-1 rounded-lg border border-accent/40 bg-white px-2.5 py-1.5 text-[10px] font-medium uppercase tracking-wide text-accent shadow-sm sm:w-auto dark:bg-black/25 dark:shadow-none",
                            "hover:bg-accent/15 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-accent"
                          )}
                        >
                          Карточка BDU
                          <ArrowRight className="h-3 w-3" aria-hidden />
                        </button>
                      ) : null}
                    </div>
                  ))}
                </div>
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

      {toast ? (
        <div className="pointer-events-none fixed bottom-4 right-4 z-[60] w-[min(420px,calc(100vw-2rem))]">
          <div className="pointer-events-auto rounded-2xl border border-slate-200/80 bg-white/95 p-4 shadow-2xl backdrop-blur dark:border-white/[0.08] dark:bg-black/70">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="text-xs font-semibold text-fg/95">{toast.title}</div>
                {toast.body ? (
                  <div className="mt-1 line-clamp-2 text-[11px] leading-snug text-muted">{toast.body}</div>
                ) : null}
              </div>
              <button
                type="button"
                onClick={() => setToast(null)}
                className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-[11px] font-medium text-fg/80 hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/35"
              >
                Ок
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

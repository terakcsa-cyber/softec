"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import * as Dialog from "@radix-ui/react-dialog";
import { Bandage, ExternalLink, Loader2, RefreshCw, Search, Volume2 } from "lucide-react";
import { apiFetch } from "@/lib/api-fetch";
import { cn } from "../ui/cn";

type PatchChannel = { slug: string; title: string };

type PatchFeedItem = {
  id: string;
  title: string;
  link: string;
  pubDate: string | null;
  descriptionText: string;
  channel: PatchChannel;
  cveIds: string[];
};

type PatchFeedResponse = {
  items: PatchFeedItem[];
  source: { fetchedAt: string; kind: string; channels: PatchChannel[] };
  errors?: { url: string; error: string }[];
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

function matchQuery(it: PatchFeedItem, q: string): boolean {
  if (!q) return true;
  const needle = q.toLowerCase();
  if (it.title.toLowerCase().includes(needle)) return true;
  if ((it.descriptionText ?? "").toLowerCase().includes(needle)) return true;
  return (it.cveIds ?? []).some((c) => c.toLowerCase().includes(needle));
}

function beepPatch() {
  try {
    const Ctx = (window.AudioContext ||
      (window as Window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext) as
      | typeof AudioContext
      | undefined;
    if (!Ctx) return;
    const ctx = new Ctx();
    const o = ctx.createOscillator();
    const g = ctx.createGain();
    o.type = "sine";
    o.frequency.value = 740;
    g.gain.value = 0.0001;
    o.connect(g);
    g.connect(ctx.destination);
    o.start();
    const now = ctx.currentTime;
    g.gain.setValueAtTime(0.0001, now);
    g.gain.linearRampToValueAtTime(0.07, now + 0.02);
    g.gain.exponentialRampToValueAtTime(0.0001, now + 0.16);
    o.stop(now + 0.18);
    o.onended = () => void ctx.close().catch(() => undefined);
  } catch {
    // ignore
  }
}

export function PatchManagementPanel({
  onOpenCve
}: {
  /** Та же перетаскиваемая карточка CVE, что на дашборде / в ФСТЭК. */
  onOpenCve?: (cveId: string) => void;
}) {
  const [channel, setChannel] = useState<string>("");
  const [q, setQ] = useState("");
  const [qDebounced, setQDebounced] = useState("");
  const [toast, setToast] = useState<{ title: string; body?: string } | null>(null);
  const toastTimer = useRef<number | null>(null);
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [detailId, setDetailId] = useState<string | null>(null);

  const storageKey = "vip:patch:lastSeenId";

  useEffect(() => {
    const t = window.setTimeout(() => setQDebounced(q.trim()), 350);
    return () => window.clearTimeout(t);
  }, [q]);

  const feedQuery = useQuery({
    queryKey: ["patch", "telegram", "feed"],
    queryFn: async () => {
      const res = await apiFetch(`/api/patch/feed`, { cache: "no-store" });
      const body = (await res.json()) as PatchFeedResponse & { error?: string };
      if (!res.ok) throw new Error(body.error ?? "feed");
      return body as PatchFeedResponse;
    },
    staleTime: 30_000,
    refetchInterval: 30_000,
    refetchIntervalInBackground: true
  });

  const itemsRaw = useMemo(() => feedQuery.data?.items ?? [], [feedQuery.data?.items]);
  const channels = useMemo(() => feedQuery.data?.source.channels ?? [], [feedQuery.data?.source.channels]);

  const detail = useMemo(() => {
    if (!detailId) return null;
    return itemsRaw.find((x) => x.id === detailId) ?? null;
  }, [detailId, itemsRaw]);

  const items = useMemo(() => {
    return itemsRaw
      .filter((it) => (channel ? it.channel.slug === channel : true))
      .filter((it) => matchQuery(it, qDebounced));
  }, [itemsRaw, channel, qDebounced]);

  const newest = itemsRaw.length ? itemsRaw[0] : null;

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
    // First load: mark without notifying.
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

    setToast({
      title: "Patch: новая публикация",
      body: newest.title || `@${newest.channel.slug}`
    });
    if (toastTimer.current) window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(null), 7000);

    if (soundEnabled) beepPatch();
  }, [newest?.id, newest?.title, newest?.channel.slug, soundEnabled]);

  useEffect(() => {
    return () => {
      if (toastTimer.current) window.clearTimeout(toastTimer.current);
    };
  }, []);

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <div className="flex items-center gap-2 text-base font-semibold tracking-tight text-fg/95">
            <Bandage className="h-5 w-5 text-accent" />
            Патч‑менеджмент
          </div>
          <p className="mt-1 max-w-3xl text-[12px] leading-relaxed text-muted">
            Лента новостей и апдейтов из Telegram‑каналов по ИБ. Парсинг идёт по публичным страницам{" "}
            <span className="font-mono text-[11px] text-fg/85">t.me/s/…</span> (как в модуле ФСТЭК). При появлении новой записи —
            уведомление внизу справа.
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <button
            type="button"
            title={soundEnabled ? "Звук: включён" : "Звук: выключен"}
            onClick={() => setSoundEnabled((v) => !v)}
            className={cn(
              "inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-fg/90 hover:bg-slate-100",
              "dark:border-border dark:bg-black/20 dark:hover:bg-black/35"
            )}
          >
            <Volume2 className={cn("h-3.5 w-3.5", !soundEnabled && "opacity-40")} />
            {soundEnabled ? "Звук" : "Без звука"}
          </button>
          <button
            type="button"
            onClick={() => void feedQuery.refetch()}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-fg/90 hover:bg-slate-100 dark:border-border dark:bg-black/20 dark:hover:bg-black/35"
          >
            {feedQuery.isFetching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
            Обновить
          </button>
        </div>
      </div>

      <div className="flex flex-col gap-3 rounded-2xl border border-slate-200/90 bg-slate-50/80 p-4 dark:border-white/[0.06] dark:bg-black/20 sm:flex-row sm:items-center">
        <div className="flex min-w-0 flex-1 items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 dark:border-border dark:bg-zinc-950/80">
          <Search className="h-4 w-4 shrink-0 text-muted" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Поиск: заголовок, текст, CVE…"
            className="min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-muted"
          />
        </div>
        <select
          value={channel}
          onChange={(e) => setChannel(e.target.value)}
          className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-fg/90 dark:border-border dark:bg-black/30"
          title="Канал"
        >
          <option value="">Все каналы</option>
          {channels.map((c) => (
            <option key={c.slug} value={c.slug}>
              {c.title} (@{c.slug})
            </option>
          ))}
        </select>
      </div>

      {feedQuery.isError ? (
        <div className="rounded-xl border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">
          Не удалось загрузить ленту. Проверьте доступность Telegram и авторизацию.
        </div>
      ) : null}

      <div className="text-[11px] text-muted">
        В ленте: <span className="tabular-nums text-fg/85">{items.length}</span>
        {feedQuery.data?.source.fetchedAt ? (
          <span className="ml-2 tabular-nums">· загружено {fmtPubDate(feedQuery.data.source.fetchedAt)}</span>
        ) : null}
        {feedQuery.isFetching ? <span className="ml-2">· обновление…</span> : null}
      </div>

      <div className="space-y-3">
        {items.length === 0 && !feedQuery.isLoading ? (
          <div className="rounded-2xl border border-dashed border-slate-200/90 bg-slate-50/50 px-6 py-12 text-center text-sm text-muted dark:border-white/[0.08] dark:bg-black/15">
            Записей нет (с учётом фильтров). Попробуйте снять фильтры или обновить.
          </div>
        ) : null}

        {feedQuery.isLoading && items.length === 0 ? (
          <div className="flex items-center justify-center gap-2 py-16 text-sm text-muted">
            <Loader2 className="h-5 w-5 animate-spin" />
            Загрузка…
          </div>
        ) : null}

        {items.map((it) => (
          <article
            key={it.id}
            role="button"
            tabIndex={0}
            onClick={() => setDetailId(it.id)}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                setDetailId(it.id);
              }
            }}
            className="group cursor-pointer rounded-2xl border border-slate-200/90 bg-white/90 p-4 text-left shadow-sm outline-none transition-colors hover:border-accent/25 hover:bg-slate-50/90 focus-visible:ring-2 focus-visible:ring-accent/30 dark:border-white/[0.08] dark:bg-black/25 dark:hover:bg-black/35"
          >
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-full border border-accent/25 bg-accent/10 px-2 py-0.5 text-[10px] font-medium tracking-wide text-accent">
                    {it.channel.title} · @{it.channel.slug}
                  </span>
                  {it.pubDate ? <span className="text-[11px] text-muted">{fmtPubDate(it.pubDate)}</span> : null}
                </div>
                <h3 className="mt-2 text-sm font-semibold leading-snug text-fg/95">{it.title}</h3>
                {it.descriptionText ? (
                  <p className="mt-2 line-clamp-4 whitespace-pre-wrap text-[12px] leading-relaxed text-muted">
                    {it.descriptionText}
                  </p>
                ) : null}
              </div>
              <a
                href={it.link}
                target="_blank"
                rel="noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-2 py-1.5 text-[11px] text-fg/90 hover:bg-slate-100 dark:border-border dark:bg-black/30 dark:hover:bg-black/45"
              >
                Telegram
                <ExternalLink className="h-3 w-3" />
              </a>
            </div>

            {it.cveIds.length > 0 ? (
              <div className="mt-3 flex flex-wrap gap-1.5">
                {it.cveIds.slice(0, 12).map((id) => (
                  <button
                    key={id}
                    type="button"
                    title={onOpenCve ? "Открыть карточку CVE" : undefined}
                    onClick={() => onOpenCve?.(id)}
                    className={cn(
                      "rounded-full border px-2 py-0.5 font-mono text-[11px] tabular-nums",
                      "border-slate-200/90 bg-slate-100 text-slate-900",
                      "dark:border-white/[0.12] dark:bg-zinc-900/85 dark:text-zinc-200",
                      onOpenCve &&
                        "cursor-pointer hover:border-accent/40 hover:bg-accent/10 hover:text-slate-950 dark:hover:bg-accent/15 dark:hover:text-zinc-50",
                      !onOpenCve && "cursor-default opacity-80"
                    )}
                  >
                    {id}
                  </button>
                ))}
                {it.cveIds.length > 12 ? <span className="text-[11px] text-muted">+{it.cveIds.length - 12}</span> : null}
              </div>
            ) : null}
          </article>
        ))}
      </div>

      {toast ? (
        <div className="pointer-events-none fixed bottom-4 right-4 z-[60] w-[min(420px,calc(100vw-2rem))]">
          <div className="pointer-events-auto rounded-2xl border border-slate-200/80 bg-white/95 p-4 shadow-2xl backdrop-blur dark:border-white/[0.08] dark:bg-black/70">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="text-xs font-semibold text-fg/95">{toast.title}</div>
                {toast.body ? <div className="mt-1 line-clamp-2 text-[11px] leading-snug text-muted">{toast.body}</div> : null}
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

      <Dialog.Root
        open={detailId != null}
        onOpenChange={(open) => {
          if (!open) setDetailId(null);
        }}
      >
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-[100] bg-black/60 backdrop-blur-sm" />
          <Dialog.Content
            className={cn(
              "fixed left-1/2 top-1/2 z-[101] max-h-[min(85vh,880px)] w-[min(760px,calc(100vw-24px))] -translate-x-1/2 -translate-y-1/2",
              "flex flex-col overflow-hidden rounded-2xl border border-border bg-white shadow-2xl outline-none dark:bg-zinc-950"
            )}
            onOpenAutoFocus={(e) => e.preventDefault()}
          >
            <div className="flex shrink-0 items-start justify-between gap-3 border-b border-slate-200 px-5 py-4 dark:border-white/[0.08]">
              <div className="min-w-0">
                <Dialog.Title className="text-sm font-semibold leading-snug text-fg/95">
                  {detail?.channel.title ?? "Запись канала"}
                  {detail?.channel.slug ? <span className="text-muted"> · @{detail.channel.slug}</span> : null}
                </Dialog.Title>
                <Dialog.Description className="mt-1 text-[11px] text-muted">
                  {detail?.pubDate ? `Опубликовано: ${fmtPubDate(detail.pubDate)}` : "Дата публикации не указана"}
                </Dialog.Description>
              </div>
              <Dialog.Close asChild>
                <button
                  type="button"
                  className="rounded-lg border border-slate-200 px-2 py-1.5 text-[11px] text-fg/80 hover:bg-slate-100 dark:border-border dark:hover:bg-black/40"
                >
                  Закрыть
                </button>
              </Dialog.Close>
            </div>

            <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
              {detail ? (
                <div className="space-y-4">
                  <h2 className="text-base font-semibold leading-snug text-fg/95">{detail.title}</h2>

                  {detail.descriptionText ? (
                    <div className="rounded-xl border border-slate-200/90 bg-slate-50/80 px-4 py-3 text-[13px] leading-relaxed text-fg/85 dark:border-white/[0.08] dark:bg-black/25">
                      <div className="whitespace-pre-wrap">{detail.descriptionText}</div>
                    </div>
                  ) : (
                    <div className="rounded-xl border border-slate-200/90 bg-slate-50/80 px-4 py-3 text-sm text-muted dark:border-white/[0.08] dark:bg-black/25">
                      Текст сообщения отсутствует.
                    </div>
                  )}

                  {detail.cveIds.length > 0 ? (
                    <div>
                      <div className="text-[10px] font-medium uppercase tracking-wide text-muted">CVE</div>
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {detail.cveIds.map((id) => (
                          <button
                            key={id}
                            type="button"
                            onClick={() => onOpenCve?.(id)}
                            className={cn(
                              "rounded-full border px-2 py-0.5 font-mono text-[11px] tabular-nums",
                              "border-slate-200/90 bg-slate-100 text-slate-900",
                              "dark:border-white/[0.12] dark:bg-zinc-900/85 dark:text-zinc-200",
                              onOpenCve && "cursor-pointer hover:border-accent/40 hover:bg-accent/10 dark:hover:bg-accent/15",
                              !onOpenCve && "cursor-default opacity-80"
                            )}
                          >
                            {id}
                          </button>
                        ))}
                      </div>
                    </div>
                  ) : null}

                  <div className="flex flex-wrap gap-2 pt-1">
                    <a
                      href={detail.link}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-4 py-2 text-xs font-medium text-fg/90 hover:bg-slate-50 dark:border-border dark:bg-black/25 dark:hover:bg-black/40"
                    >
                      Открыть в Telegram
                      <ExternalLink className="h-3.5 w-3.5" />
                    </a>
                    <Dialog.Close asChild>
                      <button
                        type="button"
                        className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-2 text-xs text-fg/90 hover:bg-slate-100 dark:border-border dark:bg-black/20 dark:hover:bg-black/35"
                      >
                        Закрыть
                      </button>
                    </Dialog.Close>
                  </div>
                </div>
              ) : (
                <div className="flex items-center justify-center gap-2 py-16 text-sm text-muted">
                  <Loader2 className="h-6 w-6 animate-spin" />
                  Загрузка…
                </div>
              )}
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}

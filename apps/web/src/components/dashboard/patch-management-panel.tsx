"use client";

import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import * as Dialog from "@radix-ui/react-dialog";
import {
  Bandage,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Loader2,
  RefreshCw,
  Search,
  X
} from "lucide-react";
import { apiFetch } from "@/lib/api-fetch";
import { cn } from "../ui/cn";

/** Подписи вендоров для фильтра и бейджей (slug в БД остаётся латиницей). */
const VENDOR_LABEL_RU: Record<string, string> = {
  cbr_ru: "Банк России — новое на сайте",
  cbr_press_ru: "Банк России — пресс-релизы",
  safe_surf_ru: "Safe-Surf (рус. обновления безопасности)",
  opennet_ru: "OpenNET (новости)",
  xakep_ru: "«Хакер»",
  debian: "Debian",
  ubuntu: "Ubuntu",
  suse: "SUSE",
  redhat: "Red Hat",
  oracle: "Oracle",
  microsoft: "Microsoft",
  aws: "Amazon Web Services",
  google_cloud: "Google Cloud",
  cisa_alerts: "CISA — оповещения",
  cisa_activity: "CISA — текущая активность",
  cisa_ics: "CISA — АСУ ТП",
  kubernetes: "Kubernetes",
  cloudflare: "Cloudflare",
  unit42: "Palo Alto Unit 42",
  sentinelone: "SentinelOne"
};

function vendorLabelRu(slug: string): string {
  return VENDOR_LABEL_RU[slug] ?? slug.replace(/_/g, " ");
}

export type VendorAdvisoryItem = {
  id: string;
  feedUrl: string;
  vendorSlug: string;
  title: string;
  link: string;
  summary: string | null;
  publishedAt: string | null;
  cveIds: string[];
  fetchedAt: string;
  createdAt: string;
};

export type VendorAdvisoryDetail = VendorAdvisoryItem & {
  rawItem: {
    title?: string;
    link?: string;
    pubDate?: string;
    description?: string;
  } | null;
};

function htmlToPlainText(html: string): string {
  if (typeof window === "undefined") return html;
  try {
    const doc = new DOMParser().parseFromString(html, "text/html");
    const t = doc.body.textContent?.replace(/\u00a0/g, " ").trim();
    return t ?? html;
  } catch {
    return html;
  }
}

export function PatchManagementPanel({
  onOpenCve
}: {
  /** Та же перетаскиваемая карточка CVE, что на дашборде / в ФСТЭК. */
  onOpenCve?: (cveId: string) => void;
}) {
  const [vendor, setVendor] = useState<string>("");
  const [q, setQ] = useState("");
  const [qDebounced, setQDebounced] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 20;
  const [detailId, setDetailId] = useState<string | null>(null);

  useEffect(() => {
    const t = window.setTimeout(() => setQDebounced(q.trim()), 350);
    return () => window.clearTimeout(t);
  }, [q]);

  useEffect(() => {
    setPage(1);
  }, [vendor, qDebounced]);

  const vendorsQuery = useQuery({
    queryKey: ["vendor-advisories", "vendors"],
    queryFn: async () => {
      const res = await apiFetch(`/api/vendor-advisories/vendors`, { cache: "no-store" });
      if (!res.ok) throw new Error("vendors");
      return (await res.json()) as { items: string[] };
    },
    staleTime: 60_000
  });

  const listQuery = useQuery({
    queryKey: ["vendor-advisories", "list", pageSize, page, vendor, qDebounced],
    queryFn: async () => {
      const url = new URL(`/api/vendor-advisories`, window.location.origin);
      url.searchParams.set("limit", String(pageSize));
      url.searchParams.set("page", String(page));
      if (vendor) url.searchParams.set("vendor", vendor);
      if (qDebounced) url.searchParams.set("q", qDebounced);
      const res = await apiFetch(url.toString(), { cache: "no-store" });
      if (!res.ok) throw new Error("list");
      return (await res.json()) as {
        items: VendorAdvisoryItem[];
        total: number;
        page: number;
        pageSize: number;
        totalPages: number;
        recentDays?: number;
      };
    },
    staleTime: 15_000
  });

  const items = listQuery.data?.items ?? [];
  const total = listQuery.data?.total ?? 0;
  const totalPages = listQuery.data?.totalPages ?? 0;
  const currentPage = listQuery.data?.page ?? page;

  useEffect(() => {
    const p = listQuery.data?.page;
    if (p == null) return;
    setPage((cur) => (cur !== p ? p : cur));
  }, [listQuery.data?.page]);

  const pageNumbersToShow = useMemo(() => {
    const tp = totalPages;
    const cp = currentPage;
    if (tp <= 0) return [];
    if (tp <= 9) return Array.from({ length: tp }, (_, i) => i + 1);
    const set = new Set([1, 2, tp - 1, tp, cp, cp - 1, cp + 1]);
    return [...set].filter((x) => x >= 1 && x <= tp).sort((a, b) => a - b);
  }, [totalPages, currentPage]);

  const detailQuery = useQuery({
    queryKey: ["vendor-advisories", "detail", detailId],
    queryFn: async () => {
      const res = await apiFetch(`/api/vendor-advisories/${encodeURIComponent(detailId!)}`, { cache: "no-store" });
      if (res.status === 404) throw new Error("not_found");
      if (!res.ok) throw new Error("detail");
      return (await res.json()) as VendorAdvisoryDetail;
    },
    enabled: detailId != null,
    staleTime: 30_000
  });

  const detail = detailQuery.data;

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <div className="flex items-center gap-2 text-base font-semibold tracking-tight text-fg/95">
            <Bandage className="h-5 w-5 text-accent" />
            Патч‑менеджмент
          </div>
          <p className="mt-1 max-w-3xl text-[12px] leading-relaxed text-muted">
            Лента бюллетеней и обновлений безопасности из публичных RSS- и Atom-лент. Показываются записи за последние{" "}
            <span className="text-fg/80">7 суток</span> (по дате публикации или времени загрузки), с разбиением по страницам. CVE
            извлекаются из заголовка и текста. Список источников — переменная{" "}
            <code className="rounded bg-slate-100 px-1 font-mono text-[10px] dark:bg-black/40">PATCH_ADVISORY_SOURCES</code> в службе
            импорта. Тексты из внешних лент могут быть на языке оригинала.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void listQuery.refetch()}
          className="inline-flex shrink-0 items-center gap-2 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-fg/90 hover:bg-slate-100 dark:border-border dark:bg-black/20 dark:hover:bg-black/35"
        >
          {listQuery.isFetching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
          Обновить
        </button>
      </div>

      <div className="flex flex-col gap-3 rounded-2xl border border-slate-200/90 bg-slate-50/80 p-4 dark:border-white/[0.06] dark:bg-black/20 sm:flex-row sm:items-center">
        <div className="flex min-w-0 flex-1 items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 dark:border-border dark:bg-zinc-950/80">
          <Search className="h-4 w-4 shrink-0 text-muted" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Поиск: заголовок, текст, номер CVE…"
            className="min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-muted"
          />
        </div>
        <select
          value={vendor}
          onChange={(e) => setVendor(e.target.value)}
          className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-fg/90 dark:border-border dark:bg-black/30"
          title="Вендор"
        >
          <option value="">Все источники (вендоры)</option>
          {(vendorsQuery.data?.items ?? []).map((v) => (
            <option key={v} value={v}>
              {vendorLabelRu(v)}
            </option>
          ))}
        </select>
      </div>

      {listQuery.isError ? (
        <div className="rounded-xl border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">
          Не удалось загрузить ленту. Проверьте API и авторизацию.
        </div>
      ) : null}

      <div className="text-[11px] text-muted">
        За 7 суток в выборке: <span className="tabular-nums text-fg/85">{total}</span>
        {totalPages > 0 ? (
          <>
            {" "}
            · страница <span className="tabular-nums text-fg/85">{currentPage}</span> из{" "}
            <span className="tabular-nums text-fg/85">{totalPages}</span> (по {pageSize} записей)
          </>
        ) : null}
        {listQuery.isFetching ? <span className="ml-2">· загрузка…</span> : null}
      </div>

      <div className="space-y-3">
        {items.length === 0 && !listQuery.isLoading ? (
          <div className="rounded-2xl border border-dashed border-slate-200/90 bg-slate-50/50 px-6 py-12 text-center text-sm text-muted dark:border-white/[0.08] dark:bg-black/15">
            За последние 7 суток записей нет (с учётом фильтров). Укажите источники в службе импорта и дождитесь опроса лент либо
            смените фильтр.
          </div>
        ) : null}

        {listQuery.isLoading && items.length === 0 ? (
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
            className="cursor-pointer rounded-2xl border border-slate-200/90 bg-white/90 p-4 text-left shadow-sm outline-none transition-colors hover:border-accent/25 hover:bg-slate-50/90 focus-visible:ring-2 focus-visible:ring-accent/30 dark:border-white/[0.08] dark:bg-black/25 dark:hover:bg-black/35"
          >
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-full border border-accent/25 bg-accent/10 px-2 py-0.5 text-[10px] font-medium tracking-wide text-accent">
                    {vendorLabelRu(it.vendorSlug)}
                  </span>
                  {it.publishedAt ? (
                    <span className="text-[11px] text-muted">
                      {new Date(it.publishedAt).toLocaleString("ru-RU", {
                        day: "2-digit",
                        month: "2-digit",
                        year: "numeric",
                        hour: "2-digit",
                        minute: "2-digit"
                      })}
                    </span>
                  ) : (
                    <span className="text-[11px] text-muted">дата не указана в ленте</span>
                  )}
                </div>
                <h3 className="mt-2 text-sm font-semibold leading-snug text-fg/95">{it.title}</h3>
                {it.summary ? <p className="mt-2 line-clamp-4 text-[12px] leading-relaxed text-muted">{it.summary}</p> : null}
              </div>
              <a
                href={it.link}
                target="_blank"
                rel="noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-2 py-1.5 text-[11px] text-fg/90 hover:bg-slate-100 dark:border-border dark:bg-black/30 dark:hover:bg-black/45"
              >
                Источник
                <ExternalLink className="h-3 w-3" />
              </a>
            </div>

            {it.cveIds.length > 0 ? (
              <div className="mt-3 flex flex-wrap gap-1.5">
                {it.cveIds.map((id) => (
                  <button
                    key={id}
                    type="button"
                    title={onOpenCve ? "Открыть карточку CVE" : undefined}
                    onClick={(e) => {
                      e.stopPropagation();
                      onOpenCve?.(id);
                    }}
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
              </div>
            ) : null}

            <div className="mt-2 truncate text-[10px] text-muted" title={it.feedUrl}>
              Адрес ленты: {it.feedUrl}
            </div>
          </article>
        ))}
      </div>

      {total > 0 ? (
        <div className="flex flex-col items-center justify-between gap-3 rounded-2xl border border-slate-200/90 bg-slate-50/80 px-4 py-3 dark:border-white/[0.06] dark:bg-black/20 sm:flex-row">
          <div className="text-[11px] text-muted">
            Страница <span className="tabular-nums text-fg/85">{currentPage}</span> из{" "}
            <span className="tabular-nums text-fg/85">{totalPages}</span>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-1.5">
            <button
              type="button"
              disabled={currentPage <= 1 || listQuery.isFetching}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className={cn(
                "inline-flex items-center gap-1 rounded-xl border px-3 py-2 text-xs",
                currentPage <= 1 || listQuery.isFetching
                  ? "cursor-not-allowed border-slate-100 text-muted opacity-50 dark:border-white/[0.06]"
                  : "border-slate-200 bg-white text-fg/90 hover:bg-slate-100 dark:border-border dark:bg-black/30 dark:hover:bg-black/45"
              )}
            >
              <ChevronLeft className="h-3.5 w-3.5" />
              Назад
            </button>
            {pageNumbersToShow.map((p, idx) => {
              const prev = pageNumbersToShow[idx - 1];
              const showGap = prev !== undefined && p - prev > 1;
              return (
                <span key={p} className="inline-flex items-center gap-1.5">
                  {showGap ? <span className="px-1 text-[11px] text-muted">…</span> : null}
                  <button
                    type="button"
                    disabled={listQuery.isFetching}
                    onClick={() => setPage(p)}
                    className={cn(
                      "min-w-[2.25rem] rounded-lg border px-2 py-1.5 text-center text-xs tabular-nums",
                      p === currentPage
                        ? "border-accent/40 bg-accent/15 font-medium text-fg/95"
                        : "border-slate-200 bg-white text-fg/85 hover:bg-slate-100 dark:border-border dark:bg-black/25 dark:hover:bg-black/40"
                    )}
                  >
                    {p}
                  </button>
                </span>
              );
            })}
            <button
              type="button"
              disabled={currentPage >= totalPages || listQuery.isFetching}
              onClick={() => setPage((p) => p + 1)}
              className={cn(
                "inline-flex items-center gap-1 rounded-xl border px-3 py-2 text-xs",
                currentPage >= totalPages || listQuery.isFetching
                  ? "cursor-not-allowed border-slate-100 text-muted opacity-50 dark:border-white/[0.06]"
                  : "border-slate-200 bg-white text-fg/90 hover:bg-slate-100 dark:border-border dark:bg-black/30 dark:hover:bg-black/45"
              )}
            >
              Далее
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
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
              "fixed left-1/2 top-1/2 z-[101] max-h-[min(85vh,880px)] w-[min(640px,calc(100vw-24px))] -translate-x-1/2 -translate-y-1/2",
              "flex flex-col overflow-hidden rounded-2xl border border-border bg-white shadow-2xl outline-none dark:bg-zinc-950"
            )}
            onOpenAutoFocus={(e) => e.preventDefault()}
          >
            <div className="flex shrink-0 items-start justify-between gap-3 border-b border-slate-200 px-5 py-4 dark:border-white/[0.08]">
              <div className="min-w-0">
                <Dialog.Title className="text-sm font-semibold leading-snug text-fg/95">Запись ленты</Dialog.Title>
                <Dialog.Description className="sr-only">
                  Подробности бюллетеня: заголовок, текст, CVE и ссылка на оригинал.
                </Dialog.Description>
              </div>
              <Dialog.Close asChild>
                <button
                  type="button"
                  className="rounded-lg border border-slate-200 p-1.5 text-muted hover:bg-slate-100 hover:text-fg dark:border-border dark:hover:bg-black/40"
                  aria-label="Закрыть"
                >
                  <X className="h-4 w-4" />
                </button>
              </Dialog.Close>
            </div>

            <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
              {detailQuery.isLoading ? (
                <div className="flex items-center justify-center gap-2 py-16 text-sm text-muted">
                  <Loader2 className="h-6 w-6 animate-spin" />
                  Загрузка…
                </div>
              ) : detailQuery.isError ? (
                <div className="rounded-xl border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">
                  {detailQuery.error instanceof Error && detailQuery.error.message === "not_found"
                    ? "Запись не найдена."
                    : "Не удалось загрузить запись."}
                </div>
              ) : detail ? (
                <div className="space-y-4 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded-full border border-accent/25 bg-accent/10 px-2 py-0.5 text-[10px] font-medium tracking-wide text-accent">
                      {vendorLabelRu(detail.vendorSlug)}
                    </span>
                    {detail.publishedAt ? (
                      <span className="text-[11px] text-muted">
                        Опубликовано:{" "}
                        {new Date(detail.publishedAt).toLocaleString("ru-RU", {
                          day: "2-digit",
                          month: "2-digit",
                          year: "numeric",
                          hour: "2-digit",
                          minute: "2-digit"
                        })}
                      </span>
                    ) : (
                      <span className="text-[11px] text-muted">дата в ленте не указана</span>
                    )}
                  </div>

                  <h2 className="text-base font-semibold leading-snug text-fg/95">{detail.title}</h2>

                  {detail.summary ? (
                    <div>
                      <div className="text-[10px] font-medium uppercase tracking-wide text-muted">Краткое описание</div>
                      <p className="mt-1 whitespace-pre-wrap text-[13px] leading-relaxed text-fg/85">{detail.summary}</p>
                    </div>
                  ) : null}

                  {detail.rawItem?.description ? (
                    <div>
                      <div className="text-[10px] font-medium uppercase tracking-wide text-muted">Полный текст из ленты</div>
                      <div className="mt-1 max-h-[min(40vh,320px)] overflow-y-auto rounded-xl border border-slate-200/80 bg-slate-50/80 px-3 py-2 text-[13px] leading-relaxed text-fg/80 dark:border-white/[0.08] dark:bg-black/30">
                        {htmlToPlainText(detail.rawItem.description)}
                      </div>
                    </div>
                  ) : null}

                  {detail.cveIds.length > 0 ? (
                    <div>
                      <div className="text-[10px] font-medium uppercase tracking-wide text-muted">CVE</div>
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {detail.cveIds.map((id) => (
                          <button
                            key={id}
                            type="button"
                            onClick={() => {
                              onOpenCve?.(id);
                              setDetailId(null);
                            }}
                            className={cn(
                              "rounded-full border px-2 py-0.5 font-mono text-[11px] tabular-nums",
                              "border-slate-200/90 bg-slate-100 text-slate-900",
                              "dark:border-white/[0.12] dark:bg-zinc-900/85 dark:text-zinc-200",
                              onOpenCve &&
                                "cursor-pointer hover:border-accent/40 hover:bg-accent/10 dark:hover:bg-accent/15"
                            )}
                          >
                            {id}
                          </button>
                        ))}
                      </div>
                    </div>
                  ) : null}

                  <div className="space-y-1 border-t border-slate-200/80 pt-3 text-[11px] text-muted dark:border-white/[0.08]">
                    <div className="break-all">
                      <span className="text-fg/70">Лента:</span> {detail.feedUrl}
                    </div>
                    <div className="break-all">
                      <span className="text-fg/70">Загружено:</span>{" "}
                      {new Date(detail.fetchedAt).toLocaleString("ru-RU", {
                        day: "2-digit",
                        month: "2-digit",
                        year: "numeric",
                        hour: "2-digit",
                        minute: "2-digit"
                      })}
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-2 pt-1">
                    <a
                      href={detail.link}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1.5 rounded-xl border border-accent/35 bg-accent/10 px-4 py-2 text-xs font-medium text-accent hover:bg-accent/15"
                    >
                      Открыть оригинал на сайте
                      <ExternalLink className="h-3.5 w-3.5" />
                    </a>
                    <Dialog.Close asChild>
                      <button
                        type="button"
                        className="rounded-xl border border-slate-200 bg-white px-4 py-2 text-xs text-fg/90 hover:bg-slate-50 dark:border-border dark:bg-black/25 dark:hover:bg-black/40"
                      >
                        Закрыть
                      </button>
                    </Dialog.Close>
                  </div>
                </div>
              ) : null}
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}

"use client";

import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import { LiveNumber } from "../ui/live-number";
import { useLiveQueryOptions } from "@/lib/live-refresh";
import {
  Activity,
  AlertCircle,
  ChevronRight,
  Inbox,
  Loader2,
  Radio,
  RefreshCw,
  ShieldAlert,
  X,
  Bookmark,
  Briefcase,
  Clock
} from "lucide-react";
import { cn } from "../ui/cn";
import { apiFetch } from "@/lib/api-fetch";
import {
  fetchVocQueue,
  fetchVocTriageBySource,
  type VocQueueItem,
  type VocSource,
  type VocTriageStatus
} from "@/lib/voc-api";
import { useVocQueueTriage } from "@/lib/use-voc-queue-triage";
import {
  buildTgCriticalRows,
  isWithinLast24h,
  type TgCveIntel,
  type TgFeedResponse
} from "@/lib/tg-feed-critical";
import { scoreTgForVoc } from "@/lib/voc-scoring-client";
import { vocPriorityLabel, vocStatusLabel } from "@/lib/voc-labels";
import { fetchVocWatchlist } from "@/lib/voc-watchlist-api";
import { applyWatchlistBoostClient, hasWatchlistHit } from "@/lib/voc-watchlist-client";
import { VocQueueRow } from "./voc-queue-row";
import { VocWatchlistPanel } from "./voc-watchlist-panel";
import { VocWatchlistQuickAdd } from "./voc-watchlist-quick-add";
import { VocCasesPanel } from "./voc-cases-panel";
import { VocShiftPanel } from "./voc-shift-panel";
import { VocVerificationPanel } from "./voc-verification-panel";
import {
  buildCaseRefMap,
  createVocCaseFromRef,
  fetchVocCases
} from "@/lib/voc-case-api";
import { isSlaBreached, slaRemainingLabel, slaTone } from "@/lib/voc-case-client";

type SourceTab = "all" | VocSource | "watchlist";
type StatusTab = "active" | "open" | "claimed" | "done" | "all";
type SectionTab = "queue" | "cases" | "watchlist" | "shift";

function fmtWhen(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("ru-RU", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
}

export function VocHomePanel({
  onOpenCve,
  onOpenBdu,
  onOpenTgLink,
  variant = "card"
}: {
  onOpenCve?: (cveId: string) => void;
  onOpenBdu?: (bduId: string) => void;
  onOpenTgLink?: (link: string) => void;
  /** `page` — отдельный модуль с вкладками; `card` — компактный блок (legacy). */
  variant?: "card" | "page";
}) {
  const isPage = variant === "page";
  const { userEmail, mergeItems, setStatus, pendingKey, error, clearError } = useVocQueueTriage();
  const [section, setSection] = useState<SectionTab>("queue");
  const [sourceTab, setSourceTab] = useState<SourceTab>("all");
  const [statusTab, setStatusTab] = useState<StatusTab>("active");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [kbdIndex, setKbdIndex] = useState(0);
  const [caseError, setCaseError] = useState<string | null>(null);
  const [casePending, setCasePending] = useState(false);

  const liveOpts = useLiveQueryOptions();
  const tgLiveOpts = useLiveQueryOptions(60_000);
  const queryClient = useQueryClient();

  const queueQuery = useQuery({
    queryKey: ["voc", "queue", sourceTab === "tg" ? "all" : sourceTab, statusTab],
    queryFn: () =>
      fetchVocQueue({
        source: sourceTab === "tg" ? "all" : sourceTab,
        status: statusTab,
        limit: 160
      }),
    ...liveOpts
  });

  const tgFeedQuery = useQuery({
    queryKey: ["patch", "telegram", "feed", "voc"],
    queryFn: async () => {
      const res = await apiFetch("/api/patch/feed", { cache: "no-store" });
      const body = (await res.json()) as TgFeedResponse & { error?: string };
      if (!res.ok) throw new Error(body.error ?? "TG feed");
      return body;
    },
    ...tgLiveOpts
  });

  const watchlistQuery = useQuery({
    queryKey: ["voc", "watchlist"],
    queryFn: fetchVocWatchlist,
    ...liveOpts
  });

  const casesQuery = useQuery({
    queryKey: ["voc", "cases", "active"],
    queryFn: () => fetchVocCases({ status: "active", limit: 80 }),
    ...liveOpts
  });

  const caseRefMap = useMemo(() => buildCaseRefMap(casesQuery.data ?? []), [casesQuery.data]);

  const tgTriageQuery = useQuery({
    queryKey: ["voc", "triage", "tg"],
    queryFn: () => fetchVocTriageBySource("tg", 240),
    enabled: sourceTab === "all" || sourceTab === "tg" || sourceTab === "watchlist",
    ...tgLiveOpts
  });

  const tgTriageMap = useMemo(() => {
    const map = new Map<string, { status: VocTriageStatus; claimedByEmail: string | null; updatedAt: string | null }>();
    for (const row of tgTriageQuery.data ?? []) {
      map.set(row.refKey, row);
    }
    return map;
  }, [tgTriageQuery.data]);

  const tgRecentItems = useMemo(
    () => (tgFeedQuery.data?.items ?? []).filter((it) => isWithinLast24h(it.pubDate)),
    [tgFeedQuery.data?.items]
  );

  const tgItems = useMemo((): VocQueueItem[] => {
    const intelByCve = new Map<string, TgCveIntel>();
    const apiItems = queueQuery.data?.items ?? [];
    for (const row of apiItems) {
      if (row.source !== "cve") continue;
      intelByCve.set(row.refId.toUpperCase(), {
        cve_id: row.refId,
        risk_score: (row.payload.risk_score as number | null) ?? null,
        epss: (row.payload.epss as number | null) ?? null,
        cvss_base: (row.payload.cvss_base as number | null) ?? null,
        exploit_known: Boolean(row.payload.exploit_known),
        vp_vendor: (row.payload.vp_vendor as string | null) ?? null,
        vp_product: (row.payload.vp_product as string | null) ?? null
      });
    }

    const watchlist = watchlistQuery.data ?? [];
    const rows = buildTgCriticalRows(tgRecentItems, intelByCve, { minScore: 24 });
    return rows.map((row) => {
      const scored = scoreTgForVoc({
        score: row.score,
        reasons: row.reasons,
        cveCount: row.item.cveIds?.length ?? 0,
        hasHotCve: row.criticalCveIds.length > 0
      });
      const hotIntel = row.cveIntel[0];
      const boosted = applyWatchlistBoostClient(
        scored,
        {
          vendor: hotIntel?.vp_vendor,
          product: hotIntel?.vp_product,
          text: `${row.item.title} ${row.item.descriptionText ?? ""} ${(row.item.cveIds ?? []).join(" ")}`
        },
        watchlist
      );
      const title = row.item.title?.trim() || `@${row.item.channel.slug}`;
      const refKey = `TG:${row.item.id}`;
      const triage = tgTriageMap.get(refKey);
      return {
        refKey,
        source: "tg" as const,
        refId: row.item.id,
        vocScore: boosted.score,
        vocPriority: boosted.priority,
        vocReasons: boosted.reasons,
        title,
        subtitle: (row.item.descriptionText || "").slice(0, 220),
        publishedAt: row.item.pubDate,
        status: triage?.status ?? "open",
        claimedByEmail: triage?.claimedByEmail ?? null,
        updatedAt: triage?.updatedAt ?? null,
        payload: {
          link: row.item.link,
          channel: row.item.channel,
          cveIds: row.item.cveIds,
          criticalCveIds: row.criticalCveIds
        }
      };
    });
  }, [tgRecentItems, queueQuery.data?.items, tgTriageMap, watchlistQuery.data]);

  const items = useMemo(() => {
    const base = queueQuery.data?.items ?? [];
    let merged =
      sourceTab === "watchlist"
        ? [...base, ...tgItems.filter((i) => hasWatchlistHit(i))]
        : sourceTab === "tg"
          ? tgItems
          : sourceTab === "all"
            ? [...base, ...tgItems]
            : base;
    merged = [...merged].sort((a, b) => {
      if (b.vocScore !== a.vocScore) return b.vocScore - a.vocScore;
      return String(b.publishedAt ?? "").localeCompare(String(a.publishedAt ?? ""));
    });
    if (statusTab === "active") {
      merged = merged.filter((i) => i.status === "open" || i.status === "claimed");
    } else if (statusTab === "open") {
      merged = merged.filter((i) => i.status === "open");
    } else if (statusTab === "claimed") {
      merged = merged.filter((i) => i.status === "claimed");
    } else if (statusTab === "done") {
      merged = merged.filter((i) => i.status === "done" || i.status === "dismissed");
    }
    return mergeItems(merged).map((item) => {
      if (item.caseId) {
        return {
          ...item,
          slaBreached: item.slaBreached ?? isSlaBreached(item.slaDueAt)
        };
      }
      const hit = caseRefMap.get(item.refKey);
      if (!hit) return item;
      return {
        ...item,
        caseId: hit.caseId,
        caseStatus: hit.caseStatus,
        assigneeEmail: hit.assigneeEmail,
        slaDueAt: hit.slaDueAt,
        slaBreached: isSlaBreached(hit.slaDueAt),
        linkedRefsCount: hit.linkedRefsCount,
        taskId: hit.taskId
      };
    });
  }, [queueQuery.data?.items, tgItems, sourceTab, statusTab, mergeItems, caseRefMap]);

  const stats = useMemo(() => {
    const s = queueQuery.data?.stats ?? {};
    return {
      total: items.length,
      open: items.filter((i) => i.status === "open").length,
      claimed: items.filter((i) => i.status === "claimed").length,
      p1: items.filter((i) => i.vocPriority === "p1").length,
      tg: tgRecentItems.length,
      watchlist: items.filter((i) => hasWatchlistHit(i)).length,
      cases: casesQuery.data?.length ?? items.filter((i) => i.caseId).length,
      apiTotal: s.total ?? 0,
      watchlistRules: (watchlistQuery.data ?? []).filter((r) => r.active).length
    };
  }, [items, queueQuery.data?.stats, tgRecentItems.length, watchlistQuery.data, casesQuery.data?.length]);

  async function handleCreateCase(item: VocQueueItem) {
    setCaseError(null);
    setCasePending(true);
    try {
      const linkedCveIds =
        item.source === "cve"
          ? [item.refId]
          : Array.isArray(item.payload.cveIds)
            ? item.payload.cveIds.map(String)
            : Array.isArray(item.payload.criticalCveIds)
              ? item.payload.criticalCveIds.map(String)
              : [];
      const vendorDisplay =
        typeof item.payload.vp_vendor === "string" ? item.payload.vp_vendor : undefined;
      const productDisplay =
        typeof item.payload.vp_product === "string" ? item.payload.vp_product : undefined;
      const created = await createVocCaseFromRef({
        refKey: item.refKey,
        source: item.source,
        refId: item.refId,
        title: item.title,
        subtitle: item.subtitle,
        vocPriority: item.vocPriority,
        vocReasons: item.vocReasons,
        linkedCveIds,
        assigneeEmail: userEmail,
        createTask: true,
        vendorKey: vendorDisplay?.toLowerCase(),
        vendorDisplay,
        productDisplay,
        productKeyNorm: productDisplay?.toLowerCase(),
        tgChannel:
          item.source === "tg" && item.payload.channel && typeof item.payload.channel === "object"
            ? String((item.payload.channel as { slug?: string }).slug ?? "")
            : undefined
      });
      if (!created.taskId && !created.case?.taskId) {
        setCaseError("Кейс есть, задача не создалась — нажмите «Создать задачу» или «Догнать задачи»");
      }
      if (item.status === "open") {
        await setStatus(item, "claimed");
      }
      void casesQuery.refetch();
      void queueQuery.refetch();
      void queryClient.invalidateQueries({ queryKey: ["vuln-tasks"] });
    } catch (e) {
      setCaseError(e instanceof Error ? e.message : "Не удалось создать кейс");
    } finally {
      setCasePending(false);
    }
  }

  const selected = useMemo(
    () => items.find((i) => i.refKey === selectedKey) ?? items[kbdIndex] ?? null,
    [items, selectedKey, kbdIndex]
  );

  useEffect(() => {
    if (!items.length) {
      setKbdIndex(0);
      setSelectedKey(null);
      return;
    }
    if (kbdIndex >= items.length) setKbdIndex(0);
    const row = items[kbdIndex];
    if (row && selectedKey !== row.refKey) setSelectedKey(row.refKey);
  }, [items, kbdIndex, selectedKey]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      if (!items.length) return;
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setKbdIndex((i) => Math.min(items.length - 1, i + 1));
      }
      if (e.key === "ArrowUp") {
        e.preventDefault();
        setKbdIndex((i) => Math.max(0, i - 1));
      }
      if (e.key === "Enter" && selected) {
        if (selected.source === "cve") onOpenCve?.(selected.refId);
        else if (selected.source === "bdu") onOpenBdu?.(selected.refId);
        else if (selected.source === "tg") {
          const link = selected.payload.link;
          if (typeof link === "string") onOpenTgLink?.(link);
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [items.length, selected, onOpenCve, onOpenBdu, onOpenTgLink]);

  const loading =
    queueQuery.isLoading ||
    (sourceTab === "tg" && (tgFeedQuery.isLoading || tgTriageQuery.isLoading));
  const refreshing = queueQuery.isFetching || tgFeedQuery.isFetching || tgTriageQuery.isFetching;
  const tgFeedErrorMessage =
    tgFeedQuery.error instanceof Error
      ? tgFeedQuery.error.message
      : tgFeedQuery.error
        ? "Не удалось загрузить TG-ленту"
        : null;
  const tgStatLoading = tgFeedQuery.isLoading && !tgFeedQuery.data;
  const statCards = [
    { label: "В ленте", value: stats.total, icon: Activity },
    { label: "P1", value: stats.p1, icon: ShieldAlert },
    { label: "В очереди", value: stats.open, icon: CircleIcon },
    { label: "В работе", value: stats.claimed, icon: UserIcon },
    { label: "Кейсы", value: stats.cases, icon: Briefcase },
    { label: "Watchlist", value: stats.watchlist, icon: Bookmark },
    {
      label: "TG 24ч",
      value: stats.tg,
      icon: Radio,
      loading: tgStatLoading,
      error: tgFeedErrorMessage
    }
  ];

  return (
    <section
      className={cn(
        isPage
          ? "space-y-5"
          : "rounded-2xl border border-indigo-200/70 bg-gradient-to-br from-indigo-50/60 via-white to-slate-50/80 p-5 ring-1 ring-indigo-200/40 dark:border-indigo-900/40 dark:from-indigo-950/30 dark:via-black/20 dark:to-black/30 dark:ring-indigo-800/30"
      )}
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <div className="flex items-center gap-2 text-base font-semibold tracking-tight text-fg/95">
            <Inbox className="h-4 w-4 text-indigo-500" />
            VOC — очередь смены
          </div>
          <p className="mt-1 max-w-3xl text-[12px] leading-relaxed text-muted">
            {isPage
              ? "Операционная лента смены: NVD, БДУ и Telegram. Ранжирование — платформа, верификация — вы. ↑↓ навигация, Enter — открыть."
              : "Единая операционная лента: NVD, БДУ ФСТЭК и Telegram. Платформа ранжирует сигналы — вы верифицируете на инфре. ↑↓ навигация, Enter — открыть карточку."}
          </p>
        </div>
        <button
          type="button"
          onClick={() => {
            void queueQuery.refetch();
            void tgFeedQuery.refetch();
            void tgTriageQuery.refetch();
            void watchlistQuery.refetch();
            void casesQuery.refetch();
          }}
          disabled={refreshing}
          className={cn(
            "inline-flex shrink-0 items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 py-2 text-[11px]",
            "hover:bg-slate-50 dark:border-white/10 dark:bg-black/30 dark:hover:bg-black/45",
            refreshing && "opacity-80"
          )}
        >
          {refreshing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
          Обновить
        </button>
      </div>

      {(!isPage || section === "queue") ? (
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-7">
        {statCards.map((c, i) => (
          <motion.div
            key={c.label}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.03 * i }}
            className="rounded-xl border border-slate-200/90 bg-white/80 px-3 py-2 dark:border-white/10 dark:bg-black/25"
          >
            <div className="flex items-center gap-1.5 text-[10px] text-muted">
              <c.icon className="h-3 w-3" />
              {c.label}
            </div>
            <div className="mt-0.5 text-xl font-semibold">
              {c.error ? (
                <span className="text-sm font-semibold text-danger">Ошибка</span>
              ) : c.loading ? (
                <span className="inline-block animate-pulse tabular-nums text-muted">…</span>
              ) : (
                <LiveNumber value={c.value} />
              )}
            </div>
          </motion.div>
        ))}
      </div>
      ) : null}

      {isPage ? (
        <div className="flex flex-wrap gap-2 border-b border-slate-200/80 pb-3 dark:border-white/10">
          {(
            [
              ["queue", "Очередь", Activity],
              ["cases", "Кейсы", Briefcase],
              ["watchlist", "Watchlist", Bookmark],
              ["shift", "Смена / KPI", Clock]
            ] as const
          ).map(([key, label, Icon]) => (
            <button
              key={key}
              type="button"
              onClick={() => setSection(key)}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-xl border px-3.5 py-2 text-[12px] font-medium transition",
                section === key
                  ? "border-indigo-400/45 bg-indigo-500/15 text-fg/95"
                  : "border-slate-200 bg-white text-muted hover:text-fg/85 dark:border-white/10 dark:bg-black/25"
              )}
            >
              <Icon className="h-3.5 w-3.5" />
              {label}
            </button>
          ))}
        </div>
      ) : (
        <>
          <VocWatchlistPanel className="mt-4" />
          <VocShiftPanel className="mt-4" />
          <VocCasesPanel
            className="mt-4"
            currentUserEmail={userEmail}
            onSelectRefKey={(refKey) => {
              const idx = items.findIndex((i) => i.refKey === refKey);
              if (idx >= 0) {
                setKbdIndex(idx);
                setSelectedKey(refKey);
              }
            }}
          />
        </>
      )}

      {isPage && section === "watchlist" ? <VocWatchlistPanel className="mt-1" /> : null}
      {isPage && section === "shift" ? <VocShiftPanel className="mt-1" /> : null}
      {isPage && section === "cases" ? (
        <VocCasesPanel
          className="mt-1"
          currentUserEmail={userEmail}
          onSelectRefKey={(refKey) => {
            setSection("queue");
            const idx = items.findIndex((i) => i.refKey === refKey);
            if (idx >= 0) {
              setKbdIndex(idx);
              setSelectedKey(refKey);
            }
          }}
        />
      ) : null}

      {(!isPage || section === "queue") && (
        <>
      {caseError ? (
        <div className="mt-4 flex items-start gap-2 rounded-xl border border-danger/35 bg-danger/10 px-3 py-2 text-[12px] text-danger">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <div className="min-w-0 flex-1">{caseError}</div>
          <button type="button" onClick={() => setCaseError(null)} className="shrink-0 rounded p-0.5 hover:bg-danger/10">
            <X className="h-4 w-4" />
          </button>
        </div>
      ) : null}

      {error ? (
        <div className="mt-4 flex items-start gap-2 rounded-xl border border-danger/35 bg-danger/10 px-3 py-2 text-[12px] text-danger">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <div className="min-w-0 flex-1">{error}</div>
          <button type="button" onClick={clearError} className="shrink-0 rounded p-0.5 hover:bg-danger/10">
            <X className="h-4 w-4" />
          </button>
        </div>
      ) : null}

      {tgFeedErrorMessage ? (
        <div className="mt-4 flex items-start gap-2 rounded-xl border border-danger/35 bg-danger/10 px-3 py-2 text-[12px] text-danger">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <div className="min-w-0 flex-1">Не удалось загрузить TG-ленту: {tgFeedErrorMessage}</div>
        </div>
      ) : null}

      <div className="mt-4 flex flex-wrap gap-2">
        {(
          [
            ["all", "Все"],
            ["watchlist", "Watchlist"],
            ["cve", "CVE"],
            ["bdu", "БДУ"],
            ["tg", "Telegram"]
          ] as const
        ).map(([key, label]) => (
          <button
            key={key}
            type="button"
            onClick={() => setSourceTab(key)}
            className={cn(
              "rounded-full border px-3 py-1 text-[11px] font-medium transition",
              sourceTab === key
                ? "border-indigo-400/40 bg-indigo-500/15 text-fg/95"
                : "border-slate-200 bg-white text-muted hover:text-fg/80 dark:border-white/10 dark:bg-black/30"
            )}
          >
            {label}
          </button>
        ))}
        <span className="mx-1 hidden h-6 w-px bg-slate-200 sm:inline dark:bg-white/10" />
        {(
          [
            ["active", "Активные"],
            ["open", "В очереди"],
            ["claimed", "В работе"],
            ["done", "Готово"],
            ["all", "Все"]
          ] as const
        ).map(([key, label]) => (
          <button
            key={key}
            type="button"
            onClick={() => setStatusTab(key)}
            className={cn(
              "rounded-full border px-3 py-1 text-[11px] transition",
              statusTab === key
                ? "border-accent/35 bg-accent/10 text-fg/90"
                : "border-slate-200 bg-white text-muted dark:border-white/10 dark:bg-black/30"
            )}
          >
            {label}
          </button>
        ))}
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(320px,0.85fr)]">
        <div
          className={cn(
            "space-y-2 overflow-y-auto overscroll-contain pr-1 [scrollbar-width:thin]",
            isPage ? "max-h-[min(44rem,calc(100vh-16rem))]" : "max-h-[min(36rem,calc(100vh-14rem))]"
          )}
        >
          {loading ? (
            <div className="space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="h-24 animate-pulse rounded-2xl bg-slate-200/60 dark:bg-white/[0.06]" />
              ))}
            </div>
          ) : items.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-slate-300 px-4 py-10 text-center text-sm text-muted dark:border-white/10">
              {sourceTab === "watchlist" && stats.watchlistRules === 0
                ? "Добавьте правила в watchlist смены выше — здесь появятся совпадения за 7 дней."
                : "Нет событий по выбранным фильтрам. Попробуйте «Все» или другой источник."}
            </div>
          ) : (
            <AnimatePresence initial={false} mode="popLayout">
              {items.map((item, idx) => (
                <motion.div
                  key={item.refKey}
                  layout
                  initial={{ opacity: 0, y: -8, scale: 0.98 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.96 }}
                  transition={{ type: "spring", stiffness: 380, damping: 32, mass: 0.8 }}
                  data-voc-key={item.refKey}
                >
                  <VocQueueRow
                    item={item}
                    active={selected?.refKey === item.refKey}
                    currentUserEmail={userEmail}
                    pending={pendingKey === item.refKey}
                    onSelect={() => {
                      setSelectedKey(item.refKey);
                      setKbdIndex(idx);
                    }}
                    onClaim={() => setStatus(item, "claimed")}
                    onRelease={() => setStatus(item, "open")}
                    onDone={() => setStatus(item, "done")}
                    onReopen={() => setStatus(item, "open")}
                  />
                </motion.div>
              ))}
            </AnimatePresence>
          )}
        </div>

        <div className="rounded-2xl border border-slate-200/90 bg-white/90 p-4 dark:border-white/10 dark:bg-black/30">
          {selected ? (
            <div className="space-y-3">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="text-[11px] font-medium uppercase tracking-wider text-muted">Превью</div>
                  <div className="mt-1 font-mono text-lg font-semibold tracking-tight">{selected.title}</div>
                  <div className="mt-1 text-[11px] text-muted">{fmtWhen(selected.publishedAt)}</div>
                </div>
                <span className="rounded-lg border border-indigo-400/30 bg-indigo-500/10 px-2 py-1 font-mono text-xs font-bold">
                  {vocPriorityLabel(selected.vocPriority)} · {selected.vocScore}
                </span>
              </div>
              <p className="text-[12px] leading-relaxed text-fg/85">{selected.subtitle || "—"}</p>
              <div className="flex flex-wrap gap-1.5">
                {selected.vocReasons.map((r) => (
                  <span
                    key={r}
                    className="rounded-full border border-accent/25 bg-accent/10 px-2 py-0.5 text-[10px] text-fg/85"
                  >
                    {r}
                  </span>
                ))}
              </div>
              <div className="flex flex-wrap items-center gap-2 pt-1">
                <span className="rounded-full border border-slate-200 px-2 py-0.5 text-[10px] dark:border-white/10">
                  {vocStatusLabel(selected.status)}
                </span>
                {selected.claimedByEmail ? (
                  <span className="text-[10px] text-muted">· triage: {selected.claimedByEmail}</span>
                ) : null}
                {selected.caseId ? (
                  <span
                    className={cn(
                      "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px]",
                      slaTone(selected.slaDueAt, selected.slaBreached)
                    )}
                  >
                    <Clock className="h-3 w-3" />
                    SLA {slaRemainingLabel(selected.slaDueAt)}
                    {(selected.linkedRefsCount ?? 0) > 1 ? ` · ${selected.linkedRefsCount} сигн.` : ""}
                  </span>
                ) : null}
                {selected.assigneeEmail ? (
                  <span className="text-[10px] text-muted">· {selected.assigneeEmail}</span>
                ) : null}
                {typeof selected.payload.vp_vendor === "string" && selected.payload.vp_vendor ? (
                  <VocWatchlistQuickAdd kind="vendor" value={selected.payload.vp_vendor} compact />
                ) : null}
                {typeof selected.payload.vp_product === "string" && selected.payload.vp_product ? (
                  <VocWatchlistQuickAdd
                    kind="product"
                    value={String(selected.payload.vp_product)}
                    compact
                  />
                ) : null}
              </div>
              <div className="flex flex-wrap gap-2 border-t border-slate-200/80 pt-3 dark:border-white/10">
                {!selected.caseId ? (
                  <button
                    type="button"
                    disabled={casePending}
                    onClick={() => void handleCreateCase(selected)}
                    className="inline-flex items-center gap-1 rounded-xl border border-violet-400/40 bg-violet-500/15 px-3 py-2 text-[11px] font-medium"
                  >
                    {casePending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Briefcase className="h-3.5 w-3.5" />}
                    Создать кейс
                  </button>
                ) : (
                  <span className="rounded-xl border border-violet-400/30 bg-violet-500/10 px-3 py-2 text-[11px] text-violet-800 dark:text-violet-200">
                    Кейс #{selected.caseId.slice(0, 8)}
                    {selected.taskId ? ` · задача ${selected.taskId.slice(0, 8)}` : " · без задачи"}
                  </span>
                )}
                {selected.caseId && !selected.taskId ? (
                  <button
                    type="button"
                    disabled={casePending}
                    onClick={() => void handleCreateCase(selected)}
                    className="inline-flex items-center gap-1 rounded-xl border border-amber-400/40 bg-amber-500/15 px-3 py-2 text-[11px] font-medium"
                  >
                    {casePending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Briefcase className="h-3.5 w-3.5" />}
                    Создать задачу
                  </button>
                ) : null}
                {selected.caseId ? (
                  <VocVerificationPanel
                    caseId={selected.caseId}
                    onResolved={() => {
                      void setStatus(selected, "done");
                      void casesQuery.refetch();
                      void queueQuery.refetch();
                    }}
                  />
                ) : null}
                {selected.status === "open" ? (
                  <button
                    type="button"
                    disabled={casePending || pendingKey === selected.refKey}
                    onClick={() => {
                      if (!selected.caseId) void handleCreateCase(selected);
                      else void setStatus(selected, "claimed");
                    }}
                    className="rounded-xl border border-indigo-400/40 bg-indigo-500/15 px-3 py-2 text-[11px] font-medium"
                  >
                    {selected.caseId ? "Взять в работу" : "В работу + кейс/задача"}
                  </button>
                ) : null}
                {selected.status === "claimed" &&
                selected.claimedByEmail?.toLowerCase() === userEmail?.toLowerCase() ? (
                  <button
                    type="button"
                    disabled={pendingKey === selected.refKey}
                    onClick={() => setStatus(selected, "open")}
                    className="rounded-xl border border-slate-200 px-3 py-2 text-[11px] dark:border-white/10"
                  >
                    Отпустить
                  </button>
                ) : null}
                {selected.status !== "done" && selected.status !== "dismissed" ? (
                  <button
                    type="button"
                    disabled={pendingKey === selected.refKey}
                    onClick={() => setStatus(selected, "done")}
                    className="rounded-xl border border-ok/35 bg-ok/10 px-3 py-2 text-[11px] text-ok"
                  >
                    Готово
                  </button>
                ) : (
                  <button
                    type="button"
                    disabled={pendingKey === selected.refKey}
                    onClick={() => setStatus(selected, "open")}
                    className="rounded-xl border border-slate-200 px-3 py-2 text-[11px] dark:border-white/10"
                  >
                    Вернуть в очередь
                  </button>
                )}
              </div>
              <div className="flex flex-wrap gap-2 pt-1">
                {selected.source === "cve" ? (
                  <button
                    type="button"
                    onClick={() => onOpenCve?.(selected.refId)}
                    className="inline-flex items-center gap-1 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-[11px] hover:bg-slate-100 dark:border-white/10 dark:bg-black/20"
                  >
                    Открыть CVE <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                ) : null}
                {selected.source === "bdu" ? (
                  <button
                    type="button"
                    onClick={() => onOpenBdu?.(selected.refId)}
                    className="inline-flex items-center gap-1 rounded-xl border border-teal-400/30 bg-teal-500/10 px-3 py-2 text-[11px] hover:bg-teal-500/15"
                  >
                    Открыть БДУ <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                ) : null}
                {selected.source === "tg" && typeof selected.payload.link === "string" ? (
                  <button
                    type="button"
                    onClick={() => onOpenTgLink?.(String(selected.payload.link))}
                    className="inline-flex items-center gap-1 rounded-xl border border-sky-400/30 bg-sky-500/10 px-3 py-2 text-[11px]"
                  >
                    Открыть в Telegram <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                ) : null}
              </div>
            </div>
          ) : (
            <div className="flex h-full min-h-[12rem] items-center justify-center text-sm text-muted">
              Выберите событие в очереди
            </div>
          )}
        </div>
      </div>
        </>
      )}
    </section>
  );
}

function CircleIcon(props: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={props.className} aria-hidden>
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2" />
    </svg>
  );
}

function UserIcon(props: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={props.className} aria-hidden>
      <circle cx="12" cy="8" r="3" stroke="currentColor" strokeWidth="2" />
      <path d="M5 20c1.5-3 4-4.5 7-4.5s5.5 1.5 7 4.5" stroke="currentColor" strokeWidth="2" />
    </svg>
  );
}

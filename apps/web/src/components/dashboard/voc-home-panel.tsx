"use client";

import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import { LiveNumber } from "../ui/live-number";
import { useLiveQueryOptions } from "@/lib/live-refresh";
import {
  Activity,
  AlertCircle,
  Bookmark,
  Briefcase,
  ChevronRight,
  Clock,
  Inbox,
  Keyboard,
  Loader2,
  RefreshCw,
  ShieldAlert,
  UserRound,
  X
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
import { vocPriorityLabel, vocPriorityMeta, vocStatusLabel } from "@/lib/voc-labels";
import { vocChipClass, vocIntelContext } from "@/lib/voc-queue-context";
import { fetchVocWatchlist } from "@/lib/voc-watchlist-api";
import { applyWatchlistBoostClient, hasWatchlistHit } from "@/lib/voc-watchlist-client";
import { VocQueueRow } from "./voc-queue-row";
import { VocWatchlistPanel } from "./voc-watchlist-panel";
import { VocWatchlistQuickAdd } from "./voc-watchlist-quick-add";
import { VocCasesPanel, type VocCaseFilter } from "./voc-cases-panel";
import { VocShiftPanel } from "./voc-shift-panel";
import {
  buildCaseRefMap,
  createVocCaseFromRef,
  fetchVocCases,
  type VocCaseRow
} from "@/lib/voc-case-api";
import { caseIssueKey, isSlaBreached, slaRemainingLabel, slaTone } from "@/lib/voc-case-client";

type SourceTab = "all" | VocSource | "watchlist";
type StatusTab = "active" | "open" | "claimed" | "done" | "all";
type SectionTab = "queue" | "cases" | "watchlist" | "shift";
type WorkLens = "now" | "mine" | "all";

function fmtWhen(raw: string | null | undefined): string {
  if (!raw) return "—";
  const s = raw.trim();
  const bdu = /^(\d{2})\.(\d{2})\.(\d{4})$/.exec(s);
  if (bdu) {
    const d = new Date(Date.UTC(Number(bdu[3]), Number(bdu[2]) - 1, Number(bdu[1])));
    if (Number.isNaN(d.getTime())) return s;
    return d.toLocaleDateString("ru-RU", {
      day: "numeric",
      month: "long",
      year: "numeric",
      timeZone: "UTC"
    });
  }
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s;
  return d.toLocaleString("ru-RU", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
}

function isMineItem(item: VocQueueItem, email?: string | null) {
  if (!email) return false;
  const e = email.toLowerCase();
  return item.claimedByEmail?.toLowerCase() === e || item.assigneeEmail?.toLowerCase() === e;
}

function isNowItem(item: VocQueueItem) {
  if (item.status === "done" || item.status === "dismissed") return false;
  if (item.vocPriority === "p1" || Boolean(item.slaBreached) || hasWatchlistHit(item)) return true;
  // ФСТЭК БДУ высокого/критичного контура — обязательный приоритет смены для банка
  return item.source === "bdu" && item.vocPriority === "p2";
}

function urgencyScore(item: VocQueueItem) {
  let n = item.vocScore;
  if (item.slaBreached) n += 1000;
  if (item.vocPriority === "p1") n += 400;
  if (item.vocPriority === "p2") n += 120;
  if (hasWatchlistHit(item)) n += 180;
  if (item.status === "open") n += 20;
  return n;
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
  const [workLens, setWorkLens] = useState<WorkLens>("all");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [kbdIndex, setKbdIndex] = useState(0);
  const [caseError, setCaseError] = useState<string | null>(null);
  const [casePending, setCasePending] = useState(false);
  const [openCaseId, setOpenCaseId] = useState<string | null>(null);
  const [caseFilter, setCaseFilter] = useState<VocCaseFilter>("all");

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

  const queueItems = useMemo(() => {
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
      const urg = urgencyScore(b) - urgencyScore(a);
      if (urg !== 0) return urg;
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

  const items = useMemo(() => {
    if (workLens === "mine") return queueItems.filter((i) => isMineItem(i, userEmail));
    if (workLens === "now") return queueItems.filter(isNowItem);
    return queueItems;
  }, [queueItems, workLens, userEmail]);

  const sourceCounts = useMemo(
    () => ({
      cve: queueItems.filter((i) => i.source === "cve").length,
      bdu: queueItems.filter((i) => i.source === "bdu").length,
      tg: queueItems.filter((i) => i.source === "tg").length
    }),
    [queueItems]
  );

  const stats = useMemo(() => {
    const slaCases = (casesQuery.data ?? []).filter((c) => isSlaBreached(c.slaDueAt)).length;
    return {
      now: queueItems.filter(isNowItem).length,
      mine: queueItems.filter((i) => isMineItem(i, userEmail)).length,
      p1: queueItems.filter((i) => i.vocPriority === "p1" && i.status !== "done" && i.status !== "dismissed").length,
      sla: slaCases || queueItems.filter((i) => i.slaBreached).length,
      cases: casesQuery.data?.length ?? 0,
      watchlist: queueItems.filter((i) => hasWatchlistHit(i) && i.status !== "done").length,
      tg: tgRecentItems.length,
      watchlistRules: (watchlistQuery.data ?? []).filter((r) => r.active).length
    };
  }, [queueItems, tgRecentItems.length, watchlistQuery.data, casesQuery.data, userEmail]);

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
      const createdCase = created.case as VocCaseRow | undefined;
      if (createdCase?.id) {
        queryClient.setQueryData<VocCaseRow[]>(["voc", "cases", "active"], (old) => {
          const list = old ?? [];
          if (list.some((c) => c.id === createdCase.id)) return list;
          return [createdCase, ...list];
        });
        setOpenCaseId(createdCase.id);
        if (isPage) setSection("cases");
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
      if (openCaseId) {
        if (e.key === "Escape") setOpenCaseId(null);
        return;
      }
      if (e.key === "1") {
        setWorkLens("now");
        if (isPage) setSection("queue");
      }
      if (e.key === "2") {
        setWorkLens("mine");
        if (isPage) setSection("queue");
      }
      if (e.key === "3") setWorkLens("all");
      if (isPage && section !== "queue") return;
      if (!items.length) return;
      if (e.key === "ArrowDown" || e.key === "j" || e.key === "J") {
        e.preventDefault();
        setKbdIndex((i) => Math.min(items.length - 1, i + 1));
      }
      if (e.key === "ArrowUp" || e.key === "k" || e.key === "K") {
        e.preventDefault();
        setKbdIndex((i) => Math.max(0, i - 1));
      }
      if ((e.key === "c" || e.key === "C") && selected?.status === "open") {
        e.preventDefault();
        setStatus(selected, "claimed");
      }
      if ((e.key === "e" || e.key === "E") && selected) {
        e.preventDefault();
        if (selected.caseId) {
          setOpenCaseId(selected.caseId);
          if (isPage) setSection("cases");
        } else {
          void handleCreateCase(selected);
        }
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
  }, [items.length, selected, onOpenCve, onOpenBdu, onOpenTgLink, openCaseId, section, isPage, setStatus]);

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

  const goQueue = (lens: WorkLens) => {
    setWorkLens(lens);
    if (isPage) setSection("queue");
  };

  const openCaseFromQueue = (caseId: string) => {
    setOpenCaseId(caseId);
    if (isPage) setSection("cases");
  };

  return (
    <section className={cn(isPage ? "space-y-5" : "rounded-2xl border border-border bg-white p-5 dark:bg-black/20")}>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <div className="flex items-center gap-2 text-base font-semibold tracking-tight text-fg/95">
            <Inbox className="h-4 w-4 text-accent" />
            Vulnerability Operations
          </div>
          <p className="mt-1 max-w-3xl text-[12px] leading-relaxed text-muted">
            Смена работает с тем, что горит: P1, SLA и watchlist. Сигнал → кейс → playbook → исход.
            Клавиши: J/K очередь, C взять, E кейс, Enter карточка, 1/2/3 линзы.
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <span className="hidden items-center gap-1 text-[10px] text-muted lg:inline-flex">
            <Keyboard className="h-3.5 w-3.5" />
            J K C E
          </span>
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
              "inline-flex items-center gap-1.5 rounded-xl border border-border bg-white px-3 py-2 text-[11px]",
              "hover:bg-slate-50 dark:bg-black/30 dark:hover:bg-black/45",
              refreshing && "opacity-80"
            )}
          >
            {refreshing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
            Обновить
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {(
          [
            {
              id: "now" as const,
              label: "Сейчас",
              hint: "P1 · SLA · watchlist",
              value: stats.now,
              icon: ShieldAlert,
              danger: stats.sla > 0 || stats.p1 > 0,
              onClick: () => goQueue("now")
            },
            {
              id: "mine" as const,
              label: "Мои",
              hint: "взятые вами",
              value: stats.mine,
              icon: UserRound,
              danger: false,
              onClick: () => goQueue("mine")
            },
            {
              id: "sla" as const,
              label: "SLA",
              hint: "просроченные кейсы",
              value: stats.sla,
              icon: Clock,
              danger: stats.sla > 0,
              onClick: () => {
                setCaseFilter("sla");
                if (isPage) setSection("cases");
              }
            },
            {
              id: "cases" as const,
              label: "Кейсы",
              hint: "открытые",
              value: stats.cases,
              icon: Briefcase,
              danger: false,
              onClick: () => {
                setCaseFilter("all");
                if (isPage) setSection("cases");
              }
            }
          ] as const
        ).map((c) => (
          <button
            key={c.id}
            type="button"
            onClick={c.onClick}
            className={cn(
              "rounded-xl border px-3 py-2.5 text-left transition",
              workLens === c.id && section === "queue"
                ? "border-accent/45 bg-accent/10"
                : "border-border bg-white hover:bg-slate-50/80 dark:bg-black/25 dark:hover:bg-white/[0.03]",
              c.danger && "border-danger/35"
            )}
          >
            <div className="flex items-center gap-1.5 text-[10px] text-muted">
              <c.icon className="h-3 w-3" />
              {c.label}
            </div>
            <div className={cn("mt-0.5 text-xl font-semibold tabular-nums", c.danger && "text-danger")}>
              <LiveNumber value={c.value} />
            </div>
            <div className="text-[10px] text-muted">{c.hint}</div>
          </button>
        ))}
      </div>

      {isPage ? (
        <div className="flex flex-wrap gap-2 border-b border-border pb-3">
          {(
            [
              ["queue", "Очередь", Activity],
              ["cases", "Кейсы", Briefcase],
              ["watchlist", "Watchlist", Bookmark],
              ["shift", "Смена", Clock]
            ] as const
          ).map(([key, label, Icon]) => (
            <button
              key={key}
              type="button"
              onClick={() => setSection(key)}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-xl border px-3.5 py-2 text-[12px] font-medium transition",
                section === key
                  ? "border-accent/45 bg-accent/12 text-fg/95"
                  : "border-border bg-white text-muted hover:text-fg/85 dark:bg-black/25"
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
            openCaseId={openCaseId}
            onOpenCaseIdChange={setOpenCaseId}
            onOpenCve={onOpenCve}
            onOpenBdu={onOpenBdu}
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
          openCaseId={openCaseId}
          onOpenCaseIdChange={setOpenCaseId}
          initialFilter={caseFilter}
          onOpenCve={onOpenCve}
          onOpenBdu={onOpenBdu}
          onSelectRefKey={(refKey) => {
            setSection("queue");
            setWorkLens("all");
            const idx = queueItems.findIndex((i) => i.refKey === refKey);
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
            ["now", "Сейчас"],
            ["mine", "Мои"],
            ["all", "Вся очередь"]
          ] as const
        ).map(([key, label]) => (
          <button
            key={key}
            type="button"
            onClick={() => setWorkLens(key)}
            className={cn(
              "rounded-full border px-3 py-1 text-[11px] font-semibold transition",
              workLens === key
                ? "border-accent/40 bg-accent/12 text-fg/95"
                : "border-border bg-white text-muted hover:text-fg/80 dark:bg-black/30"
            )}
          >
            {label}
          </button>
        ))}
        <span className="mx-1 hidden h-6 w-px bg-border sm:inline" />
        {(
          [
            ["all", "Все источники"],
            ["watchlist", "Watchlist"],
            ["cve", "CVE"],
            ["bdu", "БДУ"],
            ["tg", "Telegram"]
          ] as const
        ).map(([key, label]) => {
          const count =
            key === "cve" ? sourceCounts.cve : key === "bdu" ? sourceCounts.bdu : key === "tg" ? sourceCounts.tg : null;
          return (
          <button
            key={key}
            type="button"
            onClick={() => setSourceTab(key)}
            className={cn(
              "rounded-full border px-3 py-1 text-[11px] font-medium transition",
              sourceTab === key
                ? "border-border bg-slate-100 text-fg/95 dark:bg-white/10"
                : "border-border bg-white text-muted hover:text-fg/80 dark:bg-black/30"
            )}
          >
            {label}
            {count != null && sourceTab === "all" && count > 0 ? (
              <span className="ml-1 tabular-nums text-muted">{count}</span>
            ) : null}
          </button>
          );
        })}
        <span className="mx-1 hidden h-6 w-px bg-border sm:inline" />
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
                : "border-border bg-white text-muted dark:bg-black/30"
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
            <div className="rounded-2xl border border-dashed border-border px-4 py-10 text-center text-sm text-muted">
              {workLens === "now" ? (
                <div className="space-y-3">
                  <div>Сейчас чисто: нет P1, просроченного SLA и попаданий в watchlist.</div>
                  <button
                    type="button"
                    onClick={() => setWorkLens("all")}
                    className="rounded-lg border border-border px-3 py-1.5 text-[12px] font-medium text-fg/85 hover:bg-slate-50 dark:hover:bg-white/5"
                  >
                    Показать всю очередь
                  </button>
                </div>
              ) : workLens === "mine" ? (
                "Нет сигналов, взятых вами. Возьмите из «Сейчас» или очереди."
              ) : sourceTab === "watchlist" && stats.watchlistRules === 0 ? (
                "Добавьте правила во Watchlist — здесь появятся совпадения за 7 дней."
              ) : (
                "Нет событий по выбранным фильтрам."
              )}
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

        <div className="rounded-xl border border-border bg-white p-4 dark:bg-[#0d1524]">
          {selected ? (
            <div className="space-y-4">
              <div>
                <div className="text-[10px] font-semibold uppercase tracking-wide text-muted">Сигнал смены</div>
                <div className="mt-1 flex flex-wrap items-center gap-2">
                  <span className={cn("rounded-md border px-1.5 py-0.5 text-[11px] font-semibold", vocPriorityMeta(selected.vocPriority).badge)}>
                    {vocPriorityLabel(selected.vocPriority)}
                  </span>
                  <span className="font-mono text-[12px] font-semibold tabular-nums text-fg/70">{selected.vocScore}</span>
                  <span className="text-[11px] text-muted">{vocStatusLabel(selected.status)}</span>
                </div>
                <h2 className="mt-2 text-[16px] font-semibold leading-snug tracking-tight">{selected.title}</h2>
                <div className="mt-1 text-[11px] text-muted">{fmtWhen(selected.publishedAt)}</div>
              </div>

              <div className="flex flex-col gap-2">
                {selected.status === "open" ? (
                  <button
                    type="button"
                    disabled={casePending || pendingKey === selected.refKey}
                    onClick={() => {
                      if (!selected.caseId) void handleCreateCase(selected);
                      else void setStatus(selected, "claimed");
                    }}
                    className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-accent/40 bg-accent/12 px-3 py-2 text-[12px] font-semibold"
                  >
                    {casePending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Briefcase className="h-3.5 w-3.5" />}
                    {selected.caseId ? "Взять в работу" : "В работу — создать кейс"}
                  </button>
                ) : null}
                {selected.caseId ? (
                  <button
                    type="button"
                    onClick={() => openCaseFromQueue(selected.caseId!)}
                    className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-border px-3 py-2 text-[12px] font-medium hover:bg-slate-50 dark:hover:bg-white/5"
                  >
                    <Briefcase className="h-3.5 w-3.5" />
                    Открыть кейс {caseIssueKey(selected.caseId)}
                  </button>
                ) : selected.status !== "open" ? (
                  <button
                    type="button"
                    disabled={casePending}
                    onClick={() => void handleCreateCase(selected)}
                    className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-border px-3 py-2 text-[12px] font-medium"
                  >
                    {casePending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Briefcase className="h-3.5 w-3.5" />}
                    Создать кейс
                  </button>
                ) : null}
                {selected.source === "cve" ? (
                  <button
                    type="button"
                    onClick={() => onOpenCve?.(selected.refId)}
                    className="inline-flex items-center justify-center gap-1 rounded-lg border border-border px-3 py-2 text-[12px] hover:bg-slate-50 dark:hover:bg-white/5"
                  >
                    Открыть CVE <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                ) : null}
                {selected.source === "bdu" ? (
                  <button
                    type="button"
                    onClick={() => onOpenBdu?.(selected.refId)}
                    className="inline-flex items-center justify-center gap-1 rounded-lg border border-border px-3 py-2 text-[12px] hover:bg-slate-50 dark:hover:bg-white/5"
                  >
                    Открыть БДУ <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                ) : null}
                {selected.source === "tg" && typeof selected.payload.link === "string" ? (
                  <button
                    type="button"
                    onClick={() => onOpenTgLink?.(String(selected.payload.link))}
                    className="inline-flex items-center justify-center gap-1 rounded-lg border border-border px-3 py-2 text-[12px]"
                  >
                    Открыть в Telegram <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                ) : null}
              </div>

              {(() => {
                const intel = vocIntelContext(selected);
                if (intel) {
                  return (
                    <>
                      {intel.vendor || intel.product ? (
                        <div className="text-[12px] text-muted">
                          {[intel.vendor, intel.product].filter(Boolean).join(" / ")}
                        </div>
                      ) : null}
                      {intel.description ? (
                        <p className="text-[12px] leading-relaxed text-fg/85">{intel.description}</p>
                      ) : null}
                      {intel.chips.length ? (
                        <div className="flex flex-wrap gap-1.5">
                          {intel.chips.map((chip) => (
                            <span
                              key={chip.key}
                              className={cn("rounded-md border px-2 py-0.5 text-[10px] font-medium", vocChipClass(chip.tone))}
                            >
                              {chip.label}
                            </span>
                          ))}
                        </div>
                      ) : null}
                    </>
                  );
                }
                return (
                  <>
                    {selected.subtitle ? (
                      <p className="text-[12px] leading-relaxed text-fg/85">{selected.subtitle}</p>
                    ) : null}
                    <div className="flex flex-wrap gap-1.5">
                      {selected.vocReasons.map((r) => (
                        <span key={r} className="rounded-md border border-border px-2 py-0.5 text-[10px] text-muted">
                          {r}
                        </span>
                      ))}
                    </div>
                  </>
                );
              })()}

              <div className="flex flex-wrap items-center gap-2">
                {selected.caseId ? (
                  <span
                    className={cn(
                      "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px]",
                      slaTone(selected.slaDueAt, selected.slaBreached)
                    )}
                  >
                    <Clock className="h-3 w-3" />
                    SLA {slaRemainingLabel(selected.slaDueAt)}
                  </span>
                ) : null}
                {typeof selected.payload.vp_vendor === "string" && selected.payload.vp_vendor ? (
                  <VocWatchlistQuickAdd kind="vendor" value={selected.payload.vp_vendor} compact />
                ) : null}
                {typeof selected.payload.vp_product === "string" && selected.payload.vp_product ? (
                  <VocWatchlistQuickAdd kind="product" value={String(selected.payload.vp_product)} compact />
                ) : null}
              </div>

              <div className="flex flex-wrap gap-2 border-t border-border pt-3">
                {selected.caseId && !selected.taskId ? (
                  <button
                    type="button"
                    disabled={casePending}
                    onClick={() => void handleCreateCase(selected)}
                    className="rounded-md border border-warn/40 bg-warn/10 px-2.5 py-1.5 text-[11px] font-medium"
                  >
                    Создать задачу
                  </button>
                ) : null}
                {selected.status === "claimed" &&
                selected.claimedByEmail?.toLowerCase() === userEmail?.toLowerCase() ? (
                  <button
                    type="button"
                    disabled={pendingKey === selected.refKey}
                    onClick={() => setStatus(selected, "open")}
                    className="rounded-md border border-border px-2.5 py-1.5 text-[11px] text-muted"
                  >
                    Отпустить
                  </button>
                ) : null}
                {selected.status !== "done" && selected.status !== "dismissed" ? (
                  <button
                    type="button"
                    disabled={pendingKey === selected.refKey}
                    onClick={() => setStatus(selected, "done")}
                    className="rounded-md border border-ok/35 bg-ok/10 px-2.5 py-1.5 text-[11px] text-ok"
                  >
                    Снять с ленты
                  </button>
                ) : (
                  <button
                    type="button"
                    disabled={pendingKey === selected.refKey}
                    onClick={() => setStatus(selected, "open")}
                    className="rounded-md border border-border px-2.5 py-1.5 text-[11px] text-muted"
                  >
                    Вернуть в очередь
                  </button>
                )}
              </div>
            </div>
          ) : (
            <div className="flex h-full min-h-[12rem] items-center justify-center text-sm text-muted">
              Выберите сигнал — справа действия смены
            </div>
          )}
        </div>
      </div>
        </>
      )}
    </section>
  );
}

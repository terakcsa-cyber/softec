"use client";

import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, ChevronRight, Loader2, RefreshCw, X } from "lucide-react";
import { cn } from "../ui/cn";
import { apiFetch } from "@/lib/api-fetch";
import { LiveNumber } from "../ui/live-number";
import { useLiveQueryOptions } from "@/lib/live-refresh";
import {
  fetchVocQueue,
  fetchVocTriageBySource,
  type VocDeskDecision,
  type VocQueueItem,
  type VocTriageStatus
} from "@/lib/voc-api";
import { useVocQueueTriage } from "@/lib/use-voc-queue-triage";
import { buildTgCriticalRows, isWithinLast24h, type TgCveIntel, type TgFeedResponse } from "@/lib/tg-feed-critical";
import { scoreTgForVoc } from "@/lib/voc-scoring-client";
import { applyWatchlistBoostClient } from "@/lib/voc-watchlist-client";
import { fetchVocWatchlist } from "@/lib/voc-watchlist-api";
import { buildDeskRows, deskFacts, deskResearch, deskStats, filterDeskRows, type DeskFilter, type DeskRow } from "@/lib/voc-desk";
import { VocQueueRow } from "./voc-queue-row";
import { VocWatchlistPanel } from "./voc-watchlist-panel";
import { VocCasesPanel } from "./voc-cases-panel";
import { VocShiftPanel } from "./voc-shift-panel";
import { buildCaseRefMap, createVocCaseFromRef, fetchVocCases, type VocCaseRow } from "@/lib/voc-case-api";
import { isSlaBreached } from "@/lib/voc-case-client";

export function VocHomePanel({
  onOpenCve,
  onOpenBdu,
  onOpenTgLink
}: {
  onOpenCve?: (cveId: string) => void;
  onOpenBdu?: (bduId: string) => void;
  onOpenTgLink?: (link: string) => void;
  variant?: "card" | "page";
}) {
  const { userEmail, mergeItems, commit, pendingKey, error, clearError } = useVocQueueTriage();
  const [filter, setFilter] = useState<DeskFilter>("desk");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [caseError, setCaseError] = useState<string | null>(null);
  const [casePending, setCasePending] = useState(false);
  const [openCaseId, setOpenCaseId] = useState<string | null>(null);
  const [showSetup, setShowSetup] = useState(false);
  const liveOpts = useLiveQueryOptions();
  const queryClient = useQueryClient();

  const queueQuery = useQuery({
    queryKey: ["voc", "queue", "desk"],
    queryFn: async () => {
      const [hot, watched] = await Promise.all([
        fetchVocQueue({ source: "all", status: "all", limit: 200 }),
        fetchVocQueue({ source: "watchlist", status: "all", limit: 80 }).catch(() => ({
          items: [] as VocQueueItem[],
          stats: {}
        }))
      ]);
      const byKey = new Map<string, VocQueueItem>();
      for (const item of [...hot.items, ...watched.items]) byKey.set(item.refKey, item);
      return { items: [...byKey.values()], stats: hot.stats };
    },
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
    staleTime: 60_000,
    refetchInterval: 60_000
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

  const tgTriageQuery = useQuery({
    queryKey: ["voc", "triage", "tg"],
    queryFn: () => fetchVocTriageBySource("tg", 240),
    ...liveOpts
  });

  const caseRefMap = useMemo(() => buildCaseRefMap(casesQuery.data ?? []), [casesQuery.data]);

  const tgItems = useMemo((): VocQueueItem[] => {
    const intelByCve = new Map<string, TgCveIntel>();
    for (const row of queueQuery.data?.items ?? []) {
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
    const triage = new Map((tgTriageQuery.data ?? []).map((row) => [row.refKey, row]));
    const recent = (tgFeedQuery.data?.items ?? []).filter((item) => isWithinLast24h(item.pubDate));
    const watchlist = watchlistQuery.data ?? [];
    return buildTgCriticalRows(recent, intelByCve, { minScore: 24 }).map((row) => {
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
      const refKey = `TG:${row.item.id}`;
      const saved = triage.get(refKey);
      return {
        refKey,
        source: "tg" as const,
        refId: row.item.id,
        vocScore: boosted.score,
        vocPriority: boosted.priority,
        vocReasons: boosted.reasons,
        title: row.item.title?.trim() || `@${row.item.channel.slug}`,
        subtitle: (row.item.descriptionText || "").slice(0, 220),
        publishedAt: row.item.pubDate,
        status: saved?.status ?? "open",
        claimedByEmail: saved?.claimedByEmail ?? null,
        updatedAt: saved?.updatedAt ?? null,
        deskDecision: saved?.deskDecision ?? null,
        deskReviewAt: saved?.deskReviewAt ?? null,
        payload: {
          link: row.item.link,
          channel: row.item.channel,
          cveIds: row.item.cveIds,
          criticalCveIds: row.criticalCveIds
        }
      };
    });
  }, [queueQuery.data?.items, tgFeedQuery.data?.items, tgTriageQuery.data, watchlistQuery.data]);

  const rows = useMemo(() => {
    const merged = mergeItems([...(queueQuery.data?.items ?? []), ...tgItems]).map((item) => {
      if (item.caseId) return { ...item, slaBreached: item.slaBreached ?? isSlaBreached(item.slaDueAt) };
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
    return buildDeskRows(merged);
  }, [queueQuery.data?.items, tgItems, mergeItems, caseRefMap]);

  const stats = useMemo(() => deskStats(rows), [rows]);
  const visible = useMemo(() => filterDeskRows(rows, filter), [rows, filter]);
  const selected = visible.find((row) => row.key === selectedKey) ?? visible[0] ?? null;

  useEffect(() => {
    if (!visible.length) {
      setSelectedKey(null);
      return;
    }
    if (!selectedKey || !visible.some((row) => row.key === selectedKey)) setSelectedKey(visible[0]!.key);
  }, [visible, selectedKey]);

  async function decide(row: DeskRow, decision: VocDeskDecision) {
    setCaseError(null);
    setCasePending(true);
    try {
      if (decision === "fixing" && !row.members.some((item) => item.caseId)) {
        const item = row.primary;
        const linkedCveIds =
          item.source === "cve"
            ? [item.refId]
            : Array.isArray(item.payload.cveIds)
              ? item.payload.cveIds.map(String)
              : Array.isArray(item.payload.cve_ids)
                ? item.payload.cve_ids.map(String)
                : [];
        const vendor = typeof item.payload.vp_vendor === "string" ? item.payload.vp_vendor : undefined;
        const product = typeof item.payload.vp_product === "string" ? item.payload.vp_product : undefined;
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
          vendorDisplay: vendor,
          productDisplay: product,
          vendorKey: vendor?.toLowerCase(),
          productKeyNorm: product?.toLowerCase()
        });
        const createdCase = created.case as VocCaseRow | undefined;
        if (createdCase?.id) {
          queryClient.setQueryData<VocCaseRow[]>(["voc", "cases", "active"], (old) => {
            const list = old ?? [];
            return list.some((entry) => entry.id === createdCase.id) ? list : [createdCase, ...list];
          });
        }
        if (!created.taskId && !created.case?.taskId) {
          setCaseError("Кейс есть, задача не создалась. Её можно догнать из карточки кейса.");
        }
      }
      const status: VocTriageStatus = decision === "fixing" ? "claimed" : decision === "accepted_risk" ? "done" : "dismissed";
      const reviewAt =
        decision === "accepted_risk" ? new Date(Date.now() + 90 * 86_400_000).toISOString() : null;
      for (const member of row.members) {
        await commit(member, status, { deskDecision: decision, deskReviewAt: reviewAt });
      }
      void casesQuery.refetch();
      void queueQuery.refetch();
    } catch (err) {
      setCaseError(err instanceof Error ? err.message : "Не удалось записать решение");
    } finally {
      setCasePending(false);
    }
  }

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.target instanceof HTMLInputElement || event.target instanceof HTMLTextAreaElement || event.target instanceof HTMLButtonElement) return;
      if (!visible.length || !selected) return;
      const index = visible.findIndex((row) => row.key === selected.key);
      if (event.key === "ArrowDown" || event.key === "j" || event.key === "J") {
        event.preventDefault();
        const next = visible[Math.min(visible.length - 1, index + 1)];
        if (next) setSelectedKey(next.key);
      }
      if (event.key === "ArrowUp" || event.key === "k" || event.key === "K") {
        event.preventDefault();
        const next = visible[Math.max(0, index - 1)];
        if (next) setSelectedKey(next.key);
      }
      const decisionByKey: Record<string, VocDeskDecision> = {
        "1": "fixing",
        "2": "waiting_patch",
        "3": "not_ours",
        "4": "accepted_risk"
      };
      const decision = decisionByKey[event.key];
      if (decision && !casePending) {
        event.preventDefault();
        void decide(selected, decision);
      }
      if (event.key === "Enter") {
        event.preventDefault();
        openResearch(selected);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const refreshing = queueQuery.isFetching || tgFeedQuery.isFetching || tgTriageQuery.isFetching;
  const research = selected ? deskResearch(selected) : null;

  function openResearch(row: DeskRow) {
    const target = deskResearch(row);
    if (target.cveId) onOpenCve?.(target.cveId);
    else if (target.bduId) onOpenBdu?.(target.bduId);
    else if (target.tgLink) onOpenTgLink?.(target.tgLink);
  }

  const cards = [
    { id: "burning" as const, label: "Горит", hint: "наше и эксплуатация или SLA", value: stats.burning, danger: stats.burning > 0 },
    { id: "ours" as const, label: "Наши", hint: "без решения", value: stats.ours, danger: false },
    { id: "bdu" as const, label: "БДУ", hint: "на контуре", value: stats.bdu, danger: false }
  ];

  const facts = selected ? deskFacts(selected) : [];

  return (
    <section className="flex h-full min-h-0 flex-col gap-3">
      <div className="flex shrink-0 items-center justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold tracking-tight text-fg/95">Стол смены</h2>
          <p className="truncate text-[11px] text-muted">J/K список, Enter карточка, 1–4 решение</p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <button
            type="button"
            onClick={() => setFilter((current) => (current === "history" ? "desk" : "history"))}
            className={cn(
              "rounded-md border px-2.5 py-1.5 text-[11px]",
              filter === "history" ? "border-accent/40 bg-accent/10" : "border-border text-muted"
            )}
          >
            История
          </button>
          <button
            type="button"
            onClick={() => setShowSetup((value) => !value)}
            className="rounded-md border border-border px-2.5 py-1.5 text-[11px] text-muted"
          >
            {showSetup ? "Скрыть контур" : "Контур"}
          </button>
          <button
            type="button"
            onClick={() => {
              void queueQuery.refetch();
              void tgFeedQuery.refetch();
              void tgTriageQuery.refetch();
              void casesQuery.refetch();
            }}
            disabled={refreshing}
            className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-border px-2.5 py-1.5 text-[11px]"
          >
            {refreshing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
            Обновить
          </button>
        </div>
      </div>

      <div className="grid shrink-0 grid-cols-3 gap-2">
        {cards.map((card) => (
          <button
            key={card.id}
            type="button"
            title={card.hint}
            onClick={() => setFilter((current) => (current === card.id ? "desk" : card.id))}
            className={cn(
              "flex items-center justify-between gap-2 rounded-lg border px-3 py-2 text-left",
              filter === card.id ? "border-accent/40 bg-accent/10" : "border-border bg-white dark:bg-black/20",
              card.danger && filter !== card.id && "border-danger/30"
            )}
          >
            <span className="text-[11px] text-muted">{card.label}</span>
            <span className={cn("text-lg font-semibold tabular-nums leading-none", card.danger && "text-danger")}>
              <LiveNumber value={card.value} />
            </span>
          </button>
        ))}
      </div>

      {caseError ? <Banner text={caseError} onClose={() => setCaseError(null)} /> : null}
      {error ? <Banner text={error} onClose={clearError} /> : null}
      {queueQuery.isError ? (
        <Banner
          text={queueQuery.error instanceof Error ? queueQuery.error.message : "Не удалось загрузить стол"}
          onClose={() => void queueQuery.refetch()}
        />
      ) : null}

      {showSetup ? (
        <div className="max-h-56 shrink-0 space-y-4 overflow-y-auto rounded-lg border border-border p-3">
          <VocWatchlistPanel />
          <VocShiftPanel />
        </div>
      ) : null}

      <div className="grid min-h-0 flex-1 grid-rows-[minmax(0,1.15fr)_minmax(0,0.85fr)] gap-3 xl:grid-cols-[minmax(0,1.15fr)_minmax(320px,0.85fr)] xl:grid-rows-1">
        <div className="min-h-0 space-y-1.5 overflow-y-auto rounded-lg border border-border bg-white p-1.5 dark:bg-black/20 [scrollbar-width:thin]">
          {queueQuery.isLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 4 }).map((_, index) => (
                <div key={index} className="h-28 animate-pulse rounded-lg bg-slate-200/60 dark:bg-white/[0.06]" />
              ))}
            </div>
          ) : visible.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border px-4 py-10 text-center text-sm text-muted">
              {queueQuery.isError
                ? "Не удалось загрузить стол."
                : filter === "desk"
                  ? "Стол чистый: нет открытых решений."
                  : "В этом срезе пусто."}
            </div>
          ) : (
            visible.map((row) => (
              <VocQueueRow
                key={row.key}
                row={row}
                active={selected?.key === row.key}
                onSelect={() => setSelectedKey(row.key)}
                onOpenCve={onOpenCve}
                onOpenBdu={onOpenBdu}
                onOpenTg={onOpenTgLink}
              />
            ))
          )}
        </div>

        <aside className="flex min-h-0 flex-col overflow-hidden rounded-lg border border-border bg-white dark:bg-black/20">
          {selected && research ? (
            <>
              <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-3.5 [scrollbar-width:thin]">
                <div>
                  <div className="text-[10px] font-medium uppercase tracking-wide text-muted">Исследование</div>
                  <h3 className="mt-1 text-[15px] font-semibold leading-snug tracking-tight">{selected.product}</h3>
                  <p className="mt-1 text-[12px] leading-snug text-fg/70">{selected.phrase}</p>
                </div>
                <p className="text-[13px] leading-relaxed text-fg/85">
                  {selected.summary || "Короткого описания в ленте нет. Полный разбор открывается карточкой."}
                </p>
                {facts.length ? (
                  <dl className="grid grid-cols-2 gap-x-3 gap-y-2 border-t border-border pt-3">
                    {facts.map((fact) => (
                      <div key={fact.label} className="min-w-0">
                        <dt className="text-[10px] text-muted">{fact.label}</dt>
                        <dd
                          className={cn(
                            "truncate text-[12px] font-medium",
                            fact.tone === "danger" && "text-danger",
                            fact.tone === "warn" && "text-warn",
                            fact.tone === "ok" && "text-ok"
                          )}
                          title={fact.value}
                        >
                          {fact.value}
                        </dd>
                      </div>
                    ))}
                  </dl>
                ) : null}
                <div className="flex flex-wrap gap-1.5">
                  {research.cveId ? (
                    <button
                      type="button"
                      onClick={() => onOpenCve?.(research.cveId!)}
                      className="inline-flex items-center gap-1 rounded-md border border-accent/40 bg-accent/12 px-2.5 py-1.5 text-[12px] font-semibold"
                    >
                      {research.cveId}
                      <ChevronRight className="h-3.5 w-3.5" />
                    </button>
                  ) : null}
                  {research.bduId ? (
                    <button
                      type="button"
                      onClick={() => onOpenBdu?.(research.bduId!)}
                      className="inline-flex items-center gap-1 rounded-md border border-border px-2.5 py-1.5 text-[12px] font-medium hover:border-accent/30"
                    >
                      {research.bduId.startsWith("BDU") ? research.bduId : `BDU:${research.bduId}`}
                      <ChevronRight className="h-3.5 w-3.5" />
                    </button>
                  ) : null}
                  {research.tgLink ? (
                    <button
                      type="button"
                      onClick={() => onOpenTgLink?.(research.tgLink!)}
                      className="inline-flex items-center gap-1 rounded-md border border-border px-2.5 py-1.5 text-[12px] font-medium hover:border-accent/30"
                    >
                      Telegram
                      <ChevronRight className="h-3.5 w-3.5" />
                    </button>
                  ) : null}
                  {selected.primary.caseId ? (
                    <button
                      type="button"
                      className="inline-flex items-center gap-1 rounded-md border border-border px-2.5 py-1.5 text-[12px] text-accent hover:border-accent/30"
                      onClick={() => setOpenCaseId(selected.primary.caseId ?? null)}
                    >
                      Кейс смены
                    </button>
                  ) : null}
                </div>
              </div>
              <div className="shrink-0 border-t border-border p-3">
                <div className="grid grid-cols-2 gap-1.5">
                  <DecisionButton label="Наше, чиним" hint="1" busy={casePending || pendingKey != null} onClick={() => void decide(selected, "fixing")} primary />
                  <DecisionButton label="Ждём патч" hint="2" busy={casePending || pendingKey != null} onClick={() => void decide(selected, "waiting_patch")} />
                  <DecisionButton label="Не наше" hint="3" busy={casePending || pendingKey != null} onClick={() => void decide(selected, "not_ours")} />
                  <DecisionButton label="Принятый риск" hint="4" busy={casePending || pendingKey != null} onClick={() => void decide(selected, "accepted_risk")} />
                </div>
                <p className="mt-2 text-[11px] text-muted">
                  {selected.primary.caseId
                    ? `SLA идёт. ${selected.when ? `Осталось ${selected.when}.` : ""}`
                    : "SLA начнётся после «Наше, чиним»."}
                </p>
              </div>
            </>
          ) : (
            <div className="flex h-full items-center justify-center px-4 text-sm text-muted">Выберите строку</div>
          )}
        </aside>
      </div>

      {openCaseId ? (
        <VocCasesPanel
          presentation="drawer"
          currentUserEmail={userEmail}
          openCaseId={openCaseId}
          onOpenCaseIdChange={setOpenCaseId}
          onOpenCve={onOpenCve}
          onOpenBdu={onOpenBdu}
        />
      ) : null}
    </section>
  );
}

function DecisionButton({
  label,
  hint,
  onClick,
  busy,
  primary
}: {
  label: string;
  hint: string;
  onClick: () => void;
  busy?: boolean;
  primary?: boolean;
}) {
  return (
    <button
      type="button"
      disabled={busy}
      onClick={onClick}
      className={cn(
        "rounded-lg border px-2.5 py-2 text-left text-[12px] font-medium disabled:opacity-50",
        primary ? "border-accent/40 bg-accent/12" : "border-border bg-white dark:bg-black/25"
      )}
    >
      {label}
      <span className="ml-1 text-[10px] text-muted">{hint}</span>
    </button>
  );
}

function Banner({ text, onClose }: { text: string; onClose: () => void }) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-danger/35 bg-danger/10 px-3 py-2 text-[12px] text-danger">
      <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
      <div className="min-w-0 flex-1">{text}</div>
      <button type="button" onClick={onClose} className="shrink-0">
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}

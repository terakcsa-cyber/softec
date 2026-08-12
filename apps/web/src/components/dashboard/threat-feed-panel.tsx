"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Flame, Send, Sparkles, TrendingUp, ClipboardPlus } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiFetch } from "@/lib/api-fetch";
import { useLivePollInterval } from "@/lib/live-refresh";
import {
  EXPLOIT_RADAR_FILTER_LABELS,
  EXPLOIT_SIGNAL_TYPES,
  exploitSignalLabel,
  fmtEpssDelta,
  fmtEpssPct,
  fmtRelativeTs,
  threatScoreTone,
  type ExploitRadarFilter,
  type ThreatFeedItem,
  type ThreatFeedResponse,
  type ThreatFeedSort,
  type ThreatFeedTimeBucket,
  type ThreatFeedVendorHeat
} from "@/lib/exploit-intel-client";
import {
  buildThreatVocReasons,
  readThreatLastVisit,
  readThreatVendorFilter,
  threatToVocPriority,
  writeThreatLastVisit,
  writeThreatVendorFilter
} from "@/lib/threat-feed-client";
import { createVocCaseFromRef } from "@/lib/voc-case-api";
import { cveRefKey } from "@/lib/voc-ref-keys";
import { LiveNumber } from "../ui/live-number";
import { cn } from "../ui/cn";
import { ExploitIntelBadges } from "./exploit-intel-badges";

type WindowPreset = "24" | "168" | "720" | "all";

type WatchlistRow = { id: string; kind: string; value: string; label: string; active: boolean };

const TIME_BUCKET_META: Array<{
  key: ThreatFeedTimeBucket;
  label: string;
  hint: string;
}> = [
  { key: "new_24h", label: "Новые · 24 часа", hint: "Первый exploit-сигнал (или новый тип сигнала) за сутки" },
  { key: "updated_24h", label: "Обновлённые · 24 часа", hint: "Реальное изменение сигнала, не sync heartbeat" },
  { key: "new_7d", label: "Новые · 7 дней", hint: "Первый сигнал 1–7 дней назад (без пересечения с сутками)" },
  { key: "older", label: "Раньше в окне", hint: "В выбранном периоде, но старше 7 дней" }
];

function signalDisplayTime(it: ThreatFeedItem): { primary: string | null; label: string; secondary?: string | null } {
  if (it.is_updated) {
    return {
      primary: it.last_seen_at,
      label: "обновлён",
      secondary: it.first_seen_at
    };
  }
  return {
    primary: it.newest_signal_at || it.first_seen_at,
    label: "впервые"
  };
}

function PulseStat({
  label,
  value,
  hint,
  tone = "default"
}: {
  label: string;
  value: number;
  hint?: string;
  tone?: "default" | "hot" | "new";
}) {
  return (
    <div
      className={cn(
        "rounded-xl border px-3 py-2.5",
        tone === "hot"
          ? "border-warn/30 bg-warn/10"
          : tone === "new"
            ? "border-accent/30 bg-accent/10"
            : "border-slate-200/90 bg-white/70 dark:border-white/[0.06] dark:bg-black/20"
      )}
      title={hint}
    >
      <div className="text-[10px] uppercase tracking-wide text-muted">{label}</div>
      <div className="mt-0.5 text-xl font-semibold tabular-nums">
        <LiveNumber value={value} />
      </div>
    </div>
  );
}

function ThreatScoreBadge({ score }: { score: number }) {
  const tone = threatScoreTone(score);
  const cls =
    tone === "critical"
      ? "border-danger/40 bg-danger/15 text-danger"
      : tone === "high"
        ? "border-warn/35 bg-warn/12 text-warn"
        : tone === "medium"
          ? "border-accent/35 bg-accent/10 text-accent"
          : "border-border bg-slate-50 text-muted dark:bg-white/5";
  return (
    <span className={cn("rounded-full border px-2 py-0.5 font-mono text-[10px] font-semibold", cls)} title="Threat score">
      {score}
    </span>
  );
}

function EpssSparkline({ values }: { values?: number[] }) {
  if (!values?.length) return null;
  const w = 56;
  const h = 18;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 0.01;
  const pts = values
    .map((v, i) => {
      const x = (i / Math.max(values.length - 1, 1)) * w;
      const y = h - ((v - min) / span) * (h - 2) - 1;
      return `${x},${y}`;
    })
    .join(" ");
  const up = values[values.length - 1]! > values[0]!;
  return (
    <svg width={w} height={h} className="shrink-0" aria-label="EPSS 7d trend">
      <polyline
        fill="none"
        strokeWidth={1.5}
        points={pts}
        className={up ? "stroke-warn" : "stroke-muted"}
      />
    </svg>
  );
}

function ActivityTimeline({ days }: { days: Array<{ day: string; count: number }> }) {
  const max = Math.max(...days.map((d) => d.count), 1);
  return (
    <div className="mt-3">
      <div className="mb-2 flex items-center gap-2 text-[11px] text-muted">
        <TrendingUp className="h-3.5 w-3.5" />
        Активность за 7 дней
      </div>
      <div className="flex h-16 items-end gap-1.5">
        {days.map((d) => {
          const h = Math.max(8, Math.round((d.count / max) * 100));
          return (
            <div key={d.day} className="flex min-w-0 flex-1 flex-col items-center gap-1" title={`${d.day}: ${d.count}`}>
              <div className="w-full rounded-t-md bg-gradient-to-t from-accent/70 to-accent/30" style={{ height: `${h}%` }} />
              <span className="text-[9px] text-muted">{d.day.slice(5)}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function VendorHeatmap({
  rows,
  selected,
  onSelect
}: {
  rows: ThreatFeedVendorHeat[];
  selected: string[];
  onSelect: (vendorKey: string) => void;
}) {
  if (!rows.length) return null;
  const max = Math.max(...rows.map((r) => r.signal_count), 1);
  return (
    <div className="mt-4">
      <div className="mb-2 text-[11px] font-medium text-fg/85">Threat map · вендоры (7д)</div>
      <div className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
        {rows.map((row) => {
          const intensity = row.signal_count / max;
          const active = selected.includes(row.vendor_key);
          return (
            <button
              key={row.vendor_key}
              type="button"
              onClick={() => onSelect(row.vendor_key)}
              className={cn(
                "rounded-lg border px-2.5 py-2 text-left transition",
                active
                  ? "border-accent/40 bg-accent/10 ring-1 ring-accent/20"
                  : "border-slate-200/90 bg-white/70 hover:border-accent/30 dark:border-white/[0.06] dark:bg-black/20"
              )}
              style={{
                backgroundImage: active
                  ? undefined
                  : `linear-gradient(90deg, rgba(245,158,11,${0.08 + intensity * 0.22}) 0%, transparent 100%)`
              }}
            >
              <div className="truncate text-[11px] font-medium">{row.vendor}</div>
              <div className="mt-0.5 flex gap-2 text-[10px] text-muted">
                <span>{row.signal_count} sig</span>
                <span>{row.cve_count} CVE</span>
                {row.hot_count > 0 ? <span className="text-warn">{row.hot_count} hot</span> : null}
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

export function ThreatFeedPanel({
  onOpenCve,
  onFilter
}: {
  onOpenCve?: (cveId: string) => void;
  onFilter?: (filter: ExploitRadarFilter) => void;
}) {
  const pollMs = useLivePollInterval();
  const queryClient = useQueryClient();
  const [offset, setOffset] = useState(0);
  const [windowPreset, setWindowPreset] = useState<WindowPreset>("168");
  const [signalType, setSignalType] = useState<string | null>(null);
  const [sort, setSort] = useState<ThreatFeedSort>("threat");
  const [newOnly, setNewOnly] = useState(false);
  const [watchlistOnly, setWatchlistOnly] = useState(false);
  const [vendorFilter, setVendorFilter] = useState<string[]>(() => readThreatVendorFilter());
  const [sinceVisit] = useState(() => readThreatLastVisit());
  const [digestPending, setDigestPending] = useState(false);
  const [digestMsg, setDigestMsg] = useState<string | null>(null);
  const [digestPrep, setDigestPrep] = useState<{
    phase: "idle" | "preparing" | "sending";
    total: number;
    done: number;
  }>({ phase: "idle", total: 0, done: 0 });
  const [casePending, setCasePending] = useState<string | null>(null);
  const [caseMsg, setCaseMsg] = useState<string | null>(null);
  const limit = 60;

  useEffect(() => {
    writeThreatVendorFilter(vendorFilter);
  }, [vendorFilter]);

  useEffect(() => {
    return () => writeThreatLastVisit(new Date().toISOString());
  }, []);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const res = await apiFetch("/api/stats/threat-feed/refresh?force=true", { method: "POST" });
        const body = (await res.json()) as { ok?: boolean };
        if (!res.ok || body.ok === false) return;
        if (!cancelled) {
          void queryClient.invalidateQueries({ queryKey: ["stats", "threat-feed"] });
          void queryClient.invalidateQueries({ queryKey: ["stats", "exploit-radar"] });
        }
      } catch {
        // TI refresh is best-effort; use «Здоровье системы» for manual retry / status.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [queryClient]);

  const watchlistQuery = useQuery({
    queryKey: ["voc", "watchlist"],
    queryFn: async () => {
      const res = await apiFetch("/api/voc/watchlist", { cache: "no-store" });
      if (!res.ok) throw new Error(`watchlist (${res.status})`);
      return (await res.json()) as WatchlistRow[];
    },
    staleTime: 60_000
  });

  const feedQuery = useQuery({
    queryKey: [
      "stats",
      "threat-feed",
      offset,
      windowPreset,
      signalType,
      sort,
      newOnly,
      watchlistOnly,
      vendorFilter.join(","),
      sinceVisit
    ],
    queryFn: async () => {
      const url = new URL("/api/stats/threat-feed", window.location.origin);
      url.searchParams.set("limit", String(limit));
      url.searchParams.set("offset", String(offset));
      url.searchParams.set("windowHours", windowPreset);
      url.searchParams.set("sort", sort);
      if (signalType) url.searchParams.set("signalType", signalType);
      if (newOnly) url.searchParams.set("newOnly", "true");
      if (watchlistOnly) url.searchParams.set("watchlistOnly", "true");
      if (sinceVisit) url.searchParams.set("since", sinceVisit);
      for (const v of vendorFilter) url.searchParams.append("vendor", v);
      const res = await apiFetch(url.toString(), { cache: "no-store" });
      if (!res.ok) throw new Error(`Threat feed (${res.status})`);
      return (await res.json()) as ThreatFeedResponse;
    },
    staleTime: 15_000,
    refetchInterval: pollMs,
    refetchIntervalInBackground: false
  });

  const data = feedQuery.data;
  const items = useMemo(() => data?.items ?? [], [data?.items]);
  const total = data?.total ?? 0;
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.max(1, Math.ceil(total / limit));

  const typeCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const row of data?.summary.byType ?? []) m.set(row.signal_type, row.count);
    return m;
  }, [data?.summary.byType]);

  const resetPage = () => setOffset(0);

  const toggleVendor = useCallback((key: string) => {
    setVendorFilter((prev) => (prev.includes(key) ? prev.filter((x) => x !== key) : [...prev, key]));
    resetPage();
  }, []);

  const sendDigest = async () => {
    setDigestPending(true);
    setDigestMsg(null);
    setDigestPrep({ phase: "preparing", total: 0, done: 0 });
    try {
      // 1) Prepare: enqueue LLM enrich for digest CVEs and show progress.
      const prep = await apiFetch("/api/stats/threat-digest/prepare", { method: "POST" });
      const prepBody = (await prep.json()) as { ok?: boolean; jobId?: string; total?: number; enqueued?: number; error?: string };
      if (!prep.ok || !prepBody.ok || !prepBody.jobId) throw new Error(prepBody.error ?? `HTTP ${prep.status}`);

      const jobId = prepBody.jobId;
      const total = Number(prepBody.total ?? 0);
      setDigestPrep({ phase: "preparing", total, done: 0 });
      if (total > 0) setDigestMsg(`Подготовка дайджеста: 0/${total} (enqueued ${prepBody.enqueued ?? 0})`);

      // 2) Poll status for a limited time (avoid hanging forever).
      const deadlineMs = Date.now() + 8 * 60_000;
      let done = 0;
      let completed = total <= 0;
      while (Date.now() < deadlineMs) {
        const st = await apiFetch(`/api/stats/threat-digest/prepare/status?jobId=${encodeURIComponent(jobId)}`, {
          cache: "no-store"
        });
        const stBody = (await st.json()) as { ok?: boolean; total?: number; done?: number; completed?: boolean; error?: string };
        if (!st.ok || !stBody.ok) throw new Error(stBody.error ?? `HTTP ${st.status}`);
        done = Number(stBody.done ?? 0);
        const t = Number(stBody.total ?? total);
        setDigestPrep({ phase: "preparing", total: t, done });
        setDigestMsg(`Подготовка дайджеста: ${done}/${t}`);
        if (stBody.completed) {
          completed = true;
          break;
        }
        await new Promise((r) => setTimeout(r, 1500));
      }
      if (!completed) {
        throw new Error(
          `Подготовка не завершена за 8 мин (${done}/${total}). Дайджест не отправлен — дождитесь LLM или повторите позже.`
        );
      }

      // 3) Send digest only after preparation completed.
      setDigestPrep((cur) => ({ ...cur, phase: "sending" }));
      const res = await apiFetch("/api/stats/threat-digest/telegram", { method: "POST" });
      const body = (await res.json()) as { ok?: boolean; sent?: number; pdf?: { ok?: boolean }; error?: string };
      if (!res.ok || !body.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
      setDigestMsg(`Digest отправлен: ${body.sent ?? 1} сообщ. + PDF${body.pdf?.ok === false ? " (PDF не удалось)" : ""}`);
    } catch (e) {
      setDigestMsg(e instanceof Error ? e.message : "Ошибка отправки");
    } finally {
      setDigestPending(false);
      setDigestPrep((cur) => ({ ...cur, phase: "idle" }));
    }
  };

  const createCase = async (item: ThreatFeedResponse["items"][number]) => {
    setCasePending(item.cve_id);
    setCaseMsg(null);
    try {
      const r = await createVocCaseFromRef({
        refKey: cveRefKey(item.cve_id),
        source: "cve",
        refId: item.cve_id,
        title: `Threat: ${item.cve_id}`,
        subtitle: exploitSignalLabel(item.signal_type),
        vocPriority: threatToVocPriority(item.threat_score),
        vocReasons: buildThreatVocReasons(item),
        linkedCveIds: [item.cve_id],
        createTask: true,
        vendorKey: item.vendor_key ?? item.vendor?.toLowerCase(),
        vendorDisplay: item.vendor ?? undefined,
        productDisplay: item.product ?? undefined,
        productKeyNorm: item.product?.toLowerCase()
      });
      setCaseMsg(r.deduped ? `Кейс уже есть для ${item.cve_id}` : `VOC кейс создан${r.taskId ? " + задача" : ""}`);
      void queryClient.invalidateQueries({ queryKey: ["voc"] });
    } catch (e) {
      setCaseMsg(e instanceof Error ? e.message : "Не удалось создать кейс");
    } finally {
      setCasePending(null);
    }
  };

  const activeWatchlist = (watchlistQuery.data ?? []).filter((w) => w.active);

  const itemKey = useCallback((it: ThreatFeedResponse["items"][number], index = 0) => {
    return [it.cve_id, it.time_bucket || "", it.signal_type, String(index)].join(":");
  }, []);

  const groupedSections = useMemo(() => {
    const buckets = data?.summary.buckets;
    return TIME_BUCKET_META.map((meta) => {
      const fromGroups = data?.groups?.[meta.key];
      const list =
        fromGroups?.items ??
        items.filter((it) => (it.time_bucket || "older") === meta.key);
      const total = fromGroups?.total ?? buckets?.[meta.key] ?? list.length;
      return { ...meta, items: list, total };
    }).filter((sec) => sec.total > 0 || sec.items.length > 0);
  }, [data?.groups, data?.summary.buckets, items]);

  // Smooth live-updates: highlight newly appeared rows for a few seconds.
  const prevKeysRef = useRef<Set<string>>(new Set());
  const [flashKeys, setFlashKeys] = useState<Set<string>>(new Set());
  const prevSeenRef = useRef<Map<string, string>>(new Map());
  const [bumpKeys, setBumpKeys] = useState<Set<string>>(new Set());
  useEffect(() => {
    const next = new Set(items.map((it, i) => itemKey(it, i)));
    const prev = prevKeysRef.current;
    const appeared: string[] = [];
    for (const k of next) if (!prev.has(k)) appeared.push(k);
    prevKeysRef.current = next;
    if (appeared.length === 0) return;
    setFlashKeys((cur) => new Set([...cur, ...appeared]));
    const t = setTimeout(() => {
      setFlashKeys((cur) => {
        const n = new Set(cur);
        for (const k of appeared) n.delete(k);
        return n;
      });
    }, 4500);
    return () => clearTimeout(t);
  }, [items, itemKey]);

  // If an existing row changes (e.g. last_seen_at bumps), add a small bump animation.
  useEffect(() => {
    const prevSeen = prevSeenRef.current;
    const changed: string[] = [];
    for (let i = 0; i < items.length; i++) {
      const it = items[i]!;
      const k = itemKey(it, i);
      const seen = String(it.last_seen_at ?? "");
      const prevVal = prevSeen.get(k);
      if (prevVal != null && prevVal !== seen) changed.push(k);
      prevSeen.set(k, seen);
    }
    if (!changed.length) return;
    setBumpKeys((cur) => new Set([...cur, ...changed]));
    const t = setTimeout(() => {
      setBumpKeys((cur) => {
        const n = new Set(cur);
        for (const k of changed) n.delete(k);
        return n;
      });
    }, 1200);
    return () => clearTimeout(t);
  }, [items, itemKey]);

  return (
    <div className="space-y-4">
      <div className="glass rounded-2xl p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 text-sm font-medium">
              <Flame className="h-4 w-4 text-warn" />
              Threat Intelligence
            </div>
            <p className="mt-1 max-w-2xl text-xs leading-relaxed text-muted">
              Оперативная доска сигналов: группы по реальному first_seen (24ч / 7д), без «каши» от TI sync.
              Одна карточка на CVE, время — момент появления сигнала.
            </p>
            {feedQuery.dataUpdatedAt ? (
              <div className="mt-1 text-[10px] text-muted">
                Обновлено {fmtRelativeTs(new Date(feedQuery.dataUpdatedAt).toISOString())}
              </div>
            ) : null}
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              disabled={digestPending}
              onClick={() => void sendDigest()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-accent/30 bg-accent/10 px-2.5 py-1 text-[11px] text-fg/90 hover:bg-accent/15 disabled:opacity-50"
            >
              <Send className="h-3.5 w-3.5" />
              Суточный TG digest
            </button>
            {(
              [
                ["vckev_only", "VCK-only"],
                ["epss_spike", "EPSS spike"],
                ["has_poc", "PoC"],
                ["has_public_exploit", "Exploit"]
              ] as const
            ).map(([key, label]) => (
              <button
                key={key}
                type="button"
                onClick={() => onFilter?.(key)}
                className="rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-fg/85 hover:bg-slate-100 dark:border-border dark:bg-black/20"
                title={EXPLOIT_RADAR_FILTER_LABELS[key].hint}
              >
                {label} →
              </button>
            ))}
          </div>
        </div>

        {digestPrep.phase !== "idle" ? (
          <div className="mt-2 rounded-lg border border-border bg-white/60 px-3 py-2 dark:bg-black/20">
            <div className="flex items-center justify-between gap-3 text-[11px]">
              <div className="flex items-center gap-2 text-muted">
                <Sparkles className={cn("h-3.5 w-3.5", digestPrep.phase === "preparing" && "animate-pulse")} />
                <span className="font-medium text-fg/90">
                  {digestPrep.phase === "sending" ? "Отправка дайджеста…" : "Обогащение LLM для дайджеста…"}
                </span>
              </div>
              <div className="tabular-nums text-muted">
                {digestPrep.total > 0 ? (
                  <>
                    {Math.min(digestPrep.done, digestPrep.total)}/{digestPrep.total}
                    <span className="ml-2 text-[10px]">
                      {Math.round((Math.min(digestPrep.done, digestPrep.total) / Math.max(digestPrep.total, 1)) * 100)}%
                    </span>
                  </>
                ) : (
                  <span>—</span>
                )}
              </div>
            </div>
            <div className="mt-2 h-2 overflow-hidden rounded-full bg-slate-200/70 dark:bg-white/10">
              <div
                className={cn(
                  "h-full rounded-full transition-[width] duration-500",
                  digestPrep.phase === "sending" ? "bg-accent" : "bg-warn"
                )}
                style={{
                  width:
                    digestPrep.total > 0
                      ? `${Math.max(
                          3,
                          Math.min(
                            100,
                            (Math.min(digestPrep.done, digestPrep.total) / Math.max(digestPrep.total, 1)) * 100
                          )
                        )}%`
                      : "12%"
                }}
              />
            </div>
          </div>
        ) : null}
        {digestMsg ? <div className="mt-2 text-[11px] text-muted">{digestMsg}</div> : null}
        {caseMsg ? <div className="mt-2 text-[11px] text-accent">{caseMsg}</div> : null}

        {(data?.summary.sinceCount ?? 0) > 0 && sinceVisit ? (
          <div className="mt-3 rounded-lg border border-accent/30 bg-accent/10 px-3 py-2 text-[11px] text-fg/90">
            <span className="font-medium">{data!.summary.sinceCount}</span> новых сигналов с прошлого визита (
            {fmtRelativeTs(sinceVisit)})
          </div>
        ) : null}

        {data?.summary ? (
          <>
            <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-5">
              <PulseStat
                label="Новые 24ч"
                value={data.summary.buckets?.new_24h ?? data.summary.signals24h}
                hint="CVE с новым first_seen за 24ч"
                tone="new"
              />
              <PulseStat
                label="Новые 7д"
                value={data.summary.buckets?.new_7d ?? Math.max(0, data.summary.signals7d - data.summary.signals24h)}
                hint="Только 1–7 дней (без суток)"
              />
              <PulseStat
                label="Обновл. 24ч"
                value={data.summary.buckets?.updated_24h ?? data.summary.updatedSignals24h ?? 0}
                hint="Изменение сигнала за сутки (не TI sync)"
                tone="new"
              />
              <PulseStat label="Hot CVE" value={data.summary.hotCves} tone="hot" />
              <PulseStat label="В выборке" value={data.summary.total} hint="Уникальные CVE в окне" />
            </div>
            {(data.timeline?.length ?? 0) > 0 ? <ActivityTimeline days={data.timeline} /> : null}
            {(data.vendorHeatmap?.length ?? 0) > 0 ? (
              <VendorHeatmap rows={data.vendorHeatmap!} selected={vendorFilter} onSelect={toggleVendor} />
            ) : null}
          </>
        ) : null}
      </div>

      {/* Watchlist bar */}
      <div className="glass rounded-2xl p-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-medium text-fg/85">Watchlist</span>
          <button
            type="button"
            onClick={() => {
              setWatchlistOnly((v) => !v);
              resetPage();
            }}
            className={cn(
              "rounded-full border px-2.5 py-1 text-[11px]",
              watchlistOnly
                ? "border-accent/40 bg-accent/10 text-accent"
                : "border-slate-200 text-muted dark:border-border"
            )}
          >
            Только watchlist VOC
          </button>
          {vendorFilter.length ? (
            <button
              type="button"
              onClick={() => {
                setVendorFilter([]);
                resetPage();
              }}
              className="rounded-full border border-slate-200 px-2 py-0.5 text-[10px] text-muted"
            >
              Сбросить вендоры ×
            </button>
          ) : null}
          {activeWatchlist.slice(0, 8).map((w) => (
            <span
              key={w.id}
              className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[10px] text-muted dark:border-border dark:bg-black/20"
              title={`${w.kind}: ${w.value}`}
            >
              {w.label}
            </span>
          ))}
        </div>
      </div>

      {(data?.hotCves?.length ?? 0) > 0 ? (
        <div className="glass rounded-2xl p-5">
          <div className="mb-3 flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-warn" />
            <div className="text-sm font-medium">Hot CVE</div>
          </div>
          <ul className="grid gap-2 lg:grid-cols-2">
            {data!.hotCves!.map((row) => (
              <li key={row.cve_id}>
                <div className="flex gap-2 rounded-xl border border-slate-200/90 bg-slate-50/80 px-3 py-2.5 dark:border-white/[0.06] dark:bg-black/20">
                  <button
                    type="button"
                    onClick={() => onOpenCve?.(row.cve_id)}
                    className="min-w-0 flex-1 text-left"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sm font-semibold">{row.cve_id}</span>
                      <ThreatScoreBadge score={row.threat_score} />
                    </div>
                    <div className="mt-1.5">
                      <ExploitIntelBadges item={row} compact />
                    </div>
                  </button>
                  <button
                    type="button"
                    title="VOC кейс + задача"
                    disabled={casePending === row.cve_id}
                    onClick={() =>
                      void createCase({
                        cve_id: row.cve_id,
                        signal_type: "vulncheck_kev",
                        source: "hot",
                        url: null,
                        title: null,
                        confidence: "high",
                        first_seen_at: row.latest_signal_at,
                        last_seen_at: row.latest_signal_at,
                        cvss_base: row.cvss_base,
                        epss: row.epss,
                        risk_score: row.risk_score,
                        vckev_only: row.vckev_only,
                        epss_spike: row.epss_spike,
                        has_poc: row.has_poc,
                        has_public_exploit: row.has_public_exploit,
                        cisa_kev: row.cisa_kev,
                        epss_delta_7d: null,
                        threat_score: row.threat_score,
                        is_new: false,
                        vendor: row.vendor,
                        product: row.product
                      })
                    }
                    className="shrink-0 rounded-lg border border-slate-200 p-2 hover:bg-white dark:border-border dark:hover:bg-black/30"
                  >
                    <ClipboardPlus className="h-4 w-4 text-accent" />
                  </button>
                </div>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="glass rounded-2xl p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap gap-1.5">
            {(
              [
                ["24", "24 ч"],
                ["168", "7 д"],
                ["720", "30 д"],
                ["all", "Всё"]
              ] as const
            ).map(([k, label]) => (
              <button
                key={k}
                type="button"
                onClick={() => {
                  setWindowPreset(k);
                  resetPage();
                }}
                className={cn(
                  "rounded-full border px-2.5 py-1 text-[11px]",
                  windowPreset === k
                    ? "border-accent/40 bg-accent/10 text-fg/90"
                    : "border-slate-200 bg-white text-muted dark:border-border dark:bg-black/20"
                )}
              >
                {label}
              </button>
            ))}
            <button
              type="button"
              onClick={() => {
                setNewOnly((v) => !v);
                resetPage();
              }}
              className={cn(
                "rounded-full border px-2.5 py-1 text-[11px]",
                newOnly ? "border-accent/40 bg-accent/10 text-accent" : "border-slate-200 text-muted"
              )}
            >
              Только новые
            </button>
          </div>
          <select
            value={sort}
            onChange={(e) => {
              setSort(e.target.value as ThreatFeedSort);
              resetPage();
            }}
            className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-xs dark:border-border dark:bg-black/20"
          >
            <option value="threat">Threat score</option>
            <option value="recent">Сначала по first_seen</option>
          </select>
        </div>

        <div className="mt-3 flex flex-wrap gap-1.5">
          <button
            type="button"
            onClick={() => {
              setSignalType(null);
              resetPage();
            }}
            className={cn(
              "rounded-full border px-2 py-0.5 text-[10px]",
              signalType == null ? "border-accent/40 bg-accent/10" : "border-slate-200 text-muted"
            )}
          >
            Все типы
          </button>
          {EXPLOIT_SIGNAL_TYPES.map((t) => {
            const n = typeCounts.get(t) ?? 0;
            if (n === 0 && signalType !== t) return null;
            return (
              <button
                key={t}
                type="button"
                onClick={() => {
                  setSignalType(signalType === t ? null : t);
                  resetPage();
                }}
                className={cn(
                  "rounded-full border px-2 py-0.5 text-[10px]",
                  signalType === t ? "border-accent/40 bg-accent/10" : "border-slate-200 text-muted"
                )}
              >
                {exploitSignalLabel(t)}
                {n > 0 ? ` · ${n}` : ""}
              </button>
            );
          })}
        </div>

        {(vendorFilter.length > 0 || watchlistOnly || newOnly || signalType) ? (
          <div className="mt-3 flex flex-wrap items-center gap-2 rounded-lg border border-warn/25 bg-warn/10 px-3 py-2 text-[11px]">
            <span className="text-warn">Активные фильтры:</span>
            {vendorFilter.map((v) => (
              <button
                key={v}
                type="button"
                className="rounded-full border border-warn/30 px-2 py-0.5"
                onClick={() => toggleVendor(v)}
              >
                vendor:{v} ×
              </button>
            ))}
            {watchlistOnly ? <span className="rounded-full border px-2 py-0.5">watchlist</span> : null}
            {newOnly ? <span className="rounded-full border px-2 py-0.5">новые</span> : null}
            {signalType ? <span className="rounded-full border px-2 py-0.5">{exploitSignalLabel(signalType)}</span> : null}
          </div>
        ) : null}

        <div className="mt-4 space-y-4">
          {feedQuery.isLoading ? (
            <div className="text-sm text-muted">Загрузка…</div>
          ) : items.length === 0 ? (
            <div className="space-y-2 text-sm text-muted">
              <div>Нет сигналов под выбранные фильтры.</div>
              {(vendorFilter.length > 0 || watchlistOnly || newOnly || signalType) ? (
                <button
                  type="button"
                  className="rounded-lg border border-accent/30 bg-accent/10 px-3 py-1.5 text-xs text-accent"
                  onClick={() => {
                    setVendorFilter([]);
                    setWatchlistOnly(false);
                    setNewOnly(false);
                    setSignalType(null);
                    resetPage();
                  }}
                >
                  Сбросить все фильтры
                </button>
              ) : null}
            </div>
          ) : (
            groupedSections.map((section) => (
              <section key={section.key} className="space-y-2">
                <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-slate-200/80 pb-1.5 dark:border-white/[0.06]">
                  <div>
                    <div className="text-[12px] font-semibold text-fg/90">{section.label}</div>
                    <div className="text-[10px] text-muted">{section.hint}</div>
                  </div>
                  <div className="tabular-nums text-[11px] text-muted">
                    {section.items.length}
                    {section.total > section.items.length ? ` / ${section.total}` : ""} CVE
                  </div>
                </div>
                {section.items.length === 0 ? (
                  <div className="text-[11px] text-muted">На этой странице нет карточек этой группы.</div>
                ) : (
                  section.items.map((it, i) => {
                    const k = itemKey(it, i);
                    const when = signalDisplayTime(it);
                    return (
                      <article
                        key={k}
                        className={cn(
                          "rounded-xl border px-3 py-2.5 transition-[transform,box-shadow] duration-300",
                          flashKeys.has(k) && "ring-2 ring-accent/30 shadow-sm",
                          flashKeys.has(k) && "ti-enter",
                          bumpKeys.has(k) && "ti-bump",
                          it.is_new
                            ? "border-accent/25 bg-accent/[0.04]"
                            : it.is_updated
                              ? "border-warn/20 bg-warn/[0.04]"
                              : "border-slate-200/90 bg-slate-50/80 dark:border-white/[0.06] dark:bg-black/20"
                        )}
                      >
                        <div className="flex flex-wrap items-start justify-between gap-2">
                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <button
                                type="button"
                                onClick={() => onOpenCve?.(it.cve_id)}
                                className="font-mono text-xs font-semibold text-accent hover:underline"
                              >
                                {it.cve_id}
                              </button>
                              <ThreatScoreBadge score={it.threat_score} />
                              {it.is_new ? (
                                <span className="rounded-full border border-accent/35 bg-accent/10 px-2 py-0.5 text-[10px] font-medium text-accent">
                                  NEW 24ч
                                </span>
                              ) : it.is_updated ? (
                                <span className="rounded-full border border-warn/35 bg-warn/10 px-2 py-0.5 text-[10px] text-warn">
                                  UPD 24ч
                                </span>
                              ) : section.key === "new_7d" ? (
                                <span className="rounded-full border border-slate-300 bg-white/70 px-2 py-0.5 text-[10px] text-muted dark:border-border dark:bg-black/20">
                                  NEW 7д
                                </span>
                              ) : null}
                              <span className="rounded-full border border-accent/30 bg-accent/10 px-2 py-0.5 text-[10px] text-accent">
                                {exploitSignalLabel(it.signal_type)}
                              </span>
                              {(it.signal_count ?? 1) > 1 ? (
                                <span className="text-[10px] text-muted">{it.signal_count} сигналов</span>
                              ) : null}
                            </div>
                            <div className="mt-1.5 flex flex-wrap items-center gap-2">
                              <ExploitIntelBadges
                                item={{
                                  exploit_known: it.cisa_kev,
                                  vckev_only: it.vckev_only,
                                  epss_spike: it.epss_spike,
                                  epss_delta_7d: it.epss_delta_7d,
                                  has_poc: it.has_poc,
                                  has_public_exploit: it.has_public_exploit
                                }}
                                compact
                              />
                              <EpssSparkline values={it.epss_sparkline} />
                            </div>
                          </div>
                          <div className="flex shrink-0 items-start gap-1">
                            <button
                              type="button"
                              title="VOC кейс + задача"
                              disabled={casePending === it.cve_id}
                              onClick={() => void createCase(it)}
                              className="rounded-lg border border-slate-200 p-1.5 hover:bg-white dark:border-border dark:hover:bg-black/30"
                            >
                              <ClipboardPlus className="h-3.5 w-3.5 text-accent" />
                            </button>
                            <div className="min-w-[7.5rem] text-right text-[10px] text-muted">
                              <div className="text-fg/80">{fmtRelativeTs(when.primary)}</div>
                              <div className="opacity-80">{when.label}</div>
                              {when.secondary ? (
                                <div className="mt-0.5 opacity-70">впервые {fmtRelativeTs(when.secondary)}</div>
                              ) : null}
                            </div>
                          </div>
                        </div>
                        <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted">
                          {it.vendor ? (
                            <span className="text-fg/80">
                              {it.vendor}
                              {it.product ? ` / ${it.product}` : ""}
                            </span>
                          ) : null}
                          <span>
                            CVSS <span className="font-mono text-fg/80">{it.cvss_base ?? "—"}</span>
                          </span>
                          <span>
                            EPSS <span className="font-mono text-fg/80">{fmtEpssPct(it.epss) ?? "—"}</span>
                            {it.epss_delta_7d != null ? (
                              <span className="ml-1">({fmtEpssDelta(it.epss_delta_7d)})</span>
                            ) : null}
                          </span>
                          <span>
                            Risk <span className="font-mono text-fg/80">{it.risk_score ?? "—"}</span>
                          </span>
                        </div>
                        {it.url || it.title ? (
                          <div className="mt-1.5 text-[11px]">
                            {it.url ? (
                              <a href={it.url} target="_blank" rel="noreferrer" className="text-fg/85 hover:underline">
                                {it.title?.trim() || it.url}
                              </a>
                            ) : (
                              it.title
                            )}
                          </div>
                        ) : null}
                      </article>
                    );
                  })
                )}
              </section>
            ))
          )}
        </div>

        {pages > 1 ? (
          <div className="mt-4 flex items-center justify-between text-xs">
            <button
              type="button"
              disabled={offset <= 0}
              onClick={() => setOffset((o) => Math.max(0, o - limit))}
              className="rounded-lg border px-2 py-1 disabled:opacity-40"
            >
              Назад
            </button>
            <span className="text-muted">
              {page}/{pages} · {total.toLocaleString("ru-RU")}
            </span>
            <button
              type="button"
              disabled={offset + limit >= total}
              onClick={() => setOffset((o) => o + limit)}
              className="rounded-lg border px-2 py-1 disabled:opacity-40"
            >
              Далее
            </button>
          </div>
        ) : null}
      </div>
    </div>
  );
}

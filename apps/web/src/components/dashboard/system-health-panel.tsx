"use client";

import { useCallback, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Database,
  Loader2,
  Play,
  RefreshCw,
  RotateCcw,
  Server,
  Trash2,
  Zap
} from "lucide-react";
import { apiFetch } from "@/lib/api-fetch";
import { useAuth } from "@/contexts/auth-context";
import { cn } from "../ui/cn";
import { ReadinessBar, type ReadinessPayload } from "./readiness-bar";

type Tab = "overview" | "queues" | "dlq" | "pipelines" | "actions";

type HealthCheck = {
  name: string;
  url: string;
  ok: boolean;
  status: number | null;
  ms: number;
  error?: string;
};

type ProbeOk = { ok?: boolean; error?: string | null; ms?: number; status?: number | null };

type LlmProbe = ProbeOk & {
  configured?: boolean;
  endpoint?: string | null;
  model?: string | null;
  authReady?: boolean;
  authHint?: string | null;
};

type NvdProbe = ProbeOk & {
  apiProbeOk?: boolean;
  endpoint?: string | null;
  hasApiKey?: boolean;
  ingestStale?: boolean;
  ingestStaleHint?: string | null;
  lastProcessed?: number;
  lastAttemptProcessed?: number;
  watermarkPartial?: boolean;
  watermarkEnd?: string | null;
  watermarkTs?: string | null;
};

type BduProbe = ProbeOk & {
  sourceProbeOk?: boolean;
  endpoint?: string | null;
  recordCount?: number;
  cveLinkCount?: number;
  tlsInsecure?: boolean;
  maxBduId?: string | null;
  lastIngestRecords?: number;
  lastIngestAt?: string | null;
  maxPublicationAt?: string | null;
  lastIngestUsedFallback?: boolean;
  ingestStale?: boolean;
  ingestStaleHint?: string | null;
};

type CoverageHealth = {
  textEngine?: string;
  scoreEnabled?: boolean;
  scoreViaQueue?: boolean;
  enrichViaQueue?: boolean;
  scoreBacklogOn?: boolean;
  enrichBacklogOn?: boolean;
  totalCves?: number;
  scoredCount?: number;
  scoredMissing?: number;
  scoredPct?: number;
  enrichedCount?: number;
  enrichedMissing?: number;
  enrichedPct?: number;
  hot24?: {
    total?: number;
    scored?: number;
    scoredMissing?: number;
    scoredPct?: number;
    enriched?: number;
    enrichedMissing?: number;
    enrichedPct?: number;
  };
  lastScoreAt?: string | null;
  lastEnrichAt?: string | null;
};

type QueueHealth = {
  ok?: boolean;
  error?: string;
  queues?: {
    enrich?: { messages: number; consumers: number };
    score?: { messages: number; consumers: number };
    dlqEnrich?: { messages: number };
    dlqScore?: { messages: number };
  };
  llm?: LlmProbe;
  nvd?: NvdProbe;
  bdu?: BduProbe;
  coverage?: CoverageHealth;
};

type Reconciliation = {
  ok: boolean;
  checkedAt: string;
  sources: Array<{
    source: string;
    count: number;
    lastActivity: string | null;
    lagHours: number | null;
    ok?: boolean;
  }>;
  issues: string[];
};

function fmtTs(iso: string | null | undefined) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

function fmtMs(ms: number) {
  if (!Number.isFinite(ms)) return "—";
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(2)}s`;
}

function StatusPill({ ok, warn }: { ok: boolean; warn?: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium",
        ok && !warn
          ? "border-ok/30 bg-ok/10 text-ok"
          : warn
            ? "border-warn/30 bg-warn/10 text-warn"
            : "border-danger/30 bg-danger/10 text-danger"
      )}
    >
      {ok && !warn ? <CheckCircle2 className="h-3 w-3" /> : <AlertTriangle className="h-3 w-3" />}
      {ok && !warn ? "OK" : warn ? "WARN" : "DOWN"}
    </span>
  );
}

export function SystemHealthPanel({ onOpenSettings }: { onOpenSettings?: () => void }) {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<Tab>("overview");
  const [dlqQueue, setDlqQueue] = useState<"dlq.ai.enrich" | "dlq.ai.score">("dlq.ai.enrich");
  const [actionMsg, setActionMsg] = useState<string | null>(null);
  const [actionErr, setActionErr] = useState<string | null>(null);

  const isAdmin = user?.role === "admin";

  const healthQ = useQuery({
    queryKey: ["system", "health"],
    queryFn: async () => {
      const res = await apiFetch("/api/health", { cache: "no-store" });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "health failed");
      return body as { ok: boolean; checkedAt: string; upstream: string; checks: HealthCheck[] };
    },
    refetchInterval: 30_000
  });

  const queueQ = useQuery({
    queryKey: ["stats", "queue"],
    queryFn: async () => {
      const res = await apiFetch("/api/stats/queue", { cache: "no-store" });
      return (await res.json()) as QueueHealth;
    },
    refetchInterval: 15_000
  });

  const readinessQ = useQuery({
    queryKey: ["stats", "readiness"],
    queryFn: async () => {
      const res = await apiFetch("/api/stats/readiness", { cache: "no-store" });
      return (await res.json()) as ReadinessPayload;
    },
    refetchInterval: (q) => {
      const st = q.state.data?.status;
      if (st === "syncing" || q.state.data?.jobsRunning) return 5_000;
      if (st === "stale") return 10_000;
      return 20_000;
    }
  });

  const reconcileQ = useQuery({
    queryKey: ["stats", "reconciliation"],
    queryFn: async () => {
      const res = await apiFetch("/api/stats/reconciliation", { cache: "no-store" });
      return (await res.json()) as Reconciliation;
    },
    refetchInterval: 60_000
  });

  const opsStatusQ = useQuery({
    queryKey: ["stats", "ops", "status"],
    queryFn: async () => {
      const res = await apiFetch("/api/stats/ops/status", { cache: "no-store" });
      return res.json() as Promise<{ anyRunning?: boolean; jobs?: Record<string, unknown> }>;
    },
    refetchInterval: 5_000
  });

  const tiStatusQ = useQuery({
    queryKey: ["stats", "threat-feed", "refresh", "status"],
    queryFn: async () => {
      const res = await apiFetch("/api/stats/threat-feed/refresh/status", { cache: "no-store" });
      return res.json();
    },
    refetchInterval: 10_000
  });

  const dlqSampleQ = useQuery({
    queryKey: ["stats", "dlq", "sample", dlqQueue],
    enabled: tab === "dlq",
    queryFn: async () => {
      const res = await apiFetch(
        `/api/stats/dlq/sample?queue=${encodeURIComponent(dlqQueue)}&limit=12`,
        { cache: "no-store" }
      );
      return res.json();
    },
    refetchInterval: tab === "dlq" ? 15_000 : false
  });

  const invalidateAll = useCallback(async () => {
    await queryClient.invalidateQueries({ queryKey: ["stats"] });
    await queryClient.invalidateQueries({ queryKey: ["system"] });
  }, [queryClient]);

  const runAction = useCallback(
    async (label: string, fn: () => Promise<Response>, confirmText?: string) => {
      if (confirmText && !window.confirm(confirmText)) return;
      setActionMsg(null);
      setActionErr(null);
      try {
        const res = await fn();
        const body = await res.json().catch(() => ({}));
        const apiFailed = (body as { ok?: unknown }).ok === false;
        if (!res.ok || apiFailed) {
          throw new Error(
            (body as { message?: string; error?: string }).message ??
              (body as { error?: string }).error ??
              `${label} failed (${res.status})`
          );
        }
        setActionMsg((body as { message?: string }).message ?? `${label}: успешно`);
        await invalidateAll();
      } catch (e) {
        setActionErr(e instanceof Error ? e.message : String(e));
      }
    },
    [invalidateAll]
  );

  const tiRefresh = useMutation({
    mutationFn: async () =>
      runAction(
        "Threat Intel refresh",
        () => apiFetch("/api/stats/threat-feed/refresh?force=true", { method: "POST" }),
        "Запустить Threat Intel refresh (VulnCheck KEV + exploit intel)?"
      )
  });
  const epssSync = useMutation({
    mutationFn: async () =>
      runAction(
        "EPSS sync",
        () => apiFetch("/api/stats/ops/epss/sync", { method: "POST" }),
        "Скачать и обновить EPSS feed? Это может занять 1–3 минуты."
      )
  });
  const bduSync = useMutation({
    mutationFn: async () =>
      runAction(
        "BDU sync",
        () => apiFetch("/api/stats/ops/bdu/sync", { method: "POST" }),
        "Загрузить полный реестр БДУ ФСТЭК? Тяжёлая операция (несколько минут)."
      )
  });
  const nvdHot = useMutation({
    mutationFn: async () =>
      runAction(
        "NVD hot sync",
        () => apiFetch("/api/stats/ops/nvd/hot-sync", { method: "POST" }),
        "Догон NVD за последние ~48ч (published)? Без wipe, только upsert."
      )
  });
  const hot24 = useMutation({
    mutationFn: async () =>
      runAction(
        "Hot24 rescore",
        () => apiFetch("/api/stats/ops/hot24/rescore", { method: "POST" }),
        "Поставить в очередь score для CVE за 24ч без свежего risk_score?"
      )
  });
  const dlqRetry = useMutation({
    mutationFn: async () =>
      runAction(
        "DLQ retry",
        () =>
          apiFetch(`/api/stats/dlq/retry?queue=${encodeURIComponent(dlqQueue)}&limit=1000`, {
            method: "POST"
          }),
        `Вернуть до 1000 сообщений из ${dlqQueue} в основную очередь?`
      )
  });
  const dlqClear = useMutation({
    mutationFn: async () =>
      runAction(
        "DLQ clear",
        () =>
          apiFetch(`/api/stats/dlq/clear?queue=${encodeURIComponent(dlqQueue)}&limit=1000`, {
            method: "POST"
          }),
        `УДАЛИТЬ до 1000 сообщений из ${dlqQueue}? Это необратимо.`
      )
  });

  const tabs: { id: Tab; label: string; icon: typeof Activity }[] = [
    { id: "overview", label: "Обзор", icon: Activity },
    { id: "queues", label: "Очереди", icon: Server },
    { id: "dlq", label: "DLQ", icon: AlertTriangle },
    { id: "pipelines", label: "Конвейеры", icon: Database },
    { id: "actions", label: "Управление", icon: Zap }
  ];

  const qh = queueQ.data;
  const checks = useMemo(
    () => [...(healthQ.data?.checks ?? [])].sort((a, b) => a.name.localeCompare(b.name)),
    [healthQ.data?.checks]
  );

  const anyOpsPending =
    epssSync.isPending ||
    bduSync.isPending ||
    nvdHot.isPending ||
    hot24.isPending ||
    tiRefresh.isPending ||
    Boolean(opsStatusQ.data?.anyRunning);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-lg font-semibold tracking-tight">
            <Activity className="h-5 w-5 text-accent" />
            Здоровье системы
          </h1>
          <p className="mt-1 max-w-2xl text-xs text-muted">
            Готовность данных после простоя, мониторинг очередей и аккуратный ручной ремонт конвейеров.
            {user?.role ? (
              <span className="ml-2 rounded-md bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] dark:bg-black/30">
                role: {user.role}
              </span>
            ) : null}
          </p>
        </div>
        <button
          type="button"
          onClick={() => {
            void healthQ.refetch();
            void queueQ.refetch();
            void readinessQ.refetch();
            void reconcileQ.refetch();
            void opsStatusQ.refetch();
          }}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-medium shadow-sm hover:bg-slate-50 dark:border-border dark:bg-black/25 dark:hover:bg-black/35"
        >
          <RefreshCw className={cn("h-3.5 w-3.5", healthQ.isFetching && "animate-spin")} />
          Обновить всё
        </button>
      </div>

      <ReadinessBar data={readinessQ.data} loading={readinessQ.isLoading} />

      {(actionMsg || actionErr) && (
        <div
          className={cn(
            "rounded-xl border px-4 py-3 text-sm",
            actionErr ? "border-danger/30 bg-danger/10 text-danger" : "border-ok/30 bg-ok/10 text-ok"
          )}
        >
          {actionErr ?? actionMsg}
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-medium",
              tab === t.id
                ? "border-accent/40 bg-accent/10 text-fg"
                : "border-slate-200 bg-white text-muted hover:text-fg dark:border-border dark:bg-black/20"
            )}
          >
            <t.icon className="h-3.5 w-3.5" />
            {t.label}
          </button>
        ))}
      </div>

      {tab === "overview" && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-3 rounded-2xl border border-border bg-white p-4 dark:bg-black/15">
            <StatusPill ok={Boolean(healthQ.data?.ok)} />
            <span className="text-xs text-muted">
              upstream: <span className="font-mono text-fg/85">{healthQ.data?.upstream ?? "—"}</span>
            </span>
            <span className="text-xs text-muted">проверено: {fmtTs(healthQ.data?.checkedAt)}</span>
            {anyOpsPending ? (
              <span className="inline-flex items-center gap-1 text-xs text-warn">
                <Loader2 className="h-3 w-3 animate-spin" /> идёт синхронизация
              </span>
            ) : null}
          </div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {checks.map((c) => (
              <div
                key={c.name}
                className={cn(
                  "rounded-xl border p-3",
                  c.ok || c.status === 401
                    ? "border-slate-200 bg-slate-50/80 dark:border-white/[0.06] dark:bg-black/20"
                    : "border-danger/30 bg-danger/10"
                )}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="text-xs font-semibold">{c.name}</div>
                  <StatusPill ok={c.ok || c.status === 401} warn={c.status === 401} />
                </div>
                <div className="mt-2 flex gap-2 text-[10px] text-muted">
                  <span className="font-mono">HTTP {c.status ?? "—"}</span>
                  <span className="font-mono">{fmtMs(c.ms)}</span>
                </div>
                {c.error ? <div className="mt-1 text-[10px] text-danger">{c.error}</div> : null}
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === "queues" && (
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {(
              [
                ["ai.enrich", qh?.queues?.enrich?.messages, qh?.queues?.enrich?.consumers, qh?.coverage?.enrichViaQueue !== false],
                ["ai.score", qh?.queues?.score?.messages, qh?.queues?.score?.consumers, qh?.coverage?.scoreViaQueue === true],
                ["dlq.ai.enrich", qh?.queues?.dlqEnrich?.messages, null, true],
                ["dlq.ai.score", qh?.queues?.dlqScore?.messages, null, qh?.coverage?.scoreViaQueue === true]
              ] as const
            ).map(([name, depth, consumers, active]) => (
              <div
                key={name}
                className={cn(
                  "rounded-xl border p-4",
                  active
                    ? "border-slate-200 bg-white dark:border-border dark:bg-black/15"
                    : "border-dashed border-slate-200 bg-slate-50/70 dark:border-border dark:bg-black/10"
                )}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="font-mono text-[11px] text-muted">{name}</div>
                  {!active ? (
                    <span className="rounded-md border border-border/70 px-1.5 py-0.5 text-[9px] uppercase tracking-wide text-muted">
                      idle
                    </span>
                  ) : null}
                </div>
                <div className="mt-1 text-2xl font-semibold tabular-nums">
                  {typeof depth === "number" ? depth.toLocaleString() : "—"}
                </div>
                {consumers != null ? (
                  <div className="mt-1 text-[10px] text-muted">consumers: {consumers}</div>
                ) : null}
                {!active ? (
                  <div className="mt-1 text-[10px] text-muted">
                    {name.includes("score")
                      ? "score пишется inline — очередь не нужна"
                      : "очередь не используется"}
                  </div>
                ) : null}
              </div>
            ))}
          </div>

          <div className="grid gap-3 lg:grid-cols-2">
            <CoverageStatusCard
              title="Risk score"
              ok={Boolean(qh?.coverage?.scoreEnabled) && (qh?.coverage?.scoredMissing ?? 0) === 0}
              warn={
                qh?.coverage?.scoreEnabled === false ||
                (Boolean(qh?.coverage?.scoreEnabled) &&
                  (qh?.coverage?.scoredMissing ?? 0) > 0 &&
                  (qh?.coverage?.scoreBacklogOn ?? false))
              }
              pct={qh?.coverage?.scoredPct}
              filled={qh?.coverage?.scoredCount}
              total={qh?.coverage?.totalCves}
              missing={qh?.coverage?.scoredMissing}
              hotPct={qh?.coverage?.hot24?.scoredPct}
              hotFilled={qh?.coverage?.hot24?.scored}
              hotTotal={qh?.coverage?.hot24?.total}
              lastAt={qh?.coverage?.lastScoreAt}
              meta={[
                qh?.coverage?.scoreEnabled === false
                  ? "выключен (AI_SCORE_ENABLED=false)"
                  : qh?.coverage?.scoreViaQueue
                    ? "режим: очередь ai.score"
                    : "режим: inline",
                qh?.coverage?.scoreBacklogOn ? "backlog: on" : "backlog: off"
              ]}
            />
            <CoverageStatusCard
              title="Карточки (текст)"
              ok={(qh?.coverage?.enrichedMissing ?? 0) === 0 && (qh?.coverage?.totalCves ?? 0) > 0}
              warn={
                (qh?.coverage?.enrichedMissing ?? 0) > 0 && (qh?.coverage?.enrichBacklogOn ?? false)
              }
              pct={qh?.coverage?.enrichedPct}
              filled={qh?.coverage?.enrichedCount}
              total={qh?.coverage?.totalCves}
              missing={qh?.coverage?.enrichedMissing}
              hotPct={qh?.coverage?.hot24?.enrichedPct}
              hotFilled={qh?.coverage?.hot24?.enriched}
              hotTotal={qh?.coverage?.hot24?.total}
              lastAt={qh?.coverage?.lastEnrichAt}
              meta={[
                `TEXT_ENGINE=${qh?.coverage?.textEngine ?? "—"}`,
                qh?.coverage?.enrichViaQueue ? "режим: очередь ai.enrich" : "режим: inline",
                qh?.coverage?.enrichBacklogOn ? "backlog: on" : "backlog: off"
              ]}
            />
          </div>

          {qh?.llm ? (
            <div className="rounded-xl border border-slate-200 bg-white p-4 text-[11px] dark:border-border dark:bg-black/15">
              <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold uppercase tracking-wide">LLM</span>
                  <StatusPill
                    ok={qh.llm.configured !== false && Boolean(qh.llm.ok)}
                    warn={qh.llm.status === 429}
                  />
                </div>
                <span className="font-mono tabular-nums text-muted">
                  {typeof qh.llm.ms === "number" ? fmtMs(qh.llm.ms) : "—"}
                </span>
              </div>
              {qh.llm.endpoint ? (
                <div className="truncate font-mono text-[10px] text-fg/80">{qh.llm.endpoint}</div>
              ) : null}
              <div className="mt-1 flex flex-wrap gap-2 text-[10px] text-muted">
                {qh.llm.model ? <span>model: {qh.llm.model}</span> : null}
                {typeof qh.llm.status === "number" ? <span>HTTP {qh.llm.status}</span> : null}
                {qh.llm.error ? <span className="text-danger">{qh.llm.error}</span> : null}
              </div>
              {qh.llm.authReady === false && qh.llm.authHint ? (
                <div className="mt-2 rounded-lg border border-warn/30 bg-warn/10 px-2 py-1.5 text-[10px] text-warn">
                  {qh.llm.authHint}
                </div>
              ) : null}
            </div>
          ) : null}

          {qh?.nvd ? (
            <div className="rounded-xl border border-slate-200 bg-white p-4 text-[11px] dark:border-border dark:bg-black/15">
              <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold uppercase tracking-wide">NVD</span>
                  <StatusPill ok={Boolean(qh.nvd.ok)} warn={qh.nvd.ingestStale || qh.nvd.apiProbeOk === false} />
                </div>
                <span className="font-mono tabular-nums text-muted">
                  {typeof qh.nvd.ms === "number" ? fmtMs(qh.nvd.ms) : "—"}
                </span>
              </div>
              {qh.nvd.endpoint ? (
                <div className="truncate font-mono text-[10px] text-fg/80">{qh.nvd.endpoint}</div>
              ) : null}
              <div className="mt-1 flex flex-wrap gap-2 text-[10px] text-muted">
                <span>{qh.nvd.hasApiKey ? "API key: да" : "API key: нет"}</span>
                {typeof qh.nvd.status === "number" ? <span>HTTP {qh.nvd.status}</span> : null}
                {typeof qh.nvd.lastProcessed === "number" ? (
                  <span>
                    посл. цикл: {qh.nvd.lastProcessed.toLocaleString()} CVE
                    {qh.nvd.watermarkPartial ? " (частично)" : ""}
                  </span>
                ) : typeof qh.nvd.lastAttemptProcessed === "number" ? (
                  <span>посл. попытка: {qh.nvd.lastAttemptProcessed.toLocaleString()} CVE</span>
                ) : null}
                {qh.nvd.watermarkEnd ? <span>окно до: {fmtTs(qh.nvd.watermarkEnd)}</span> : null}
                {qh.nvd.watermarkTs ? <span>запись: {fmtTs(qh.nvd.watermarkTs)}</span> : null}
              </div>
              {qh.nvd.error ? (
                <div className={cn("mt-1 text-[10px]", qh.nvd.ok ? "text-warn" : "text-danger")}>
                  {qh.nvd.error}
                </div>
              ) : null}
              {qh.nvd.ingestStale && qh.nvd.ingestStaleHint ? (
                <div className="mt-2 rounded-lg border border-warn/30 bg-warn/10 px-2 py-1.5 text-[10px] text-warn">
                  {qh.nvd.ingestStaleHint}
                </div>
              ) : null}
            </div>
          ) : null}

          {qh?.bdu ? (
            <div className="rounded-xl border border-teal-200/80 bg-teal-50/50 p-4 text-[11px] dark:border-teal-900/40 dark:bg-teal-950/20">
              <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold uppercase tracking-wide">БДУ ФСТЭК</span>
                  <StatusPill ok={Boolean(qh.bdu.ok)} warn={qh.bdu.ingestStale || qh.bdu.sourceProbeOk === false} />
                </div>
                <span className="font-mono tabular-nums text-muted">
                  {typeof qh.bdu.ms === "number" ? fmtMs(qh.bdu.ms) : "—"}
                </span>
              </div>
              {qh.bdu.endpoint ? (
                <div className="truncate font-mono text-[10px] text-fg/80">{qh.bdu.endpoint}</div>
              ) : null}
              <div className="mt-1 flex flex-wrap gap-2 text-[10px] text-muted">
                {typeof qh.bdu.recordCount === "number" ? (
                  <span>записей: {qh.bdu.recordCount.toLocaleString()}</span>
                ) : null}
                {typeof qh.bdu.cveLinkCount === "number" ? (
                  <span>связей CVE: {qh.bdu.cveLinkCount.toLocaleString()}</span>
                ) : null}
                {typeof qh.bdu.status === "number" ? <span>HTTP {qh.bdu.status}</span> : null}
                {qh.bdu.tlsInsecure ? <span className="text-warn">TLS insecure</span> : null}
                {qh.bdu.maxBduId ? <span>max id: {qh.bdu.maxBduId}</span> : null}
                {typeof qh.bdu.lastIngestRecords === "number" ? (
                  <span>посл. цикл: {qh.bdu.lastIngestRecords.toLocaleString()}</span>
                ) : null}
                {qh.bdu.lastIngestAt ? <span>ingest: {fmtTs(qh.bdu.lastIngestAt)}</span> : null}
                {qh.bdu.maxPublicationAt ? <span>публ.: {fmtTs(qh.bdu.maxPublicationAt)}</span> : null}
                {qh.bdu.lastIngestUsedFallback ? <span className="text-warn">зеркало</span> : null}
              </div>
              {qh.bdu.error ? (
                <div className={cn("mt-1 text-[10px]", qh.bdu.ok ? "text-warn" : "text-danger")}>
                  {qh.bdu.error}
                </div>
              ) : null}
              {qh.bdu.ingestStale && qh.bdu.ingestStaleHint ? (
                <div className="mt-2 rounded-lg border border-warn/30 bg-warn/10 px-2 py-1.5 text-[10px] text-warn">
                  {qh.bdu.ingestStaleHint}
                </div>
              ) : null}
            </div>
          ) : null}

          {!qh?.ok && (
            <div className="text-sm text-danger">{qh?.error ? String(qh.error) : "Очереди недоступны"}</div>
          )}
        </div>
      )}

      {tab === "dlq" && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={dlqQueue}
              onChange={(e) => setDlqQueue(e.target.value as "dlq.ai.enrich" | "dlq.ai.score")}
              className="rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-xs dark:border-border dark:bg-black/20"
            >
              <option value="dlq.ai.enrich">dlq.ai.enrich</option>
              <option value="dlq.ai.score">dlq.ai.score</option>
            </select>
            {isAdmin ? (
              <>
                <button
                  type="button"
                  disabled={dlqRetry.isPending}
                  onClick={() => dlqRetry.mutate()}
                  className="inline-flex items-center gap-1 rounded-lg border border-accent/30 bg-accent/10 px-3 py-1.5 text-xs hover:bg-accent/15 disabled:opacity-50"
                >
                  {dlqRetry.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <RotateCcw className="h-3 w-3" />}
                  Повторить до 1000
                </button>
                <button
                  type="button"
                  disabled={dlqClear.isPending}
                  onClick={() => dlqClear.mutate()}
                  className="inline-flex items-center gap-1 rounded-lg border border-danger/30 bg-danger/10 px-3 py-1.5 text-xs text-danger hover:bg-danger/15 disabled:opacity-50"
                >
                  {dlqClear.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3 w-3" />}
                  Очистить до 1000
                </button>
              </>
            ) : (
              <span className="text-[10px] text-warn">Только admin может управлять DLQ</span>
            )}
          </div>
          <pre className="max-h-96 overflow-auto rounded-xl border border-border bg-black/5 p-3 font-mono text-[10px] dark:bg-black/25">
            {dlqSampleQ.isFetching ? "Загрузка…" : JSON.stringify(dlqSampleQ.data ?? {}, null, 2)}
          </pre>
        </div>
      )}

      {tab === "pipelines" && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <StatusPill ok={Boolean(reconcileQ.data?.ok)} />
            <span className="text-xs text-muted">сверка: {fmtTs(reconcileQ.data?.checkedAt)}</span>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            {(reconcileQ.data?.sources ?? readinessQ.data?.sources ?? []).map((s) => (
              <div
                key={s.source}
                className="rounded-xl border border-slate-200 bg-white p-4 dark:border-border dark:bg-black/15"
              >
                <div className="flex items-center justify-between">
                  <div className="text-sm font-semibold uppercase">{s.source}</div>
                  <StatusPill ok={s.ok !== false} />
                </div>
                <dl className="mt-2 space-y-1 text-[11px]">
                  <div className="flex justify-between">
                    <dt className="text-muted">Записей</dt>
                    <dd className="font-mono tabular-nums">{s.count.toLocaleString()}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-muted">Последняя активность</dt>
                    <dd className="font-mono text-[10px]">{fmtTs(s.lastActivity)}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-muted">Lag</dt>
                    <dd className="font-mono">{s.lagHours != null ? `${s.lagHours.toFixed(1)}h` : "—"}</dd>
                  </div>
                </dl>
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === "actions" && (
        <div className="space-y-4">
          {!isAdmin && (
            <div className="rounded-xl border border-warn/30 bg-warn/10 px-4 py-3 text-xs text-warn">
              Для управления нужна роль <strong>admin</strong>. Текущая: {user?.role ?? "unknown"}.
              {onOpenSettings ? (
                <button type="button" onClick={onOpenSettings} className="ml-2 underline">
                  Настройки
                </button>
              ) : null}
            </div>
          )}
          <p className="text-[11px] text-muted">
            После долгого простоя: <strong>NVD hot</strong> → <strong>EPSS</strong> → <strong>BDU</strong> →{" "}
            <strong>Threat Intel</strong> → <strong>Hot24 rescore</strong>. Статус-бар сверху покажет «Можно
            пользоваться».
          </p>
          <div className="grid gap-3 sm:grid-cols-2">
            <ActionCard
              title="NVD hot sync (~48ч)"
              desc="Догон published CVE без wipe"
              disabled={!isAdmin || anyOpsPending}
              pending={nvdHot.isPending}
              onClick={() => nvdHot.mutate()}
              status={opsStatusQ.data?.jobs?.nvd_hot}
            />
            <ActionCard
              title="EPSS sync"
              desc="Скачать актуальный EPSS feed"
              disabled={!isAdmin || anyOpsPending}
              pending={epssSync.isPending}
              onClick={() => epssSync.mutate()}
              status={opsStatusQ.data?.jobs?.epss}
            />
            <ActionCard
              title="BDU sync"
              desc="Полный реестр ФСТЭК (тяжёлая)"
              disabled={!isAdmin || anyOpsPending}
              pending={bduSync.isPending}
              onClick={() => bduSync.mutate()}
              status={opsStatusQ.data?.jobs?.bdu}
            />
            <ActionCard
              title="Threat Intel refresh"
              desc="VulnCheck KEV + exploit intel"
              disabled={!isAdmin || anyOpsPending}
              pending={tiRefresh.isPending}
              onClick={() => tiRefresh.mutate()}
              status={tiStatusQ.data}
            />
            <ActionCard
              title="Hot24 rescore"
              desc="Score queue для CVE за 24ч"
              disabled={!isAdmin || anyOpsPending}
              pending={hot24.isPending}
              onClick={() => hot24.mutate()}
              status={opsStatusQ.data?.jobs?.hot24_score}
            />
            <ActionCard
              title="Обновить DLQ sample"
              desc="Перечитать сообщения в выбранной DLQ"
              disabled={dlqSampleQ.isFetching}
              pending={dlqSampleQ.isFetching}
              onClick={() => void dlqSampleQ.refetch()}
              icon={RefreshCw}
            />
          </div>
        </div>
      )}
    </div>
  );
}

function CoverageStatusCard({
  title,
  ok,
  warn,
  pct,
  filled,
  total,
  missing,
  hotPct,
  hotFilled,
  hotTotal,
  lastAt,
  meta
}: {
  title: string;
  ok: boolean;
  warn?: boolean;
  pct?: number;
  filled?: number;
  total?: number;
  missing?: number;
  hotPct?: number;
  hotFilled?: number;
  hotTotal?: number;
  lastAt?: string | null;
  meta?: string[];
}) {
  const bar = typeof pct === "number" && Number.isFinite(pct) ? Math.max(0, Math.min(100, pct)) : 0;
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-border dark:bg-black/15">
      <div className="flex items-center justify-between gap-2">
        <div className="text-sm font-semibold">{title}</div>
        <StatusPill ok={ok} warn={warn} />
      </div>
      <div className="mt-2 flex items-end justify-between gap-2">
        <div className="text-2xl font-semibold tabular-nums">
          {typeof pct === "number" ? `${pct}%` : "—"}
        </div>
        <div className="text-[10px] text-muted tabular-nums">
          {typeof filled === "number" && typeof total === "number"
            ? `${filled.toLocaleString()} / ${total.toLocaleString()}`
            : "—"}
        </div>
      </div>
      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-100 dark:bg-white/10">
        <div
          className={cn("h-full rounded-full transition-[width]", ok ? "bg-ok" : warn ? "bg-warn" : "bg-danger")}
          style={{ width: `${Math.max(ok ? 100 : 4, bar)}%` }}
        />
      </div>
      <dl className="mt-2 space-y-1 text-[11px]">
        <div className="flex justify-between gap-2">
          <dt className="text-muted">Без покрытия</dt>
          <dd className="font-mono tabular-nums">{typeof missing === "number" ? missing.toLocaleString() : "—"}</dd>
        </div>
        <div className="flex justify-between gap-2">
          <dt className="text-muted">Hot 24ч</dt>
          <dd className="font-mono tabular-nums">
            {typeof hotPct === "number" && typeof hotFilled === "number" && typeof hotTotal === "number"
              ? `${hotPct}% · ${hotFilled.toLocaleString()}/${hotTotal.toLocaleString()}`
              : "—"}
          </dd>
        </div>
        <div className="flex justify-between gap-2">
          <dt className="text-muted">Последняя активность</dt>
          <dd className="font-mono text-[10px]">{fmtTs(lastAt)}</dd>
        </div>
      </dl>
      {meta?.length ? (
        <div className="mt-2 flex flex-wrap gap-1.5 text-[10px] text-muted">
          {meta.map((m) => (
            <span key={m} className="rounded-md border border-border/70 px-1.5 py-0.5 font-mono">
              {m}
            </span>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function ActionCard({
  title,
  desc,
  disabled,
  pending,
  onClick,
  status,
  icon: Icon = Play
}: {
  title: string;
  desc: string;
  disabled?: boolean;
  pending?: boolean;
  onClick: () => void;
  status?: unknown;
  icon?: typeof Play;
}) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-border dark:bg-black/15">
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="text-sm font-semibold">{title}</div>
          <div className="mt-1 text-[11px] text-muted">{desc}</div>
        </div>
        <button
          type="button"
          disabled={disabled}
          onClick={onClick}
          className="rounded-lg border border-accent/30 bg-accent/10 p-2 hover:bg-accent/15 disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Icon className="h-4 w-4" />}
        </button>
      </div>
      {status != null ? (
        <pre className="mt-3 max-h-24 overflow-auto font-mono text-[9px] text-muted">
          {JSON.stringify(status, null, 2)}
        </pre>
      ) : null}
    </div>
  );
}

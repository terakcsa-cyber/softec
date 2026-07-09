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

type Tab = "overview" | "queues" | "dlq" | "pipelines" | "actions";

type HealthCheck = {
  name: string;
  url: string;
  ok: boolean;
  status: number | null;
  ms: number;
  error?: string;
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
  llm?: Record<string, unknown>;
  nvd?: Record<string, unknown>;
  bdu?: Record<string, unknown>;
};

type Reconciliation = {
  ok: boolean;
  checkedAt: string;
  sources: Array<{
    source: string;
    count: number;
    lastActivity: string | null;
    lagHours: number | null;
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

  const isAdmin = user?.role === "admin" || !user?.role;

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

  const reconcileQ = useQuery({
    queryKey: ["stats", "reconciliation"],
    queryFn: async () => {
      const res = await apiFetch("/api/stats/reconciliation", { cache: "no-store" });
      return (await res.json()) as Reconciliation;
    },
    refetchInterval: 60_000
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

  const runAction = useCallback(
    async (label: string, fn: () => Promise<Response>) => {
      setActionMsg(null);
      setActionErr(null);
      try {
        const res = await fn();
        const body = await res.json().catch(() => ({}));
        if (!res.ok) {
          throw new Error(
            (body as { message?: string; error?: string }).message ??
              (body as { error?: string }).error ??
              `${label} failed (${res.status})`
          );
        }
        setActionMsg(`${label}: успешно`);
        await queryClient.invalidateQueries({ queryKey: ["stats"] });
        await queryClient.invalidateQueries({ queryKey: ["system"] });
      } catch (e) {
        setActionErr(e instanceof Error ? e.message : String(e));
      }
    },
    [queryClient]
  );

  const tiRefresh = useMutation({
    mutationFn: async () =>
      runAction("Threat Intel refresh", () =>
        apiFetch("/api/stats/threat-feed/refresh?force=true", { method: "POST" })
      )
  });

  const dlqRetry = useMutation({
    mutationFn: async () =>
      runAction("DLQ retry", () =>
        apiFetch(`/api/stats/dlq/retry?queue=${encodeURIComponent(dlqQueue)}&limit=1000`, {
          method: "POST"
        })
      )
  });

  const dlqClear = useMutation({
    mutationFn: async () =>
      runAction("DLQ clear", () =>
        apiFetch(`/api/stats/dlq/clear?queue=${encodeURIComponent(dlqQueue)}&limit=1000`, {
          method: "POST"
        })
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

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-lg font-semibold tracking-tight">
            <Activity className="h-5 w-5 text-accent" />
            Здоровье системы
          </h1>
          <p className="mt-1 max-w-2xl text-xs text-muted">
            Мониторинг очередей, интеграций и конвейеров данных. Управление DLQ и перезапуск задач — только для
            администраторов.
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
            void reconcileQ.refetch();
          }}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-medium shadow-sm hover:bg-slate-50 dark:border-border dark:bg-black/25 dark:hover:bg-black/35"
        >
          <RefreshCw className={cn("h-3.5 w-3.5", healthQ.isFetching && "animate-spin")} />
          Обновить всё
        </button>
      </div>

      {(actionMsg || actionErr) && (
        <div
          className={cn(
            "rounded-xl border px-4 py-3 text-sm",
            actionErr
              ? "border-danger/30 bg-danger/10 text-danger"
              : "border-ok/30 bg-ok/10 text-ok"
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
            {!checks.length && healthQ.isLoading ? (
              <div className="text-sm text-muted">Загрузка проверок…</div>
            ) : null}
          </div>
        </div>
      )}

      {tab === "queues" && (
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {(
              [
                ["ai.enrich", qh?.queues?.enrich?.messages, qh?.queues?.enrich?.consumers],
                ["ai.score", qh?.queues?.score?.messages, qh?.queues?.score?.consumers],
                ["dlq.ai.enrich", qh?.queues?.dlqEnrich?.messages, null],
                ["dlq.ai.score", qh?.queues?.dlqScore?.messages, null]
              ] as const
            ).map(([name, depth, consumers]) => (
              <div
                key={name}
                className="rounded-xl border border-slate-200 bg-white p-4 dark:border-border dark:bg-black/15"
              >
                <div className="font-mono text-[11px] text-muted">{name}</div>
                <div className="mt-1 text-2xl font-semibold tabular-nums">
                  {typeof depth === "number" ? depth.toLocaleString() : "—"}
                </div>
                {consumers != null ? (
                  <div className="mt-1 text-[10px] text-muted">consumers: {consumers}</div>
                ) : null}
              </div>
            ))}
          </div>

          {["llm", "nvd", "bdu"].map((key) => {
            const probe = qh?.[key as keyof QueueHealth] as Record<string, unknown> | undefined;
            if (!probe) return null;
            const ok = Boolean(probe.ok);
            return (
              <div
                key={key}
                className="rounded-xl border border-slate-200 bg-slate-50/80 p-4 text-[11px] dark:border-border dark:bg-black/20"
              >
                <div className="mb-2 flex items-center justify-between">
                  <span className="font-semibold uppercase tracking-wide">{key}</span>
                  <StatusPill ok={ok} warn={probe.status === 429} />
                </div>
                <pre className="max-h-40 overflow-auto whitespace-pre-wrap font-mono text-[10px] text-fg/80">
                  {JSON.stringify(probe, null, 2)}
                </pre>
              </div>
            );
          })}

          {!qh?.ok && (
            <div className="text-sm text-danger">{qh?.error ? String(qh.error) : "Очереди недоступны"}</div>
          )}
        </div>
      )}

      {tab === "dlq" && (
        <div className="space-y-4">
          <p className="text-xs text-muted">
            Dead Letter Queue — сообщения, которые не удалось обработать. Можно вернуть в основную очередь или удалить.
          </p>
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
          <div className="rounded-xl border border-border bg-black/5 p-3 dark:bg-black/25">
            <pre className="max-h-96 overflow-auto whitespace-pre-wrap font-mono text-[10px]">
              {dlqSampleQ.isFetching
                ? "Загрузка…"
                : JSON.stringify(dlqSampleQ.data ?? {}, null, 2)}
            </pre>
          </div>
        </div>
      )}

      {tab === "pipelines" && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <StatusPill ok={Boolean(reconcileQ.data?.ok)} />
            <span className="text-xs text-muted">сверка: {fmtTs(reconcileQ.data?.checkedAt)}</span>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            {(reconcileQ.data?.sources ?? []).map((s) => (
              <div
                key={s.source}
                className="rounded-xl border border-slate-200 bg-white p-4 dark:border-border dark:bg-black/15"
              >
                <div className="text-sm font-semibold uppercase">{s.source}</div>
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
                    <dd className="font-mono">
                      {s.lagHours != null ? `${s.lagHours.toFixed(1)}h` : "—"}
                    </dd>
                  </div>
                </dl>
              </div>
            ))}
          </div>
          {(reconcileQ.data?.issues ?? []).length > 0 && (
            <div className="rounded-xl border border-warn/30 bg-warn/10 p-4 text-xs text-warn">
              <div className="font-semibold">Проблемы</div>
              <ul className="mt-2 list-inside list-disc">
                {reconcileQ.data?.issues.map((i) => (
                  <li key={i}>{i}</li>
                ))}
              </ul>
            </div>
          )}
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
          <div className="grid gap-3 sm:grid-cols-2">
            <ActionCard
              title="Threat Intel refresh"
              desc="VulnCheck KEV + пересчёт exploit intel"
              disabled={!isAdmin || tiRefresh.isPending}
              onClick={() => tiRefresh.mutate()}
              icon={Play}
              status={tiStatusQ.data}
            />
            <ActionCard
              title="Обновить DLQ sample"
              desc="Перечитать сообщения в выбранной DLQ"
              disabled={dlqSampleQ.isFetching}
              onClick={() => void dlqSampleQ.refetch()}
              icon={RefreshCw}
            />
          </div>
          <div className="rounded-xl border border-dashed border-slate-300 p-4 text-[11px] text-muted dark:border-white/10">
            <strong className="text-fg/80">Скрипты на сервере:</strong>{" "}
            <code className="font-mono">pnpm epss:sync</code>,{" "}
            <code className="font-mono">pnpm rescore:hot24</code>,{" "}
            <code className="font-mono">pnpm dlq:replay:score</code>,{" "}
            <code className="font-mono">pnpm smoke:post-deploy</code>
          </div>
        </div>
      )}
    </div>
  );
}

function ActionCard({
  title,
  desc,
  disabled,
  onClick,
  icon: Icon,
  status
}: {
  title: string;
  desc: string;
  disabled?: boolean;
  onClick: () => void;
  icon: typeof Play;
  status?: unknown;
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
          <Icon className="h-4 w-4" />
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

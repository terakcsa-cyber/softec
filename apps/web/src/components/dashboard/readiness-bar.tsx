"use client";

import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, Clock3, Loader2 } from "lucide-react";
import { cn } from "../ui/cn";

export type ReadinessPayload = {
  ready: boolean;
  status: "ready" | "syncing" | "stale" | "degraded";
  headline: string;
  checkedAt: string;
  staleHours?: number;
  sources: Array<{
    source: string;
    count: number;
    lastActivity: string | null;
    lagHours: number | null;
    ok?: boolean;
    progressPercent?: number;
  }>;
  blockingIssues: string[];
  warnings: string[];
  jobsRunning?: boolean;
  progressPercent?: number;
  etaSeconds?: number;
  etaLabel?: string;
  etaAt?: string | null;
  phase?: string;
};

function fmtLag(h: number | null | undefined) {
  if (h == null || !Number.isFinite(h)) return "—";
  if (h < 1) return `${Math.round(h * 60)}м`;
  if (h < 48) return `${h.toFixed(1)}ч`;
  return `${(h / 24).toFixed(1)}д`;
}

function phaseLabel(phase?: string, status?: string) {
  if (status === "ready") return "Система актуальна";
  if (!phase) return "Оценка состояния…";
  if (phase.startsWith("job:")) {
    const kinds = phase.slice(4).split("+").join(", ");
    return `Идёт операция: ${kinds}`;
  }
  if (phase === "queues") return "Фоновые очереди (не блокируют готовность)";
  if (phase === "awaiting_repair") return "Ожидает ручного ремонта";
  if (phase === "catchup") return "Догоняем источники (NVD / EPSS / BDU / KEV)";
  if (phase === "complete") return "Система актуальна";
  return phase;
}

function useSmoothPercent(target: number) {
  const [value, setValue] = useState(target);
  useEffect(() => {
    let raf = 0;
    const tick = () => {
      setValue((prev) => {
        const next = prev + (target - prev) * 0.18;
        if (Math.abs(target - next) < 0.4) return target;
        raf = requestAnimationFrame(tick);
        return next;
      });
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target]);
  return value;
}

function useCountdown(etaAt?: string | null, etaSeconds?: number) {
  const [left, setLeft] = useState<number | null>(etaSeconds ?? null);
  useEffect(() => {
    if (!etaAt && (etaSeconds == null || etaSeconds <= 0)) {
      setLeft(0);
      return;
    }
    const end = etaAt ? new Date(etaAt).getTime() : Date.now() + (etaSeconds ?? 0) * 1000;
    const update = () => setLeft(Math.max(0, Math.round((end - Date.now()) / 1000)));
    update();
    const id = window.setInterval(update, 1000);
    return () => window.clearInterval(id);
  }, [etaAt, etaSeconds]);
  return left;
}

function fmtLeft(sec: number | null) {
  if (sec == null) return "…";
  if (sec <= 0) return "почти готово";
  if (sec < 60) return `~${sec} с`;
  if (sec < 3600) return `~${Math.max(1, Math.round(sec / 60))} мин`;
  const h = Math.floor(sec / 3600);
  const m = Math.round((sec % 3600) / 60);
  return m > 0 ? `~${h} ч ${m} мин` : `~${h} ч`;
}

export function ReadinessBar({
  data,
  loading,
  compact
}: {
  data?: ReadinessPayload | null;
  loading?: boolean;
  compact?: boolean;
}) {
  const status = data?.status ?? (loading ? "syncing" : "stale");
  const targetPct = data?.progressPercent ?? (status === "ready" ? 100 : loading ? 12 : 0);
  const smoothPct = useSmoothPercent(targetPct);
  const leftSec = useCountdown(data?.etaAt, data?.etaSeconds);
  const etaText = status === "ready" ? "готово" : data?.etaLabel ?? fmtLeft(leftSec);

  const tone =
    status === "ready"
      ? {
          shell: "border-ok/35 bg-gradient-to-br from-ok/15 via-ok/5 to-transparent",
          bar: "from-emerald-400 to-ok",
          chip: "text-ok",
          track: "bg-ok/15"
        }
      : status === "syncing"
        ? {
            shell: "border-accent/35 bg-gradient-to-br from-accent/15 via-accent/5 to-transparent",
            bar: "from-sky-400 to-indigo-500",
            chip: "text-fg",
            track: "bg-accent/15"
          }
        : status === "degraded"
          ? {
              shell: "border-warn/35 bg-gradient-to-br from-warn/15 via-warn/5 to-transparent",
              bar: "from-amber-400 to-orange-500",
              chip: "text-warn",
              track: "bg-warn/15"
            }
          : {
              shell: "border-danger/35 bg-gradient-to-br from-danger/15 via-danger/5 to-transparent",
              bar: "from-rose-400 to-red-500",
              chip: "text-danger",
              track: "bg-danger/15"
            };

  const label =
    status === "ready"
      ? "Готово / Актуально"
      : status === "syncing"
        ? "Синхронизация…"
        : status === "degraded"
          ? "Работает с оговорками"
          : "Устарело / Нужен ремонт";

  const finishLocal = useMemo(() => {
    if (!data?.etaAt || status === "ready") return null;
    try {
      return new Date(data.etaAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    } catch {
      return null;
    }
  }, [data?.etaAt, status]);

  return (
    <div className={cn("rounded-2xl border px-4 py-3.5 shadow-sm", tone.shell)}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className={cn("flex flex-wrap items-center gap-2 text-sm font-semibold", tone.chip)}>
            {status === "ready" ? (
              <CheckCircle2 className="h-4 w-4 shrink-0" />
            ) : status === "syncing" || loading ? (
              <Loader2 className="h-4 w-4 shrink-0 animate-spin" />
            ) : (
              <AlertTriangle className="h-4 w-4 shrink-0" />
            )}
            <span>{label}</span>
            <span className="rounded-full border border-black/5 bg-white/70 px-2 py-0.5 font-mono text-[10px] tabular-nums text-fg/80 dark:border-white/10 dark:bg-black/30">
              {Math.round(smoothPct)}%
            </span>
          </div>
          <p className={cn("mt-1 text-xs text-fg/80", compact && "line-clamp-1")}>
            {data?.headline ?? (loading ? "Проверяем свежесть источников…" : "Нет данных readiness")}
          </p>
          {!compact ? (
            <p className="mt-0.5 text-[10px] text-muted">{phaseLabel(data?.phase, status)}</p>
          ) : null}
        </div>

        <div className="flex shrink-0 flex-col items-end gap-1 text-right">
          <div className="inline-flex items-center gap-1.5 rounded-full border border-black/5 bg-white/70 px-2.5 py-1 text-[11px] font-medium text-fg/85 dark:border-white/10 dark:bg-black/30">
            <Clock3 className="h-3.5 w-3.5 text-muted" />
            <span className="tabular-nums">{etaText}</span>
          </div>
          {finishLocal ? (
            <div className="text-[10px] text-muted">ориентир ~{finishLocal}</div>
          ) : !compact && data?.checkedAt ? (
            <div className="text-[10px] text-muted">{new Date(data.checkedAt).toLocaleString()}</div>
          ) : null}
        </div>
      </div>

      <div className="mt-3">
        <div className={cn("relative h-2.5 overflow-hidden rounded-full", tone.track)}>
          <div
            className={cn(
              "absolute inset-y-0 left-0 rounded-full bg-gradient-to-r transition-[width] duration-500 ease-out",
              tone.bar,
              status === "syncing" && "animate-pulse"
            )}
            style={{ width: `${Math.max(status === "ready" ? 100 : 4, Math.min(100, smoothPct))}%` }}
          />
          {status === "syncing" || loading ? (
            <div className="pointer-events-none absolute inset-0 overflow-hidden rounded-full">
              <div className="absolute inset-y-0 w-1/3 animate-readiness-shimmer bg-gradient-to-r from-transparent via-white/35 to-transparent" />
            </div>
          ) : null}
        </div>
        <div className="mt-1.5 flex items-center justify-between text-[10px] text-muted">
          <span>
            {status === "ready"
              ? "Все ключевые источники свежие"
              : status === "stale"
                ? "Полоска заполнится после ремонта / догона"
                : "Прогресс синхронизации (оценка)"}
          </span>
          <span className="font-mono tabular-nums">
            {Math.round(smoothPct)}% · ETA {etaText}
          </span>
        </div>
      </div>

      {(data?.sources?.length ?? 0) > 0 && (
        <div className={cn("mt-3 grid gap-2", compact ? "grid-cols-2 sm:grid-cols-4" : "grid-cols-2 md:grid-cols-4")}>
          {data!.sources.map((s) => {
            const ok = s.ok !== false;
            const sp = s.progressPercent ?? (ok ? 100 : 0);
            return (
              <div
                key={s.source}
                className={cn(
                  "rounded-xl border px-2.5 py-2",
                  ok
                    ? "border-ok/20 bg-white/55 dark:bg-black/20"
                    : "border-danger/25 bg-danger/5"
                )}
                title={s.lastActivity ?? undefined}
              >
                <div className="flex items-center justify-between gap-2 text-[10px] font-medium">
                  <span className="uppercase tracking-wide">{s.source}</span>
                  <span className="font-mono tabular-nums text-muted">{fmtLag(s.lagHours)}</span>
                </div>
                <div className={cn("mt-1.5 h-1 overflow-hidden rounded-full", ok ? "bg-ok/15" : "bg-danger/15")}>
                  <div
                    className={cn(
                      "h-full rounded-full transition-[width] duration-500",
                      ok ? "bg-ok" : "bg-danger/70"
                    )}
                    style={{ width: `${Math.max(4, Math.min(100, sp))}%` }}
                  />
                </div>
                <div className="mt-1 flex justify-between text-[9px] text-muted">
                  <span className="tabular-nums">{Math.round(sp)}%</span>
                  <span className="tabular-nums">{s.count.toLocaleString()}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {!compact && ((data?.blockingIssues?.length ?? 0) > 0 || (data?.warnings?.length ?? 0) > 0) && (
        <ul className="mt-3 space-y-1 text-[11px] text-fg/75">
          {(data?.blockingIssues ?? []).slice(0, 4).map((i) => (
            <li key={i}>• {i}</li>
          ))}
          {(data?.warnings ?? []).slice(0, 3).map((i) => (
            <li key={i}>• {i}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

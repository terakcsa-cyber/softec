"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Activity, ExternalLink, Loader2, RefreshCw, TriangleAlert } from "lucide-react";
import { RequireAuth } from "@/components/auth/require-auth";
import { apiFetch } from "@/lib/api-fetch";
import { cn } from "@/components/ui/cn";

type HealthCheck = {
  name: string;
  url: string;
  ok: boolean;
  status: number | null;
  ms: number;
  error?: string;
};

type HealthResponse = {
  ok: boolean;
  checkedAt: string;
  upstream: string;
  checks: HealthCheck[];
};

function fmtMs(ms: number) {
  if (!Number.isFinite(ms)) return "—";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

export default function HealthPage() {
  const [data, setData] = useState<HealthResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const sorted = useMemo(() => {
    if (!data?.checks) return [];
    return [...data.checks].sort((a, b) => a.name.localeCompare(b.name));
  }, [data]);

  const refresh = useCallback(async () => {
    setBusy(true);
    setErr(null);
    try {
      const res = await apiFetch("/api/health", { cache: "no-store" });
      const body = (await res.json()) as HealthResponse & { error?: string };
      if (!res.ok) {
        setData(body as HealthResponse);
        throw new Error(body.error ?? `health failed (${res.status})`);
      }
      setData(body);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "health failed");
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), 30_000);
    return () => clearInterval(t);
  }, [refresh]);

  return (
    <RequireAuth>
      <main className="min-h-screen px-6 py-8">
        <div className="mx-auto w-full max-w-5xl space-y-6">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-sm font-semibold tracking-tight">
                <Activity className="h-4 w-4 text-accent" aria-hidden />
                Health
              </div>
              <div className="mt-1 text-xs text-muted">
                Проверка интеграций и сервисов. Обновляется раз в 30 секунд.
                {data?.checkedAt ? (
                  <span className="ml-2 tabular-nums">({new Date(data.checkedAt).toLocaleString()})</span>
                ) : null}
              </div>
            </div>

            <button
              type="button"
              onClick={() => void refresh()}
              disabled={busy}
              className={cn(
                "inline-flex shrink-0 items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-fg/90 shadow-sm",
                "hover:bg-slate-50 disabled:opacity-60 dark:border-border dark:bg-black/25 dark:shadow-none dark:hover:bg-black/35"
              )}
            >
              {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden /> : <RefreshCw className="h-3.5 w-3.5" aria-hidden />}
              Обновить
            </button>
          </div>

          {err ? (
            <div className="rounded-xl border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">
              {err}
            </div>
          ) : null}

          <div className="glass rounded-2xl p-4">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200/80 pb-3 text-[11px] text-muted dark:border-white/[0.06]">
              <div className="min-w-0">
                <div>
                  upstream: <span className="font-mono text-fg/85">{data?.upstream ?? "—"}</span>
                </div>
              </div>
              <div
                className={cn(
                  "inline-flex items-center gap-2 rounded-full border px-2.5 py-1 font-medium",
                  data?.ok ? "border-ok/25 bg-ok/10 text-ok" : "border-warn/30 bg-warn/10 text-warn"
                )}
              >
                {data?.ok ? "OK" : "DEGRADED"}
              </div>
            </div>

            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              {sorted.length ? (
                sorted.map((c) => (
                  <div
                    key={c.name}
                    className={cn(
                      "rounded-xl border p-3",
                      c.ok || c.status === 401
                        ? "border-slate-200/90 bg-slate-50/70 dark:border-white/[0.07] dark:bg-black/20"
                        : "border-danger/30 bg-danger/10"
                    )}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="truncate text-xs font-semibold text-fg/95">{c.name}</div>
                        <a
                          href={c.url}
                          target="_blank"
                          rel="noreferrer"
                          className="mt-1 inline-flex max-w-full items-center gap-1 truncate font-mono text-[10px] text-muted hover:underline"
                          title={c.url}
                        >
                          {c.url}
                          <ExternalLink className="h-3 w-3 shrink-0" aria-hidden />
                        </a>
                      </div>
                      {!c.ok && c.status !== 401 ? (
                        <TriangleAlert className="h-4 w-4 shrink-0 text-danger" aria-hidden />
                      ) : null}
                    </div>

                    <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-muted">
                      <span className="rounded-md bg-white px-1.5 py-0.5 font-mono tabular-nums text-fg/80 dark:bg-black/25">
                        {c.status ?? "—"}
                      </span>
                      <span className="rounded-md bg-white px-1.5 py-0.5 font-mono tabular-nums text-fg/80 dark:bg-black/25">
                        {fmtMs(c.ms)}
                      </span>
                      {c.error ? <span className="truncate text-danger">{c.error}</span> : null}
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-sm text-muted">Нет данных</div>
              )}
            </div>
          </div>
        </div>
      </main>
    </RequireAuth>
  );
}


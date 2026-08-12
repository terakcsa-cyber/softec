"use client";

import { apiFetch } from "@/lib/api-fetch";
import { cn } from "@/components/ui/cn";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";

type UpdateCommit = {
  sha: string;
  shortSha: string;
  subject: string;
  date: string | null;
};

type UpdateJob = {
  phase: string;
  progressRu: string;
  errorRu: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  updatedAt: string | null;
};

type UpdateStatus = {
  current: {
    sha: string | null;
    shortSha: string | null;
    branch: string | null;
    tag: string | null;
    versionLabel: string;
    source: string;
  };
  remote: {
    url: string | null;
    branch: string;
    sha: string | null;
    shortSha: string | null;
  };
  updateAvailable: boolean;
  commitsAhead: UpdateCommit[];
  commitsAheadCount: number;
  apply: {
    enabled: boolean;
    allowed: boolean;
    mode: string;
    blockersRu: string[];
  };
  job: UpdateJob | null;
  checkedAt: string | null;
  safetyNotesRu: string[];
  config: {
    repoDir: string | null;
    hostRepoPath: string | null;
    branch: string;
    envFile: string;
    composeFile: string;
    backupBeforeApply: boolean;
  };
};

async function readApiError(res: Response, fallback: string) {
  try {
    const data = (await res.json()) as { message?: unknown; error?: unknown };
    if (typeof data.message === "string") return data.message;
    if (Array.isArray(data.message)) return data.message.join(", ");
    if (typeof data.error === "string") return data.error;
  } catch {
    // ignore
  }
  return fallback;
}

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("ru-RU", {
      dateStyle: "medium",
      timeStyle: "short"
    });
  } catch {
    return iso;
  }
}

function jobBusy(phase: string | undefined): boolean {
  if (!phase) return false;
  return !["idle", "done", "failed"].includes(phase);
}

export function PlatformUpdatePanel({ embedded = false }: { embedded?: boolean }) {
  const qc = useQueryClient();
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const statusQ = useQuery({
    queryKey: ["settings", "updates"],
    queryFn: async () => {
      const res = await apiFetch("/api/settings/updates", { cache: "no-store" });
      if (!res.ok) throw new Error(await readApiError(res, "Не удалось загрузить статус обновлений"));
      return (await res.json()) as UpdateStatus;
    },
    refetchInterval: (q) => (jobBusy(q.state.data?.job?.phase) ? 3000 : false)
  });

  useEffect(() => {
    if (statusQ.data?.job?.phase === "done") {
      setMsg(statusQ.data.job.progressRu || "Обновление завершено");
      setErr(null);
    } else if (statusQ.data?.job?.phase === "failed") {
      setErr(statusQ.data.job.errorRu || statusQ.data.job.progressRu || "Ошибка обновления");
    }
  }, [statusQ.data?.job?.phase, statusQ.data?.job?.progressRu, statusQ.data?.job?.errorRu]);

  const check = useMutation({
    mutationFn: async () => {
      const res = await apiFetch("/api/settings/updates/check", {
        method: "POST",
        headers: { accept: "application/json" },
        cache: "no-store"
      });
      if (!res.ok) throw new Error(await readApiError(res, "Не удалось проверить обновления"));
      return (await res.json()) as UpdateStatus;
    },
    onSuccess: async (data) => {
      setErr(null);
      setMsg(
        data.updateAvailable
          ? `Доступно обновление: ${data.current.shortSha ?? "?"} → ${data.remote.shortSha ?? "?"}`
          : "Установлена актуальная версия"
      );
      await qc.setQueryData(["settings", "updates"], data);
    },
    onError: (e) => {
      setMsg(null);
      setErr(e instanceof Error ? e.message : "Ошибка проверки");
    }
  });

  const apply = useMutation({
    mutationFn: async () => {
      const res = await apiFetch("/api/settings/updates/apply", {
        method: "POST",
        headers: { accept: "application/json" },
        cache: "no-store"
      });
      if (!res.ok) throw new Error(await readApiError(res, "Не удалось запустить обновление"));
      return (await res.json()) as UpdateStatus;
    },
    onSuccess: async (data) => {
      setErr(null);
      setMsg("Обновление запущено. Сервисы перезапустятся; страница может кратко стать недоступной.");
      await qc.setQueryData(["settings", "updates"], data);
      await qc.invalidateQueries({ queryKey: ["settings", "updates"] });
    },
    onError: (e) => {
      setMsg(null);
      setErr(e instanceof Error ? e.message : "Ошибка применения");
    }
  });

  const st = statusQ.data;
  const busy = check.isPending || apply.isPending || jobBusy(st?.job?.phase);

  return (
    <div className={cn(!embedded && "glass rounded-2xl p-5 sm:p-6")}>
      {!embedded ? (
        <div className="mb-4">
          <div className="text-sm font-semibold tracking-tight text-fg/95">Обновления</div>
          <p className="mt-1 text-xs text-muted">
            Проверка git-репозитория и безопасное обновление Docker Compose без потери данных.
          </p>
        </div>
      ) : null}

      {statusQ.isLoading ? <p className="text-sm text-muted">Загрузка…</p> : null}
      {statusQ.isError ? (
        <p className="text-sm text-red-700 dark:text-red-300">
          {statusQ.error instanceof Error ? statusQ.error.message : "Ошибка загрузки"}
        </p>
      ) : null}

      {st ? (
        <div className="space-y-5">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-xl border border-slate-200 px-4 py-3 dark:border-border">
              <div className="text-[11px] uppercase tracking-wide text-muted">Текущая версия</div>
              <div className="mt-1 font-mono text-sm text-fg/90">{st.current.versionLabel}</div>
              <div className="mt-1 text-xs text-muted">
                {st.current.branch ? `ветка ${st.current.branch}` : "ветка неизвестна"}
                {st.current.shortSha ? ` · ${st.current.shortSha}` : ""}
                {` · ${st.current.source}`}
              </div>
            </div>
            <div className="rounded-xl border border-slate-200 px-4 py-3 dark:border-border">
              <div className="text-[11px] uppercase tracking-wide text-muted">Remote</div>
              <div className="mt-1 font-mono text-sm text-fg/90">
                {st.remote.shortSha ?? "—"}
                {st.updateAvailable ? (
                  <span className="ml-2 text-xs font-sans text-amber-700 dark:text-amber-300">есть обновление</span>
                ) : (
                  <span className="ml-2 text-xs font-sans text-muted">актуально</span>
                )}
              </div>
              <div className="mt-1 truncate text-xs text-muted" title={st.remote.url ?? undefined}>
                {st.remote.branch}
                {st.remote.url ? ` · ${st.remote.url}` : ""}
              </div>
            </div>
          </div>

          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              disabled={busy}
              onClick={() => check.mutate()}
              className="inline-flex items-center gap-2 rounded-xl border border-accent/35 bg-accent/10 px-3.5 py-2 text-sm font-medium text-fg/95 transition hover:bg-accent/15 disabled:opacity-50"
            >
              <RefreshCw className={cn("h-4 w-4", check.isPending && "animate-spin")} aria-hidden />
              Проверить обновления
            </button>
            <button
              type="button"
              disabled={busy || !st.apply.allowed || !st.updateAvailable}
              onClick={() => {
                if (
                  !window.confirm(
                    "Применить обновление? Будет сделан backup Postgres, git fast-forward и пересборка контейнеров. Volumes и .env не трогаются."
                  )
                ) {
                  return;
                }
                apply.mutate();
              }}
              className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-slate-50 px-3.5 py-2 text-sm font-medium text-fg/90 transition hover:bg-slate-100 disabled:opacity-50 dark:border-border dark:bg-white/[0.04] dark:hover:bg-white/[0.07]"
            >
              Применить обновление
            </button>
          </div>

          {st.checkedAt ? (
            <p className="text-[11px] text-muted">Последняя проверка: {formatDate(st.checkedAt)}</p>
          ) : null}

          {msg ? (
            <div className="rounded-xl border border-emerald-200 bg-emerald-50/80 px-3 py-2 text-sm text-emerald-900 dark:border-emerald-900/40 dark:bg-emerald-950/30 dark:text-emerald-100">
              {msg}
            </div>
          ) : null}
          {err ? (
            <div className="rounded-xl border border-red-200 bg-red-50/80 px-3 py-2 text-sm text-red-800 dark:border-red-900/40 dark:bg-red-950/30 dark:text-red-100">
              {err}
            </div>
          ) : null}

          {st.job && st.job.phase !== "idle" ? (
            <div className="rounded-xl border border-slate-200 px-4 py-3 dark:border-border">
              <div className="text-[11px] uppercase tracking-wide text-muted">Прогресс</div>
              <div className="mt-1 text-sm text-fg/90">
                <span className="font-mono text-xs text-muted">{st.job.phase}</span>
                <span className="mx-2 text-muted">·</span>
                {st.job.progressRu}
              </div>
              {st.job.errorRu ? (
                <p className="mt-2 text-sm text-red-700 dark:text-red-300">{st.job.errorRu}</p>
              ) : null}
            </div>
          ) : null}

          {st.commitsAhead.length > 0 ? (
            <div>
              <div className="mb-2 text-xs font-medium text-fg/85">
                Коммиты ahead ({st.commitsAheadCount}
                {st.commitsAheadCount > st.commitsAhead.length ? "+" : ""})
              </div>
              <ul className="max-h-56 space-y-1.5 overflow-y-auto rounded-xl border border-slate-200 p-3 dark:border-border">
                {st.commitsAhead.map((c) => (
                  <li key={c.sha} className="text-xs leading-snug">
                    <span className="font-mono text-muted">{c.shortSha}</span>
                    <span className="mx-1.5 text-fg/85">{c.subject}</span>
                    {c.date ? <span className="text-muted">· {formatDate(c.date)}</span> : null}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          {!st.apply.allowed ? (
            <div className="rounded-xl border border-amber-200 bg-amber-50/70 px-4 py-3 text-sm text-amber-950 dark:border-amber-900/40 dark:bg-amber-950/20 dark:text-amber-100">
              <div className="font-medium">Apply недоступен</div>
              <ul className="mt-2 list-disc space-y-1 pl-5 text-xs">
                {st.apply.blockersRu.map((b) => (
                  <li key={b}>{b}</li>
                ))}
              </ul>
              <p className="mt-3 text-xs text-amber-900/80 dark:text-amber-100/80">
                Ручной безопасный путь на сервере:{" "}
                <code className="font-mono">bash scripts/platform-update.sh</code> (эквивалент{" "}
                <code className="font-mono">git pull</code> +{" "}
                <code className="font-mono">./deploy.sh --yes --update</code>).
              </p>
            </div>
          ) : null}

          <div className="rounded-xl border border-slate-200 px-4 py-3 dark:border-border">
            <div className="text-[11px] uppercase tracking-wide text-muted">Гарантии безопасности</div>
            <ul className="mt-2 list-disc space-y-1 pl-5 text-xs text-muted">
              {st.safetyNotesRu.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          </div>
        </div>
      ) : null}
    </div>
  );
}

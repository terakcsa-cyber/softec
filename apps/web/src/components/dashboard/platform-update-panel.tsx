"use client";

import { apiFetch } from "@/lib/api-fetch";
import { cn } from "@/components/ui/cn";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { HardDrive, RefreshCw, Trash2 } from "lucide-react";

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

type DiskMount = {
  path: string;
  label: string;
  totalBytes: number;
  usedBytes: number;
  freeBytes: number;
  usedRatio: number;
};

type StorageStatus = {
  checkedAt: string;
  mounts: DiskMount[];
  backups: {
    dir: string | null;
    files: Array<{ name: string; sizeBytes: number; mtime: string | null }>;
    totalBytes: number;
    keepDefault: number;
  };
  docker: {
    available: boolean;
    summaryRu: string | null;
    reclaimableRu: string | null;
  };
  notesRu: string[];
};

type CleanupResult = {
  deleted: Array<{ name: string; sizeBytes: number }>;
  kept: Array<{ name: string; sizeBytes: number }>;
  freedBytes: number;
  dockerPruned: boolean;
  dockerPruneLog: string | null;
  storage: StorageStatus;
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

function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  const digits = i === 0 ? 0 : v >= 10 ? 1 : 2;
  return `${v.toFixed(digits)} ${units[i]}`;
}

function diskTone(ratio: number): string {
  if (ratio >= 0.9) return "bg-danger";
  if (ratio >= 0.75) return "bg-warn";
  return "bg-accent";
}

export function PlatformUpdatePanel({ embedded = false }: { embedded?: boolean }) {
  const qc = useQueryClient();
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [pruneDocker, setPruneDocker] = useState(false);

  const statusQ = useQuery({
    queryKey: ["settings", "updates"],
    queryFn: async () => {
      const res = await apiFetch("/api/settings/updates", { cache: "no-store" });
      if (!res.ok) throw new Error(await readApiError(res, "Не удалось загрузить статус обновлений"));
      return (await res.json()) as UpdateStatus;
    },
    refetchInterval: (q) => (jobBusy(q.state.data?.job?.phase) ? 3000 : false)
  });

  const storageQ = useQuery({
    queryKey: ["settings", "updates", "storage"],
    queryFn: async () => {
      const res = await apiFetch("/api/settings/updates/storage", { cache: "no-store" });
      if (!res.ok) throw new Error(await readApiError(res, "Не удалось загрузить статус диска"));
      return (await res.json()) as StorageStatus;
    },
    refetchInterval: 60_000
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

  const cleanup = useMutation({
    mutationFn: async () => {
      const res = await apiFetch("/api/settings/updates/cleanup", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({
          keepBackups: storageQ.data?.backups.keepDefault ?? 3,
          pruneDocker
        }),
        cache: "no-store"
      });
      if (!res.ok) throw new Error(await readApiError(res, "Не удалось очистить место"));
      return (await res.json()) as CleanupResult;
    },
    onSuccess: async (data) => {
      setErr(null);
      const parts = [
        data.deleted.length
          ? `Удалено бэкапов: ${data.deleted.length} (−${formatBytes(data.freedBytes)})`
          : "Старых бэкапов для удаления нет",
        `оставлено ${data.kept.length}`
      ];
      if (data.dockerPruned) parts.push("Docker prune выполнен");
      setMsg(parts.join(" · "));
      await qc.setQueryData(["settings", "updates", "storage"], data.storage);
      await qc.invalidateQueries({ queryKey: ["settings", "updates", "storage"] });
    },
    onError: (e) => {
      setMsg(null);
      setErr(e instanceof Error ? e.message : "Ошибка очистки");
    }
  });

  const st = statusQ.data;
  const storage = storageQ.data;
  const busy = check.isPending || apply.isPending || cleanup.isPending || jobBusy(st?.job?.phase);
  const primaryMount = storage?.mounts[0] ?? null;
  const deletableBackups = Math.max(
    0,
    (storage?.backups.files.length ?? 0) - (storage?.backups.keepDefault ?? 3)
  );

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
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div>
                <div className="inline-flex items-center gap-1.5 text-[11px] uppercase tracking-wide text-muted">
                  <HardDrive className="h-3.5 w-3.5" aria-hidden />
                  Диск и бэкапы
                </div>
                <p className="mt-1 text-xs text-muted">
                  Место на ФС без SSH. Очистка удаляет только старые dump’ы в{" "}
                  <code className="font-mono">backups/</code>, оставляя{" "}
                  {storage?.backups.keepDefault ?? 3} свежих.
                </p>
              </div>
              <button
                type="button"
                disabled={storageQ.isFetching}
                onClick={() => void storageQ.refetch()}
                className="inline-flex items-center gap-1.5 rounded-lg border border-border px-2.5 py-1.5 text-[11px] font-medium text-fg/80 hover:bg-slate-50 disabled:opacity-50 dark:hover:bg-white/5"
              >
                <RefreshCw className={cn("h-3.5 w-3.5", storageQ.isFetching && "animate-spin")} aria-hidden />
                Обновить диск
              </button>
            </div>

            {storageQ.isLoading ? <p className="mt-3 text-sm text-muted">Считаем диск…</p> : null}
            {storageQ.isError ? (
              <p className="mt-3 text-sm text-danger">
                {storageQ.error instanceof Error ? storageQ.error.message : "Не удалось получить диск"}
              </p>
            ) : null}

            {primaryMount ? (
              <div className="mt-3 space-y-2">
                {(storage?.mounts ?? []).slice(0, 3).map((m) => {
                  const pct = Math.round(m.usedRatio * 100);
                  return (
                    <div key={`${m.label}:${m.path}`}>
                      <div className="mb-1 flex items-center justify-between gap-2 text-[11px]">
                        <span className="truncate font-medium text-fg/85" title={m.path}>
                          {m.label}
                        </span>
                        <span className="shrink-0 tabular-nums text-muted">
                          свободно {formatBytes(m.freeBytes)} · занято {formatBytes(m.usedBytes)} /{" "}
                          {formatBytes(m.totalBytes)} ({pct}%)
                        </span>
                      </div>
                      <div className="h-2.5 overflow-hidden rounded-full bg-slate-100 dark:bg-white/10">
                        <div
                          className={cn("h-full rounded-full transition-all", diskTone(m.usedRatio))}
                          style={{ width: `${Math.min(100, Math.max(0, pct))}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : null}

            <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted">
              <span>
                Бэкапы:{" "}
                <span className="font-semibold tabular-nums text-fg/85">
                  {storage?.backups.files.length ?? 0}
                </span>{" "}
                ·{" "}
                <span className="font-semibold tabular-nums text-fg/85">
                  {formatBytes(storage?.backups.totalBytes ?? 0)}
                </span>
                {deletableBackups > 0 ? (
                  <span className="text-warn"> · можно удалить {deletableBackups}</span>
                ) : (
                  <span> · лишнего нет</span>
                )}
              </span>
              {storage?.docker.available ? (
                <span className="truncate" title={storage.docker.summaryRu ?? undefined}>
                  Docker: {storage.docker.reclaimableRu || "CLI доступен"}
                </span>
              ) : (
                <span>Docker prune: недоступен без update-helper</span>
              )}
            </div>

            {(storage?.backups.files.length ?? 0) > 0 ? (
              <ul className="mt-2 max-h-28 space-y-1 overflow-y-auto rounded-lg border border-border/70 bg-slate-50/60 px-2.5 py-2 text-[11px] dark:bg-black/20">
                {storage!.backups.files.slice(0, 12).map((f, idx) => (
                  <li key={f.name} className="flex items-center justify-between gap-2">
                    <span className="truncate font-mono text-fg/80">
                      {idx < (storage?.backups.keepDefault ?? 3) ? (
                        <span className="mr-1 text-ok">keep</span>
                      ) : (
                        <span className="mr-1 text-warn">old</span>
                      )}
                      {f.name}
                    </span>
                    <span className="shrink-0 tabular-nums text-muted">{formatBytes(f.sizeBytes)}</span>
                  </li>
                ))}
              </ul>
            ) : null}

            <div className="mt-3 flex flex-wrap items-center gap-3">
              <label className="inline-flex items-center gap-2 text-[11px] text-muted">
                <input
                  type="checkbox"
                  checked={pruneDocker}
                  disabled={!storage?.docker.available || busy}
                  onChange={(e) => setPruneDocker(e.target.checked)}
                  className="h-3.5 w-3.5 rounded border-slate-300"
                />
                + Docker prune (dangling images / build cache, без volumes)
              </label>
              <button
                type="button"
                disabled={busy || (!deletableBackups && !pruneDocker)}
                onClick={() => {
                  const keep = storage?.backups.keepDefault ?? 3;
                  const confirmMsg = pruneDocker
                    ? `Удалить старые бэкапы (оставить ${keep} свежих) и выполнить Docker prune без volumes?`
                    : `Удалить старые SQL-бэкапы в backups/, оставив ${keep} самых свежих? Volumes и .env не трогаются.`;
                  if (!window.confirm(confirmMsg)) return;
                  cleanup.mutate();
                }}
                className="inline-flex items-center gap-1.5 rounded-xl border border-warn/35 bg-warn/10 px-3 py-2 text-sm font-medium text-fg/90 transition hover:bg-warn/15 disabled:opacity-50"
              >
                <Trash2 className="h-4 w-4" aria-hidden />
                Очистить старое
              </button>
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 px-4 py-3 dark:border-border">
            <div className="text-[11px] uppercase tracking-wide text-muted">Гарантии безопасности</div>
            <ul className="mt-2 list-disc space-y-1 pl-5 text-xs text-muted">
              {st.safetyNotesRu.map((n) => (
                <li key={n}>{n}</li>
              ))}
              {storage?.notesRu.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          </div>
        </div>
      ) : null}
    </div>
  );
}

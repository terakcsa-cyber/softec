"use client";

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Eye, EyeOff, Loader2, Plus, Trash2, Target, AlertCircle, X } from "lucide-react";
import { cn } from "../ui/cn";
import {
  addVocWatchlist,
  deleteVocWatchlist,
  fetchVocWatchlist,
  patchVocWatchlist,
  type VocWatchlistKind
} from "@/lib/voc-watchlist-api";
import { watchlistKindLabel } from "@/lib/voc-watchlist-client";

const KINDS: { id: VocWatchlistKind; label: string }[] = [
  { id: "vendor", label: "Вендор" },
  { id: "product", label: "Продукт" },
  { id: "keyword", label: "Ключевое слово" }
];

function kindTone(kind: VocWatchlistKind): string {
  if (kind === "vendor") return "border-indigo-400/35 bg-indigo-500/10 text-indigo-700 dark:text-indigo-300";
  if (kind === "product") return "border-teal-400/35 bg-teal-500/10 text-teal-700 dark:text-teal-300";
  return "border-amber-400/35 bg-amber-500/10 text-amber-800 dark:text-amber-300";
}

export function VocWatchlistPanel({ className }: { className?: string }) {
  const queryClient = useQueryClient();
  const [kind, setKind] = useState<VocWatchlistKind>("vendor");
  const [value, setValue] = useState("");
  const [open, setOpen] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const watchlistQuery = useQuery({
    queryKey: ["voc", "watchlist"],
    queryFn: fetchVocWatchlist,
    staleTime: 30_000
  });

  const rules = useMemo(() => watchlistQuery.data ?? [], [watchlistQuery.data]);
  const activeCount = useMemo(() => rules.filter((r) => r.active).length, [rules]);

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["voc", "watchlist"] });
    void queryClient.invalidateQueries({ queryKey: ["voc", "queue"] });
  };

  const addMutation = useMutation({
    mutationFn: addVocWatchlist,
    onMutate: () => setError(null),
    onSuccess: () => {
      setValue("");
      invalidate();
    },
    onError: (err) => setError(err instanceof Error ? err.message : "Ошибка добавления")
  });

  const patchMutation = useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) => patchVocWatchlist(id, { active }),
    onMutate: () => setError(null),
    onSuccess: invalidate,
    onError: (err) => setError(err instanceof Error ? err.message : "Ошибка обновления")
  });

  const deleteMutation = useMutation({
    mutationFn: deleteVocWatchlist,
    onMutate: () => setError(null),
    onSuccess: invalidate,
    onError: (err) => setError(err instanceof Error ? err.message : "Ошибка удаления")
  });

  const busy = addMutation.isPending || patchMutation.isPending || deleteMutation.isPending;

  return (
    <div
      className={cn(
        "rounded-xl border border-slate-200/90 bg-white/70 p-3 dark:border-white/10 dark:bg-black/20",
        className
      )}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between gap-2 text-left"
      >
        <div className="flex items-center gap-2 text-[12px] font-semibold text-fg/95">
          <Target className="h-3.5 w-3.5 text-indigo-500" />
          Watchlist смены
          <span className="rounded-full border border-slate-200 px-2 py-0.5 text-[10px] font-medium text-muted dark:border-white/10">
            {activeCount} активн.
          </span>
        </div>
        <span className="text-[10px] text-muted">{open ? "Свернуть" : "Развернуть"}</span>
      </button>

      {open ? (
        <div className="mt-3 space-y-3">
          <p className="text-[11px] leading-relaxed text-muted">
            Вендоры, продукты и ключевые слова — совпадения за 7 дней поднимаются в ленте VOC и во вкладке Watchlist.
          </p>

          {error ? (
            <div className="flex items-start gap-2 rounded-lg border border-danger/35 bg-danger/10 px-2.5 py-2 text-[11px] text-danger">
              <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <div className="min-w-0 flex-1">{error}</div>
              <button type="button" onClick={() => setError(null)} className="shrink-0">
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          ) : null}

          {watchlistQuery.isError ? (
            <div className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-[11px] text-danger">
              Не удалось загрузить watchlist: {(watchlistQuery.error as Error).message}
            </div>
          ) : null}

          <form
            className="flex flex-col gap-2 sm:flex-row sm:items-end"
            onSubmit={(e) => {
              e.preventDefault();
              const v = value.trim();
              if (!v || addMutation.isPending) return;
              addMutation.mutate({ kind, value: v, label: v });
            }}
          >
            <div className="flex flex-wrap gap-1.5">
              {KINDS.map((k) => (
                <button
                  key={k.id}
                  type="button"
                  onClick={() => setKind(k.id)}
                  className={cn(
                    "rounded-full border px-2.5 py-1 text-[10px] font-medium transition",
                    kind === k.id
                      ? "border-indigo-400/40 bg-indigo-500/15 text-fg/95"
                      : "border-slate-200 text-muted dark:border-white/10"
                  )}
                >
                  {k.label}
                </button>
              ))}
            </div>
            <div className="flex min-w-0 flex-1 gap-2">
              <input
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder={
                  kind === "vendor" ? "apache" : kind === "product" ? "http_server" : "exchange, fortios…"
                }
                className="min-w-0 flex-1 rounded-lg border border-slate-200 bg-white px-3 py-2 text-[12px] dark:border-white/10 dark:bg-black/30"
              />
              <button
                type="submit"
                disabled={!value.trim() || busy}
                className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-indigo-400/35 bg-indigo-500/15 px-3 py-2 text-[11px] font-medium disabled:opacity-60"
              >
                {addMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
                Добавить
              </button>
            </div>
          </form>

          {watchlistQuery.isLoading ? (
            <div className="h-10 animate-pulse rounded-lg bg-slate-200/50 dark:bg-white/5" />
          ) : rules.length === 0 ? (
            <div className="rounded-lg border border-dashed border-slate-300 px-3 py-4 text-center text-[11px] text-muted dark:border-white/10">
              Пока пусто — добавьте вендор или продукт, который важен для вашей инфры.
            </div>
          ) : (
            <ul className="flex flex-wrap gap-2">
              {rules.map((rule) => (
                <li
                  key={rule.id}
                  className={cn(
                    "inline-flex max-w-full items-center gap-1.5 rounded-full border px-2 py-1 text-[11px]",
                    rule.active
                      ? "border-slate-200/90 bg-slate-50 dark:border-white/10 dark:bg-black/30"
                      : "border-slate-200/60 bg-transparent opacity-55 dark:border-white/5"
                  )}
                >
                  <span className={cn("rounded-md border px-1.5 py-0.5 text-[9px] font-semibold", kindTone(rule.kind))}>
                    {watchlistKindLabel(rule.kind)}
                  </span>
                  <span className="truncate font-medium text-fg/90">{rule.label || rule.value}</span>
                  <button
                    type="button"
                    disabled={busy}
                    title={rule.active ? "Приостановить" : "Включить"}
                    onClick={() => patchMutation.mutate({ id: rule.id, active: !rule.active })}
                    className="rounded p-0.5 text-muted hover:text-fg/80"
                  >
                    {rule.active ? <Eye className="h-3.5 w-3.5" /> : <EyeOff className="h-3.5 w-3.5" />}
                  </button>
                  <button
                    type="button"
                    disabled={busy}
                    title="Удалить"
                    onClick={() => deleteMutation.mutate(rule.id)}
                    className="rounded p-0.5 text-muted hover:text-danger"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : null}
    </div>
  );
}

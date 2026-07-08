"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Loader2, Plus, Target } from "lucide-react";
import { cn } from "../ui/cn";
import { addVocWatchlist, type VocWatchlistKind } from "@/lib/voc-watchlist-api";

export function VocWatchlistQuickAdd({
  kind,
  value,
  label,
  className,
  compact = false
}: {
  kind: VocWatchlistKind;
  value: string;
  label?: string;
  className?: string;
  compact?: boolean;
}) {
  const queryClient = useQueryClient();
  const text = value.trim();
  const mutation = useMutation({
    mutationFn: () => addVocWatchlist({ kind, value: text, label: label ?? text }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["voc", "watchlist"] });
      void queryClient.invalidateQueries({ queryKey: ["voc", "queue"] });
    }
  });

  if (!text) return null;

  return (
    <button
      type="button"
      disabled={mutation.isPending}
      title={`Добавить в watchlist: ${text}`}
      onClick={(e) => {
        e.stopPropagation();
        mutation.mutate();
      }}
      className={cn(
        "inline-flex items-center gap-1 rounded-lg border border-amber-400/35 bg-amber-500/10 text-amber-900 hover:bg-amber-500/15 dark:text-amber-200",
        compact ? "px-1.5 py-0.5 text-[9px]" : "px-2 py-1 text-[10px]",
        className
      )}
    >
      {mutation.isPending ? (
        <Loader2 className={cn("animate-spin", compact ? "h-3 w-3" : "h-3.5 w-3.5")} />
      ) : (
        <Target className={cn(compact ? "h-3 w-3" : "h-3.5 w-3.5")} />
      )}
      {!compact ? <span>В watchlist</span> : <Plus className="h-3 w-3" />}
    </button>
  );
}

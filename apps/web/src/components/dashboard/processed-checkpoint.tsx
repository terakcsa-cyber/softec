"use client";

import { Check, Circle } from "lucide-react";
import { cn } from "../ui/cn";

export function ProcessedCheckpoint({
  processed,
  onToggle,
  compact = false,
  className
}: {
  processed: boolean;
  onToggle: () => void;
  compact?: boolean;
  className?: string;
}) {
  return (
    <span
      role="checkbox"
      tabIndex={0}
      aria-checked={processed}
      title={processed ? "Снять отметку «обработано»" : "Отметить как обработано"}
      onClick={(e) => {
        e.stopPropagation();
        e.preventDefault();
        onToggle();
      }}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          e.stopPropagation();
          onToggle();
        }
      }}
      onPointerDown={(e) => e.stopPropagation()}
      className={cn(
        "inline-flex shrink-0 cursor-pointer items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium transition select-none",
        processed
          ? "border-ok/45 bg-ok/15 text-ok shadow-[0_0_10px_rgba(34,197,94,0.15)]"
          : "border-slate-200/90 bg-white/90 text-muted hover:border-accent/35 hover:text-fg/80 dark:border-white/10 dark:bg-black/30 dark:hover:border-accent/30",
        compact && "px-1.5",
        className
      )}
    >
      {processed ? (
        <Check className={cn("h-3.5 w-3.5", compact && "h-3 w-3")} strokeWidth={2.5} />
      ) : (
        <Circle className={cn("h-3.5 w-3.5 opacity-55", compact && "h-3 w-3")} strokeWidth={2} />
      )}
      {!compact ? <span>{processed ? "Обработано" : "В очереди"}</span> : null}
    </span>
  );
}

export function processedCardClass(processed: boolean): string {
  return processed ? "opacity-[0.62] saturate-[0.88] hover:opacity-80" : "";
}

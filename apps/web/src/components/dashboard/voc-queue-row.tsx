"use client";

import { cn } from "../ui/cn";
import type { DeskRow } from "@/lib/voc-desk";
import { deskDecisionLabel } from "@/lib/voc-desk";

export function VocQueueRow({
  row,
  active,
  onSelect
}: {
  row: DeskRow;
  active: boolean;
  onSelect: () => void;
}) {
  const decision = deskDecisionLabel(row.primary.deskDecision);
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        "w-full rounded-lg border px-3 py-2.5 text-left transition",
        "border-l-2",
        row.burning
          ? "border-l-danger"
          : row.ours
            ? "border-l-warn"
            : "border-l-transparent",
        active
          ? "border-accent/40 bg-accent/[0.07]"
          : "border-border bg-white hover:bg-slate-50 dark:bg-black/20 dark:hover:bg-white/[0.03]"
      )}
    >
      <div className="flex items-baseline justify-between gap-3">
        <span className="font-mono text-[11px] text-fg/70">{row.ident}</span>
        <span className={cn("shrink-0 text-[11px] tabular-nums", row.when === "просрочен" ? "text-danger" : "text-muted")}>
          {decision || row.when || (row.ours ? "контур" : "")}
        </span>
      </div>
      <div className="mt-1 text-[13px] font-semibold leading-snug tracking-tight text-fg/95">{row.product}</div>
      <div className="mt-0.5 text-[12px] leading-snug text-muted">{row.phrase}</div>
    </button>
  );
}

"use client";

import { cn } from "../ui/cn";
import { VULN_CLASS_CATALOG, toggleVulnClassSelection, type VulnClassId } from "@/lib/vuln-class";
import { vulnClassChipClasses } from "./vuln-class-badge";

export function VulnClassFilter({
  value,
  onChange,
  className,
  compact = false
}: {
  value: VulnClassId[];
  onChange: (next: VulnClassId[]) => void;
  className?: string;
  compact?: boolean;
}) {
  const selected = value.length;

  return (
    <div
      className={cn(
        compact
          ? "space-y-1.5"
          : "rounded-2xl border border-slate-200/90 bg-gradient-to-br from-slate-50/90 to-white/70 p-2 dark:border-white/10 dark:from-white/[0.04] dark:to-black/20",
        className
      )}
    >
      <div className="mb-1.5 flex items-center justify-between gap-2 px-0.5">
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-medium text-fg/90">Класс уязвимости</span>
          {selected > 0 ? (
            <span className="rounded-full border border-accent/30 bg-accent/10 px-1.5 py-px text-[10px] font-medium tabular-nums text-fg/80">
              {selected}
            </span>
          ) : (
            <span className="text-[10px] text-muted">мультивыбор</span>
          )}
        </div>
        {selected > 0 ? (
          <button
            type="button"
            onClick={() => onChange([])}
            className="rounded-full border border-slate-200 bg-white px-2 py-0.5 text-[10px] text-fg/75 transition hover:bg-slate-100 dark:border-white/10 dark:bg-black/30 dark:hover:bg-black/45"
          >
            Сбросить
          </button>
        ) : null}
      </div>
      <div className="flex flex-wrap gap-1.5">
        {VULN_CLASS_CATALOG.map((meta) => {
          const active = value.includes(meta.id);
          return (
            <button
              key={meta.id}
              type="button"
              aria-pressed={active}
              title={meta.label}
              onClick={() => onChange(toggleVulnClassSelection(value, meta.id))}
              className={vulnClassChipClasses(meta.tone, active)}
            >
              {meta.shortLabel}
            </button>
          );
        })}
      </div>
    </div>
  );
}

"use client";

import type { ReactNode } from "react";
import { cn } from "../ui/cn";

export function DetailMetricGrid({
  items
}: {
  items: Array<{ label: string; value: string; title?: string; tone?: "danger" | "warn" | "ok" | "neutral" }>;
}) {
  return (
    <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
      {items.map((item) => (
        <div
          key={item.label}
          title={item.title}
          className="min-w-0 rounded-lg border border-border bg-white px-3 py-2 dark:bg-black/25"
        >
          <div className="truncate text-[10px] uppercase tracking-wide text-muted">{item.label}</div>
          <div
            className={cn(
              "mt-0.5 truncate text-sm font-semibold tabular-nums text-fg",
              item.tone === "danger" && "text-danger",
              item.tone === "warn" && "text-warn",
              item.tone === "ok" && "text-ok"
            )}
          >
            {item.value}
          </div>
        </div>
      ))}
    </div>
  );
}

export function DetailFactList({ rows }: { rows: Array<{ label: string; value: ReactNode }> }) {
  return (
    <dl className="mt-2">
      {rows.map((row) => (
        <div
          key={row.label}
          className="grid grid-cols-1 gap-0.5 border-b border-border/70 py-2 last:border-b-0 sm:grid-cols-[9.5rem_minmax(0,1fr)] sm:items-baseline sm:gap-3"
        >
          <dt className="text-[11px] text-muted">{row.label}</dt>
          <dd className="min-w-0 break-words text-[13px] leading-snug text-fg/90">{row.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function DetailTabs<T extends string>({
  tabs,
  value,
  onChange
}: {
  tabs: Array<{ id: T; label: string }>;
  value: T;
  onChange: (id: T) => void;
}) {
  return (
    <div className="mt-4 flex gap-1 overflow-x-auto border-b border-border" role="tablist">
      {tabs.map((tab) => {
        const active = tab.id === value;
        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(tab.id)}
            className={cn(
              "-mb-px shrink-0 border-b-2 px-3 py-2 text-xs",
              active ? "border-accent text-fg" : "border-transparent text-muted hover:text-fg/80"
            )}
          >
            {tab.label}
          </button>
        );
      })}
    </div>
  );
}

export function DetailSection({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) {
  return (
    <section className="rounded-xl border border-border bg-white p-4 dark:bg-black/20">
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-xs font-medium uppercase tracking-wide text-muted">{title}</h3>
        {action}
      </div>
      {children}
    </section>
  );
}

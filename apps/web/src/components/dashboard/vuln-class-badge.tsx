"use client";

import { cn } from "../ui/cn";
import { vulnClassMeta, type VulnClassTone } from "@/lib/vuln-class";

function toneClasses(tone: VulnClassTone, active = false): string {
  switch (tone) {
    case "critical":
      return active
        ? "border-danger/50 bg-danger/20 text-danger shadow-[0_0_12px_rgba(239,68,68,0.35)]"
        : "border-danger/35 bg-danger/10 text-danger";
    case "high":
      return active
        ? "border-warn/50 bg-warn/20 text-warn shadow-[0_0_10px_rgba(245,158,11,0.28)]"
        : "border-warn/35 bg-warn/12 text-warn";
    case "medium":
      return active
        ? "border-accent/45 bg-accent/15 text-fg/95 shadow-[0_0_10px_rgba(99,102,241,0.22)]"
        : "border-accent/30 bg-accent/10 text-fg/85";
    case "low":
      return active
        ? "border-slate-300 bg-slate-100 text-fg/90 shadow-sm dark:border-white/20 dark:bg-white/10"
        : "border-slate-200 bg-slate-50 text-fg/80 dark:border-white/10 dark:bg-white/5";
    case "neutral":
    default:
      return active
        ? "border-sky-400/45 bg-sky-500/15 text-sky-700 shadow-[0_0_10px_rgba(14,165,233,0.2)] dark:text-sky-300"
        : "border-sky-300/40 bg-sky-500/10 text-sky-700 dark:text-sky-300";
  }
}

export function VulnClassBadge({
  vulnClass,
  className,
  title
}: {
  vulnClass: string | null | undefined;
  className?: string;
  title?: string;
}) {
  const meta = vulnClassMeta(vulnClass);
  if (!meta) return null;
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-px font-mono text-[9px] font-semibold uppercase tracking-[0.14em] leading-none",
        toneClasses(meta.tone),
        className
      )}
      title={title ?? meta.label}
    >
      {meta.shortLabel}
    </span>
  );
}

export function vulnClassChipClasses(tone: VulnClassTone, selected: boolean): string {
  return cn(
    "rounded-full border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wide transition-all duration-200",
    selected
      ? toneClasses(tone, true)
      : cn(toneClasses(tone), "opacity-80 hover:opacity-100 hover:-translate-y-px")
  );
}

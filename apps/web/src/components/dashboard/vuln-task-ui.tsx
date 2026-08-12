"use client";

import type {
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes
} from "react";
import { forwardRef } from "react";
import { ArrowDown, ArrowUp, ChevronsUp, Minus } from "lucide-react";
import { cn } from "../ui/cn";

export type TaskStatus = "new" | "in_progress" | "closed";

export const TASK_STATUS_COLUMNS: Array<{ key: TaskStatus; title: string }> = [
  { key: "new", title: "Новая" },
  { key: "in_progress", title: "В работе" },
  { key: "closed", title: "Закрыта" }
];

export function normalizeUiTaskStatus(st: unknown): TaskStatus {
  const s = String(st || "");
  if (s === "new" || s === "in_progress" || s === "closed") return s;
  if (s === "risk_accepted" || s === "not_applicable") return "closed";
  return s === "needs_info" || s === "fixing" || s === "mitigated" ? "in_progress" : "new";
}

/** Short Jira-like key from UUID (stable, display-only). */
export function taskIssueKey(id: string): string {
  const compact = String(id || "").replace(/-/g, "").slice(0, 8).toUpperCase();
  return compact ? `VT-${compact}` : "VT-????????";
}

export function statusMeta(st: string) {
  const s = normalizeUiTaskStatus(st);
  if (s === "in_progress") {
    return {
      label: "В работе",
      dot: "bg-accent",
      chip: "border-accent/40 bg-accent/15 text-fg/90",
      colTint: "border-t-accent",
      segmentActive: "border-accent/50 bg-accent/20 text-fg shadow-sm"
    };
  }
  if (s === "closed") {
    return {
      label: "Закрыта",
      dot: "bg-ok",
      chip: "border-ok/40 bg-ok/15 text-ok",
      colTint: "border-t-ok",
      segmentActive: "border-ok/45 bg-ok/20 text-ok shadow-sm"
    };
  }
  return {
    label: "Новая",
    dot: "bg-slate-400 dark:bg-slate-500",
    chip: "border-border bg-slate-100 text-fg/85 dark:bg-white/10 dark:text-fg/90",
    colTint: "border-t-slate-400/80",
    segmentActive: "border-border bg-slate-100 text-fg/90 shadow-sm dark:bg-white/15"
  };
}

export function scoreTone(n: number) {
  if (n >= 85) return "text-danger";
  if (n >= 70) return "text-warn";
  if (n >= 40) return "text-fg/85";
  return "text-ok";
}

export function scoreBadgeCls(n: number) {
  if (n >= 85) return "border-danger/35 bg-danger/10 text-danger";
  if (n >= 70) return "border-warn/35 bg-warn/10 text-warn";
  if (n >= 40) return "border-border bg-slate-100 text-fg/85 dark:bg-white/10";
  return "border-ok/35 bg-ok/10 text-ok";
}

export function priorityMeta(p: string) {
  const v = String(p || "medium").toLowerCase();
  if (v === "critical") {
    return {
      label: "Критичный",
      short: "Crit",
      Icon: ChevronsUp,
      cls: "text-danger",
      badge: "border-danger/35 bg-danger/10 text-danger",
      sort: 4
    };
  }
  if (v === "high") {
    return {
      label: "Высокий",
      short: "High",
      Icon: ArrowUp,
      cls: "text-warn",
      badge: "border-warn/35 bg-warn/10 text-warn",
      sort: 3
    };
  }
  if (v === "low") {
    return {
      label: "Низкий",
      short: "Low",
      Icon: ArrowDown,
      cls: "text-ok",
      badge: "border-ok/35 bg-ok/10 text-ok",
      sort: 1
    };
  }
  return {
    label: "Средний",
    short: "Med",
    Icon: Minus,
    cls: "text-muted",
    badge: "border-border bg-slate-100 text-fg/80 dark:bg-white/10",
    sort: 2
  };
}

export function PriorityMark({ priority, className }: { priority: string; className?: string }) {
  const { Icon, cls, label } = priorityMeta(priority);
  return (
    <span className={cn("inline-flex items-center gap-0.5", cls, className)} title={label}>
      <Icon className="h-3.5 w-3.5" aria-hidden />
      <span className="sr-only">{label}</span>
    </span>
  );
}

export function PriorityBadge({
  priority,
  compact,
  className
}: {
  priority: string;
  compact?: boolean;
  className?: string;
}) {
  const { Icon, label, short, badge } = priorityMeta(priority);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 border font-medium",
        compact ? "rounded px-1.5 py-0.5 text-[10px]" : "rounded-md px-2 py-0.5 text-[11px]",
        badge,
        className
      )}
      title={label}
    >
      <Icon className={cn(compact ? "h-3 w-3" : "h-3.5 w-3.5")} aria-hidden />
      {compact ? short : label}
    </span>
  );
}

export function StatusChip({ status, compact }: { status: string; compact?: boolean }) {
  const m = statusMeta(status);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 border font-semibold",
        compact ? "rounded px-1.5 py-0.5 text-[10px]" : "rounded-md px-2 py-0.5 text-[11px]",
        m.chip
      )}
    >
      <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", m.dot)} />
      {m.label}
    </span>
  );
}

export function ScoreBadge({ score, className }: { score: number; className?: string }) {
  const n = Number.isFinite(score) ? Math.round(score) : 0;
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-1.5 py-0.5 text-[11px] font-bold tabular-nums",
        scoreBadgeCls(n),
        className
      )}
      title={`Score ${n}`}
    >
      {n}
    </span>
  );
}

export function DueBadge({
  iso,
  label = "Due",
  className
}: {
  iso: string | null | undefined;
  label?: string;
  className?: string;
}) {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  const overdue = d.getTime() < Date.now();
  const text = d.toLocaleDateString("ru-RU", { day: "2-digit", month: "short" });
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-medium tabular-nums",
        overdue
          ? "border-danger/40 bg-danger/10 text-danger"
          : "border-border bg-slate-50 text-fg/75 dark:bg-white/5",
        className
      )}
      title={`${label}: ${d.toLocaleString("ru-RU")}${overdue ? " (просрочено)" : ""}`}
    >
      {label} {text}
      {overdue ? "!" : ""}
    </span>
  );
}

export function MetaRow({
  vendor,
  product,
  className
}: {
  vendor?: string | null;
  product?: string | null;
  className?: string;
}) {
  const v = String(vendor || "").trim();
  const p = String(product || "").trim();
  if (!v && !p) return null;
  return (
    <div className={cn("truncate text-[11px] text-muted", className)} title={[v, p].filter(Boolean).join(" / ")}>
      {v}
      {p ? ` / ${p}` : ""}
    </div>
  );
}

export const controlCls =
  "w-full rounded-lg border border-border bg-white px-2.5 py-2 text-[13px] text-fg outline-none ring-accent/25 transition placeholder:text-muted/70 focus:ring-2 dark:bg-black/40";

export function Field({
  label,
  hint,
  className,
  children
}: {
  label: string;
  hint?: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <label className={cn("block min-w-0", className)}>
      <span className="mb-1 block text-[11px] font-semibold uppercase tracking-wide text-fg/70">{label}</span>
      {children}
      {hint ? <span className="mt-1 block text-[10px] text-muted">{hint}</span> : null}
    </label>
  );
}

export const TextField = forwardRef<
  HTMLInputElement,
  { label: string; hint?: string; className?: string } & InputHTMLAttributes<HTMLInputElement>
>(function TextField({ label, hint, className, ...props }, ref) {
  return (
    <Field label={label} hint={hint} className={className}>
      <input {...props} ref={ref} className={controlCls} />
    </Field>
  );
});

export function SelectField({
  label,
  hint,
  className,
  children,
  ...props
}: {
  label: string;
  hint?: string;
  className?: string;
  children: ReactNode;
} & SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <Field label={label} hint={hint} className={className}>
      <select {...props} className={controlCls}>
        {children}
      </select>
    </Field>
  );
}

export const TextareaField = forwardRef<
  HTMLTextAreaElement,
  { label: string; hint?: string; className?: string } & TextareaHTMLAttributes<HTMLTextAreaElement>
>(function TextareaField({ label, hint, className, ...props }, ref) {
  return (
    <Field label={label} hint={hint}>
      <textarea {...props} ref={ref} className={cn(controlCls, "min-h-[72px] resize-y", className)} />
    </Field>
  );
});

export function SectionCard({
  title,
  action,
  children,
  className
}: {
  title: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("rounded-xl border border-border bg-slate-50/60 p-3 dark:bg-white/[0.03]", className)}>
      <div className="mb-2.5 flex items-center justify-between gap-2">
        <h3 className="text-[12px] font-semibold tracking-tight text-fg/90">{title}</h3>
        {action}
      </div>
      {children}
    </section>
  );
}

export function AssigneeAvatar({ name }: { name: string | null | undefined }) {
  const raw = String(name || "").trim();
  if (!raw) {
    return (
      <span
        className="inline-flex h-6 w-6 items-center justify-center rounded-full border border-dashed border-border text-[9px] text-muted"
        title="Без исполнителя"
      >
        —
      </span>
    );
  }
  const initials = raw
    .split(/[\s@._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0]?.toUpperCase() ?? "")
    .join("");
  return (
    <span
      className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-border bg-slate-100 text-[10px] font-semibold text-fg/85 dark:bg-white/10"
      title={raw}
    >
      {initials || "?"}
    </span>
  );
}

/** Avatar + account label for list/board density (owner = current worker). */
export function AssigneeCell({
  name,
  showLabel = true,
  emptyLabel = "—"
}: {
  name: string | null | undefined;
  showLabel?: boolean;
  emptyLabel?: string;
}) {
  const raw = String(name || "").trim();
  if (!raw) {
    return (
      <span className="inline-flex min-w-0 items-center gap-1.5 text-[11px] text-muted" title="Без исполнителя">
        <AssigneeAvatar name={null} />
        {showLabel ? <span className="truncate">{emptyLabel}</span> : null}
      </span>
    );
  }
  return (
    <span className="inline-flex min-w-0 max-w-full items-center gap-1.5" title={raw}>
      <AssigneeAvatar name={raw} />
      {showLabel ? <span className="min-w-0 truncate text-[11px] font-medium text-fg/85">{raw}</span> : null}
    </span>
  );
}

export function FilterChip({
  active,
  onClick,
  children,
  tone = "default",
  title
}: {
  active?: boolean;
  onClick: () => void;
  children: ReactNode;
  tone?: "default" | "danger" | "warn" | "accent";
  title?: string;
}) {
  const activeCls =
    tone === "danger"
      ? "border-danger/35 bg-danger/12 text-danger"
      : tone === "warn"
        ? "border-warn/35 bg-warn/12 text-warn"
        : tone === "accent"
          ? "border-accent/40 bg-accent/12 text-fg/90"
          : "border-accent/40 bg-accent/12 text-fg/90";
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      className={cn(
        "rounded-md border px-2.5 py-1 text-[11px] font-semibold transition",
        active
          ? activeCls
          : "border-border bg-white text-muted hover:bg-slate-50 hover:text-fg/85 dark:bg-black/30 dark:hover:bg-white/5"
      )}
    >
      {children}
    </button>
  );
}

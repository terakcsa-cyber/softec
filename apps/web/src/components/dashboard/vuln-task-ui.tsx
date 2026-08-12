"use client";

import type { ReactNode } from "react";
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
      chip: "border-accent/25 bg-accent/10 text-fg/80",
      colTint: "border-t-accent"
    };
  }
  if (s === "closed") {
    return {
      label: "Закрыта",
      dot: "bg-ok",
      chip: "border-ok/25 bg-ok/10 text-ok",
      colTint: "border-t-ok"
    };
  }
  return {
    label: "Новая",
    dot: "bg-muted",
    chip: "border-border bg-black/[0.03] text-fg/75 dark:bg-white/5",
    colTint: "border-t-muted/50"
  };
}

export function scoreTone(n: number) {
  if (n >= 85) return "text-danger";
  if (n >= 70) return "text-warn";
  if (n >= 40) return "text-fg/80";
  return "text-ok";
}

export function priorityMeta(p: string) {
  const v = String(p || "medium").toLowerCase();
  if (v === "critical") {
    return { label: "Критичный", Icon: ChevronsUp, cls: "text-danger", sort: 4 };
  }
  if (v === "high") {
    return { label: "Высокий", Icon: ArrowUp, cls: "text-warn", sort: 3 };
  }
  if (v === "low") {
    return { label: "Низкий", Icon: ArrowDown, cls: "text-ok", sort: 1 };
  }
  return { label: "Средний", Icon: Minus, cls: "text-muted", sort: 2 };
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

export function StatusChip({ status, compact }: { status: string; compact?: boolean }) {
  const m = statusMeta(status);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 border font-medium",
        compact ? "rounded px-1.5 py-0.5 text-[10px]" : "rounded-md px-2 py-0.5 text-[11px]",
        m.chip
      )}
    >
      <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", m.dot)} />
      {m.label}
    </span>
  );
}

export function AssigneeAvatar({ name }: { name: string | null | undefined }) {
  const raw = String(name || "").trim();
  if (!raw) {
    return (
      <span
        className="inline-flex h-5 w-5 items-center justify-center rounded-full border border-dashed border-border text-[9px] text-muted"
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
      className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-border bg-slate-100 text-[9px] font-semibold text-fg/80 dark:bg-white/10"
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
      {showLabel ? <span className="min-w-0 truncate text-[11px] text-fg/80">{raw}</span> : null}
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
      ? "border-danger/30 bg-danger/10 text-danger"
      : tone === "warn"
        ? "border-warn/30 bg-warn/10 text-warn"
        : tone === "accent"
          ? "border-accent/35 bg-accent/10 text-fg/85"
          : "border-accent/35 bg-accent/10 text-fg/85";
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      className={cn(
        "rounded border px-2 py-0.5 text-[11px] font-medium transition",
        active
          ? activeCls
          : "border-border bg-transparent text-muted hover:bg-black/[0.03] hover:text-fg/80 dark:hover:bg-white/5"
      )}
    >
      {children}
    </button>
  );
}

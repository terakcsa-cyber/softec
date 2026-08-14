export type VocCaseStatus = "open" | "in_progress" | "resolved" | "cancelled";

export const VOC_SLA_HOURS = {
  p1: 4,
  p2: 24,
  p3: 72,
  p4: 168
} as const;

export function vocCaseStatusLabel(status: VocCaseStatus): string {
  switch (status) {
    case "open":
      return "Открыт";
    case "in_progress":
      return "В работе";
    case "resolved":
      return "Закрыт";
    case "cancelled":
      return "Отменён";
  }
}

export function caseIssueKey(id: string): string {
  const compact = String(id || "").replace(/-/g, "").slice(0, 8).toUpperCase();
  return compact ? `VC-${compact}` : "VC-????????";
}

export function vocCaseStatusMeta(status: VocCaseStatus) {
  if (status === "in_progress") {
    return {
      label: "В работе",
      dot: "bg-accent",
      chip: "border-accent/40 bg-accent/15 text-fg/90",
      segmentActive: "border-accent/50 bg-accent/20 text-fg shadow-sm"
    };
  }
  if (status === "resolved") {
    return {
      label: "Закрыт",
      dot: "bg-ok",
      chip: "border-ok/40 bg-ok/15 text-ok",
      segmentActive: "border-ok/45 bg-ok/20 text-ok shadow-sm"
    };
  }
  if (status === "cancelled") {
    return {
      label: "Отменён",
      dot: "bg-slate-400",
      chip: "border-border bg-slate-100 text-muted dark:bg-white/10",
      segmentActive: "border-border bg-slate-100 text-muted shadow-sm dark:bg-white/15"
    };
  }
  return {
    label: "Открыт",
    dot: "bg-slate-400 dark:bg-slate-500",
    chip: "border-border bg-slate-100 text-fg/85 dark:bg-white/10 dark:text-fg/90",
    segmentActive: "border-border bg-slate-100 text-fg/90 shadow-sm dark:bg-white/15"
  };
}

export function isSlaBreached(slaDueAt: string | null | undefined, now = Date.now()): boolean {
  if (!slaDueAt) return false;
  const t = new Date(slaDueAt).getTime();
  return Number.isFinite(t) && t < now;
}

export function slaRemainingLabel(slaDueAt: string | null | undefined, now = Date.now()): string {
  if (!slaDueAt) return "—";
  const t = new Date(slaDueAt).getTime();
  if (!Number.isFinite(t)) return "—";
  const diffMs = t - now;
  if (diffMs <= 0) return "просрочен";
  const h = Math.floor(diffMs / 3_600_000);
  if (h >= 48) return `${Math.floor(h / 24)}д`;
  if (h >= 1) return `${h}ч`;
  const m = Math.max(1, Math.floor(diffMs / 60_000));
  return `${m}м`;
}

export function slaTone(slaDueAt: string | null | undefined, breached?: boolean): string {
  if (breached || isSlaBreached(slaDueAt)) {
    return "border-danger/40 bg-danger/12 text-danger";
  }
  if (!slaDueAt) return "border-slate-200 text-muted dark:border-white/10";
  const t = new Date(slaDueAt).getTime();
  const diffMs = t - Date.now();
  if (diffMs < 3_600_000) return "border-warn/40 bg-warn/12 text-warn";
  return "border-emerald-400/35 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";
}

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

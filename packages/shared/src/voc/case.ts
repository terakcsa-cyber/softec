import type { VocPriority, VocSource } from "./triage.js";

export const VOC_CASE_STATUSES = ["open", "in_progress", "resolved", "cancelled"] as const;
export type VocCaseStatus = (typeof VOC_CASE_STATUSES)[number];

export const VOC_SLA_HOURS: Record<VocPriority, number> = {
  p1: 4,
  p2: 24,
  p3: 72,
  p4: 168
};

export function computeSlaDueAt(priority: VocPriority, from = new Date()): string {
  const hours = VOC_SLA_HOURS[priority] ?? VOC_SLA_HOURS.p4;
  return new Date(from.getTime() + hours * 3_600_000).toISOString();
}

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

export function vocPriorityToTaskPriority(p: VocPriority): "low" | "medium" | "high" | "critical" {
  if (p === "p1") return "critical";
  if (p === "p2") return "high";
  if (p === "p3") return "medium";
  return "low";
}

/** Dedup key: same CVE/BDU/TG primary signal merges into one case. */
export function vocDedupKey(input: {
  refKey: string;
  source: VocSource;
  refId: string;
  linkedCveIds?: string[];
}): string {
  if (input.source === "cve") return input.refKey.toUpperCase();
  if (input.source === "bdu") return input.refKey.toUpperCase();
  const cve = input.linkedCveIds?.find((id) => /^CVE-\d{4}-\d+/i.test(id));
  if (cve) return cve.toUpperCase().startsWith("CVE:") ? cve.toUpperCase() : `CVE:${cve.toUpperCase()}`;
  return input.refKey.toUpperCase();
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

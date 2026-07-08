import type { VocPriority, VocTriageStatus } from "./voc-api";

/** Клиентские лейблы без barrel `@vuln-intel/shared` (тянет node:crypto → ломает Next). */
export function vocPriorityLabel(p: VocPriority): string {
  switch (p) {
    case "p1":
      return "P1";
    case "p2":
      return "P2";
    case "p3":
      return "P3";
    default:
      return "P4";
  }
}

export function vocStatusLabel(s: VocTriageStatus): string {
  switch (s) {
    case "open":
      return "В очереди";
    case "claimed":
      return "В работе";
    case "done":
      return "Обработано";
    case "dismissed":
      return "Не актуально";
  }
}

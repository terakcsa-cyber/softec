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

export function vocPriorityMeta(p: VocPriority) {
  if (p === "p1") {
    return {
      label: "P1 · Критичный",
      short: "P1",
      badge: "border-danger/35 bg-danger/10 text-danger",
      rail: "before:bg-danger"
    };
  }
  if (p === "p2") {
    return {
      label: "P2 · Высокий",
      short: "P2",
      badge: "border-warn/35 bg-warn/10 text-warn",
      rail: "before:bg-warn"
    };
  }
  if (p === "p3") {
    return {
      label: "P3 · Средний",
      short: "P3",
      badge: "border-accent/35 bg-accent/10 text-fg/85",
      rail: "before:bg-accent"
    };
  }
  return {
    label: "P4 · Низкий",
    short: "P4",
    badge: "border-border bg-slate-100 text-muted dark:bg-white/10",
    rail: "before:bg-border"
  };
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

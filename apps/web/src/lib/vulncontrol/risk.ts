import type { Severity, Vulnerability } from "./types";

type RiskInput = Pick<Vulnerability, "cvss" | "epss" | "kev" | "exploitAvailable" | "patchAvailable"> & {
  /** Дней с обнаружения. Не передаётся из каталога, чтобы не сдвигать текущие оценки. */
  ageDays?: number;
  /** Локальный тренд эксплуатации, 0–1. Точка расширения под backend-модель. */
  trend?: number;
};

/**
 * Собственная оценка VulnControl. CVSS — один из входов, не результат.
 * Формулу можно заменить ответом backend, не меняя поле riskScore в UI.
 */
export function calculateRiskScore(vulnerability: RiskInput): number {
  let score = vulnerability.cvss * 0.82;
  score += Math.min(1, Math.max(0, vulnerability.epss)) * 1.1;
  if (vulnerability.kev) score += 0.45;
  if (vulnerability.exploitAvailable) score += 0.25;
  if (!vulnerability.patchAvailable) score += 0.2;
  if (vulnerability.ageDays) score += Math.min(0.3, vulnerability.ageDays / 400);
  if (vulnerability.trend) score += Math.min(0.2, vulnerability.trend);
  const clamped = Math.min(10, Math.max(0, score));
  return Math.round(clamped * 10) / 10;
}

/** Полосы как на макете: 4.3 остаётся низкой, 6.1 — средней, 7.8 — высокой. */
export function severityFromRisk(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 5) return "medium";
  return "low";
}

export function riskColor(score: number): string {
  const severity = severityFromRisk(score);
  if (severity === "critical") return "var(--vc-critical)";
  if (severity === "high") return "var(--vc-high)";
  if (severity === "medium") return "var(--vc-medium)";
  return "var(--vc-low)";
}

/** Прозрачный оттенок: работает и с hex, и с var(--vc-*). */
export function tint(color: string, percent: number) {
  return `color-mix(in srgb, ${color} ${percent}%, transparent)`;
}

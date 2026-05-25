import type { BduListItem } from "@/components/dashboard/bdu-card";

function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n));
}

/** Оценка «приоритета» для карточки БДУ (аналог computeCvePriority). */
export function computeBduPriority(item: BduListItem): {
  score: number;
  level: "critical" | "high" | "medium" | "low";
  reasons: string[];
} {
  const reasons: string[] = [];
  const cvss = typeof item.cvssScore === "number" && Number.isFinite(item.cvssScore) ? item.cvssScore : null;
  const level = item.severityLevel ?? 0;
  let score = cvss != null ? Math.round(cvss * 10) : level * 20;

  if (item.hasExploit) {
    score += 18;
    reasons.push("Известен эксплойт (БДУ)");
  }
  if (level >= 4) {
    score += 12;
    reasons.push("Критический уровень (ФСТЭК)");
  } else if (level >= 3) {
    score += 8;
    reasons.push("Высокий уровень (ФСТЭК)");
  }
  if (cvss != null) {
    if (cvss >= 9) {
      score += 10;
      reasons.push(`CVSS ≥ 9.0 (${cvss.toFixed(1)})`);
    } else if (cvss >= 8) {
      score += 5;
      reasons.push(`CVSS ≥ 8.0 (${cvss.toFixed(1)})`);
    }
  }
  if ((item.linkedCveIds?.length ?? 0) > 0) {
    score += 4;
    reasons.push("Есть CVE в локальной базе");
  }

  score = Math.round(clamp(score, 0, 100));
  const prLevel =
    score >= 90 ? ("critical" as const) : score >= 75 ? ("high" as const) : score >= 45 ? ("medium" as const) : ("low" as const);

  if (reasons.length === 0) reasons.push("Расчёт по CVSS и классификации ФСТЭК");
  return { score, level: prLevel, reasons: reasons.slice(0, 6) };
}

/** Псевдо risk_score для правой плашки карточки (как risk_score у CVE). */
export function bduRiskScore(item: BduListItem): number | null {
  const cvss = typeof item.cvssScore === "number" && Number.isFinite(item.cvssScore) ? item.cvssScore : null;
  if (cvss == null) {
    const lvl = item.severityLevel ?? 0;
    if (lvl >= 4) return 88;
    if (lvl >= 3) return 72;
    if (lvl >= 2) return 48;
    if (lvl >= 1) return 28;
    return null;
  }
  let s = cvss * 10;
  if (item.hasExploit) s += 12;
  return Math.round(clamp(s, 0, 100));
}

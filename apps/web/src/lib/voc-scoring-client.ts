import type { VocPriority } from "./voc-api";

export function scoreTgForVoc(input: {
  score: number;
  reasons: string[];
  cveCount: number;
  hasHotCve: boolean;
}): { score: number; priority: VocPriority; reasons: string[] } {
  let score = input.score;
  const reasons = [...input.reasons];
  if (input.hasHotCve) {
    score += 10;
    reasons.push("горячий CVE в посте");
  }
  if (input.cveCount > 1) {
    score += 6;
    reasons.push("несколько CVE");
  }
  const final = Math.max(0, Math.min(100, Math.round(score)));
  const priority: VocPriority =
    final >= 85 ? "p1" : final >= 65 ? "p2" : final >= 40 ? "p3" : "p4";
  return { score: final, priority, reasons: reasons.slice(0, 8) };
}

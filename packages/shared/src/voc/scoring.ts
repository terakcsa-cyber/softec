import type { VocPriority } from "./triage.js";
import { resolveBduHasExploit, resolveBduHasFix } from "../bdu/status.js";

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n));
}

export type VocScoreResult = {
  score: number;
  priority: VocPriority;
  reasons: string[];
};

export function vocPriorityFromScore(score: number): VocPriority {
  if (score >= 85) return "p1";
  if (score >= 65) return "p2";
  if (score >= 40) return "p3";
  return "p4";
}

export type VocCveSignals = {
  cve_id: string;
  published_at?: string | null;
  risk_score?: number | null;
  epss?: number | null;
  cvss_base?: number | null;
  exploit_known?: boolean;
  vuln_class?: string | null;
  epss_spike?: boolean;
  vckev_only?: boolean;
  vulncheck_kev?: boolean;
  has_poc?: boolean;
  has_public_exploit?: boolean;
};

export function scoreCveForVoc(cve: VocCveSignals): VocScoreResult {
  let score = 0;
  const reasons: string[] = [];
  const add = (n: number, r: string) => {
    score += n;
    reasons.push(r);
  };

  if (cve.exploit_known) add(35, "KEV");
  if (cve.vckev_only) add(30, "VulnCheck KEV (не CISA)");
  else if (cve.vulncheck_kev) add(25, "VulnCheck KEV");
  if (cve.epss_spike) add(18, "EPSS spike");
  if (cve.has_public_exploit) add(15, "публичный эксплойт");
  else if (cve.has_poc) add(10, "PoC");
  const epss = typeof cve.epss === "number" && Number.isFinite(cve.epss) ? cve.epss : null;
  if (epss != null) {
    if (epss >= 0.5) add(28, `EPSS ${(epss * 100).toFixed(0)}%`);
    else if (epss >= 0.2) add(14, `EPSS ${(epss * 100).toFixed(0)}%`);
  }
  const cvss = typeof cve.cvss_base === "number" && Number.isFinite(cve.cvss_base) ? cve.cvss_base : null;
  if (cvss != null) {
    if (cvss >= 9) add(22, `CVSS ${cvss.toFixed(1)}`);
    else if (cvss >= 8) add(12, `CVSS ${cvss.toFixed(1)}`);
  }
  const risk = typeof cve.risk_score === "number" && Number.isFinite(cve.risk_score) ? cve.risk_score : null;
  if (risk != null && risk >= 70) add(10, `risk ${risk}`);

  if (cve.published_at) {
    const ageH = (Date.now() - new Date(cve.published_at).getTime()) / 3_600_000;
    if (Number.isFinite(ageH) && ageH <= 6) add(8, "свежая публикация");
  }

  if (cve.vuln_class === "rce") add(12, "класс RCE");
  else if (cve.vuln_class === "ssrf" || cve.vuln_class === "lpe") add(8, `класс ${cve.vuln_class.toUpperCase()}`);

  const final = clamp(Math.round(score), 0, 100);
  return { score: final, priority: vocPriorityFromScore(final), reasons: reasons.slice(0, 8) };
}

export type VocBduSignals = {
  bduId: string;
  hasExploit?: boolean;
  cvssScore?: number | null;
  linkedCveCount?: number;
  hasHotLinkedCve?: boolean;
  severityLevel?: number | null;
  hasFix?: boolean | null;
  fixStatus?: string | null;
  exploitStatus?: string | null;
};

/** БДУ, которые обязаны попасть в VOC: высокий/крит ФСТЭК, CVSS≥7, эксплойт или горячий CVE. */
export function isVocAttentionBdu(bdu: {
  hasExploit?: boolean;
  cvssScore?: number | null;
  severityLevel?: number | null;
  hasHotLinkedCve?: boolean;
}): boolean {
  if (bdu.hasExploit || bdu.hasHotLinkedCve) return true;
  const cvss = typeof bdu.cvssScore === "number" && Number.isFinite(bdu.cvssScore) ? bdu.cvssScore : null;
  if (cvss != null && cvss >= 7) return true;
  return (bdu.severityLevel ?? 0) >= 3;
}

export function scoreBduForVoc(bdu: VocBduSignals): VocScoreResult {
  let score = 0;
  const reasons: string[] = [];
  const add = (n: number, r: string) => {
    score += n;
    reasons.push(r);
  };

  add(22, "регулятор ФСТЭК");
  add(14, "окно внимания ФСТЭК");

  const level = typeof bdu.severityLevel === "number" && Number.isFinite(bdu.severityLevel) ? bdu.severityLevel : 0;
  if (level >= 4) add(34, "критический (ФСТЭК)");
  else if (level >= 3) add(30, "высокий (ФСТЭК)");

  const hasExploit = resolveBduHasExploit({ exploitStatus: bdu.exploitStatus, hasExploit: bdu.hasExploit });
  if (hasExploit) add(28, "эксплойт (БДУ)");
  const cvss = typeof bdu.cvssScore === "number" && Number.isFinite(bdu.cvssScore) ? bdu.cvssScore : null;
  if (cvss != null) {
    if (cvss >= 9) add(20, `CVSS ${cvss.toFixed(1)}`);
    else if (cvss >= 8) add(12, `CVSS ${cvss.toFixed(1)}`);
    else if (cvss >= 7) add(8, `CVSS ${cvss.toFixed(1)}`);
  }
  if (bdu.hasHotLinkedCve) add(16, "горячий связанный CVE");
  else if ((bdu.linkedCveCount ?? 0) > 0) add(8, "связь с CVE");

  const hasFix = resolveBduHasFix({ fixStatus: bdu.fixStatus, hasFix: bdu.hasFix });
  if (hasFix === false && (level >= 3 || (cvss != null && cvss >= 7))) {
    add(10, "нет исправления (ФСТЭК)");
  }

  const final = clamp(Math.round(score), 0, 100);
  return { score: final, priority: vocPriorityFromScore(final), reasons: reasons.slice(0, 8) };
}

export function scoreTgForVoc(input: {
  score: number;
  reasons: string[];
  cveCount: number;
  hasHotCve: boolean;
}): VocScoreResult {
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
  const final = clamp(Math.round(score), 0, 100);
  return { score: final, priority: vocPriorityFromScore(final), reasons: reasons.slice(0, 8) };
}

/**
 * Client-safe catalog for vulnerability class chips/badges.
 * Keep in sync with `packages/shared/src/cve/vuln-class-filter.ts`.
 */
export const VULN_CLASS_IDS = [
  "rce",
  "lpe",
  "ssrf",
  "sqli",
  "xss",
  "path",
  "auth",
  "info",
  "dos"
] as const;

export type VulnClassId = (typeof VULN_CLASS_IDS)[number];

export type VulnClassTone = "critical" | "high" | "medium" | "low" | "neutral";

export type VulnClassMeta = {
  id: VulnClassId;
  label: string;
  shortLabel: string;
  tone: VulnClassTone;
};

export const VULN_CLASS_CATALOG: readonly VulnClassMeta[] = [
  { id: "rce", label: "Remote Code Execution", shortLabel: "RCE", tone: "critical" },
  { id: "lpe", label: "Privilege Escalation", shortLabel: "LPE", tone: "high" },
  { id: "ssrf", label: "Server-Side Request Forgery", shortLabel: "SSRF", tone: "high" },
  { id: "sqli", label: "SQL Injection", shortLabel: "SQLi", tone: "medium" },
  { id: "xss", label: "Cross-Site Scripting", shortLabel: "XSS", tone: "medium" },
  { id: "path", label: "Path Traversal", shortLabel: "PATH", tone: "low" },
  { id: "auth", label: "Auth / Authorization Bypass", shortLabel: "AUTH", tone: "medium" },
  { id: "info", label: "Information Disclosure", shortLabel: "INFO", tone: "neutral" },
  { id: "dos", label: "Denial of Service", shortLabel: "DoS", tone: "low" }
] as const;

const VULN_CLASS_ID_SET = new Set<string>(VULN_CLASS_IDS);

export function isVulnClassId(value: string): value is VulnClassId {
  return VULN_CLASS_ID_SET.has(value);
}

export function vulnClassMeta(id: string | null | undefined): VulnClassMeta | null {
  if (!id || !isVulnClassId(id)) return null;
  return VULN_CLASS_CATALOG.find((x) => x.id === id) ?? null;
}

export function parseVulnClassFilter(raw: string | string[] | undefined): VulnClassId[] {
  const chunks = Array.isArray(raw) ? raw : raw ? [raw] : [];
  const out: VulnClassId[] = [];
  const seen = new Set<VulnClassId>();
  for (const chunk of chunks) {
    for (const part of String(chunk).split(",")) {
      const id = part.trim().toLowerCase();
      if (!isVulnClassId(id) || seen.has(id)) continue;
      seen.add(id);
      out.push(id);
    }
  }
  return out;
}

export function toggleVulnClassSelection(current: VulnClassId[], id: VulnClassId): VulnClassId[] {
  return current.includes(id) ? current.filter((x) => x !== id) : [...current, id];
}

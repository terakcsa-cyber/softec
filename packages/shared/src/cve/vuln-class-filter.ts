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

/** UI + API catalog — keep ids stable for saved views and SQL filters. */
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

/** Accepts repeated query params and comma-separated lists. */
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

/** Requires lateral alias `ea1` and table alias `c` in the surrounding SQL. */
export const SQL_VULN_CLASS_TEXT_EXPR = `lower(COALESCE(
  ea1.output_json->>'vulnerabilityClass',
  ea1.output_json->'raw_model_json'->>'vulnerabilityClass',
  c.raw->'descriptions'->0->>'value',
  c.raw->'cve'->'descriptions'->0->>'value',
  c.raw->'cve'->'description'->'description_data'->0->>'value',
  c.raw->'description'->'description_data'->0->>'value',
  ''
))`;

/** Requires table alias `c`. */
export const SQL_VULN_CLASS_CWE_EXPR = `lower(COALESCE(c.raw->'weaknesses'->0->'description'->0->>'value', ''))`;

export function sqlVulnClassGuessExpr(): string {
  const textExpr = SQL_VULN_CLASS_TEXT_EXPR;
  const cweExpr = SQL_VULN_CLASS_CWE_EXPR;
  return `(
    CASE
      WHEN ${textExpr} ~ '(remote code execution|arbitrary code execution|execute arbitrary code|\\brce\\b)'
        OR ${cweExpr} ~ 'cwe-(78|94|434|502|787|119|120|416)' THEN 'rce'
      WHEN ${textExpr} ~ '(privilege escalation|elevation of privilege|\\blpe\\b)'
        OR ${cweExpr} ~ 'cwe-(269|264|287|862)' THEN 'lpe'
      WHEN ${textExpr} ~ '(server-side request forgery|\\bssrf\\b)'
        OR ${cweExpr} ~ 'cwe-918' THEN 'ssrf'
      WHEN ${textExpr} ~ '(sql injection|\\bsqli\\b)'
        OR ${cweExpr} ~ 'cwe-89' THEN 'sqli'
      WHEN ${textExpr} ~ '(cross-site scripting|\\bxss\\b)'
        OR ${cweExpr} ~ 'cwe-79' THEN 'xss'
      WHEN ${textExpr} ~ '(path traversal|directory traversal)'
        OR ${cweExpr} ~ 'cwe-22' THEN 'path'
      WHEN ${textExpr} ~ '(denial of service|\\bdos\\b)'
        OR ${cweExpr} ~ 'cwe-400' THEN 'dos'
      WHEN ${textExpr} ~ '(information disclosure|information exposure|leak)'
        OR ${cweExpr} ~ 'cwe-200' THEN 'info'
      WHEN ${textExpr} ~ '(authentication bypass|authorization bypass|improper authentication|missing authorization|missing authentication)'
        OR ${cweExpr} ~ 'cwe-(287|306|862)' THEN 'auth'
      ELSE NULL
    END
  )`;
}

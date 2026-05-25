import { normalizeBduId, normalizeCveId } from "./id.js";

export type BduVulxmlRecord = {
  bduId: string;
  name: string;
  description: string;
  softwareNames: string;
  vendors: string;
  cveIds: string[];
  severity: string;
  severityLevel: number;
  cvssScore: number | null;
  cvssVector: string;
  identifyDate: string;
  publicationDate: string;
  lastUpdDate: string;
  identifyYear: number | null;
  solution: string;
  status: string;
  exploitStatus: string;
  fixStatus: string;
  hasExploit: boolean;
  hasFix: boolean;
  sources: string;
};

const SEVERITY_LEVEL: Record<string, number> = {
  критический: 4,
  высокий: 3,
  средний: 2,
  низкий: 1
};

function pickText(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "string") return v.trim();
  if (typeof v === "object" && v !== null && "#text" in v) {
    return String((v as { "#text": unknown })["#text"]).trim();
  }
  return String(v).trim();
}

function severityLevel(text: string): number {
  const t = (text || "").toLowerCase();
  for (const [keyword, level] of Object.entries(SEVERITY_LEVEL)) {
    if (t.includes(keyword)) return level;
  }
  return 0;
}

export function parseIdentifyYear(identifyDate: string): number | null {
  if (!identifyDate) return null;
  const parts = identifyDate.trim().split(".");
  if (parts.length !== 3) return null;
  const y = Number(parts[2]);
  return Number.isInteger(y) ? y : null;
}

function extractCves(vul: Record<string, unknown>): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const identifiers = vul.identifiers as Record<string, unknown> | undefined;
  const rawIdents = identifiers?.identifier;
  const rows = Array.isArray(rawIdents) ? rawIdents : rawIdents ? [rawIdents] : [];
  for (const row of rows) {
    if (!row || typeof row !== "object") continue;
    const o = row as Record<string, unknown>;
    const type = String(o["@_type"] ?? o.type ?? "").toUpperCase();
    if (type !== "CVE") continue;
    const cve = normalizeCveId(pickText(o));
    if (cve && !seen.has(cve)) {
      seen.add(cve);
      out.push(cve);
    }
  }
  return out;
}

function extractSoftware(vul: Record<string, unknown>): { softwareNames: string[]; vendors: string[] } {
  const softwareNames: string[] = [];
  const vendors: string[] = [];
  const vs = vul.vulnerable_software as Record<string, unknown> | undefined;
  const rawSoft = vs?.soft;
  const rows = Array.isArray(rawSoft) ? rawSoft : rawSoft ? [rawSoft] : [];
  for (const row of rows) {
    if (!row || typeof row !== "object") continue;
    const soft = row as Record<string, unknown>;
    const sn = pickText(soft.name);
    const sv = pickText(soft.vendor);
    if (sn) softwareNames.push(sn);
    if (sv) vendors.push(sv);
  }
  return { softwareNames, vendors };
}

/** Разбор одного узла `<vul>` из официальной XML-выгрузки БДУ ФСТЭК. */
export function parseBduVulNode(vul: unknown): BduVulxmlRecord | null {
  if (!vul || typeof vul !== "object") return null;
  const row = vul as Record<string, unknown>;
  const bduId = normalizeBduId(pickText(row.identifier));
  if (!bduId) return null;

  const name = pickText(row.name);
  const description = pickText(row.description);
  const severity = pickText(row.severity);
  const cvssEl = row.cvss as Record<string, unknown> | undefined;
  const vectorEl = cvssEl?.vector as Record<string, unknown> | undefined;
  let cvssScore: number | null = null;
  let cvssVector = "";
  if (vectorEl && typeof vectorEl === "object") {
    const raw = String(vectorEl["@_score"] ?? vectorEl.score ?? "")
      .replace(",", ".")
      .trim();
    if (raw) {
      const n = Number(raw);
      cvssScore = Number.isFinite(n) ? n : null;
    }
    cvssVector = pickText(vectorEl);
  }

  const identifyDate = pickText(row.identify_date);
  const publicationDate = pickText(row.publication_date);
  const lastUpdDate = pickText(row.last_upd_date);
  const exploitStatus = pickText(row.exploit_status);
  const fixStatus = pickText(row.fix_status);
  const { softwareNames, vendors } = extractSoftware(row);

  return {
    bduId,
    name: name || `BDU:${bduId}`,
    description,
    softwareNames: softwareNames.join(" "),
    vendors: vendors.join(" "),
    cveIds: extractCves(row),
    severity,
    severityLevel: severityLevel(severity),
    cvssScore,
    cvssVector,
    identifyDate,
    publicationDate,
    lastUpdDate,
    identifyYear: parseIdentifyYear(identifyDate),
    solution: pickText(row.solution),
    status: pickText(row.vul_status),
    exploitStatus,
    fixStatus,
    hasExploit: exploitStatus.toLowerCase().includes("существует"),
    hasFix: fixStatus.toLowerCase().includes("имеется"),
    sources: pickText(row.sources)
  };
}

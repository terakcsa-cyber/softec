import { apiFetch } from "@/lib/api-fetch";
import { cvssBand, type CveDetail, type LiveTask } from "./live";

export type VulnCard = {
  id: string;
  title: string;
  description: string;
  nvdText: string | null;
  aiNote: string | null;
  ai: {
    note: string;
    facts: string[];
    remediation: string[];
    exploitNotes: string | null;
    publicExploit: "yes" | "no" | "unknown" | null;
    vulnClass: string | null;
    attack: Array<{ role: "condition" | "entry" | "weakness" | "impact"; title: string; detail: string }>;
    sources: Array<{ url: string; title: string }>;
  } | null;
  cwe: string | null;
  severity: { key: string; label: string; color: string } | null;
  riskScore: number | null;
  cvss: number | null;
  cvssVector: string | null;
  epss: number | null;
  kev: boolean;
  poc: boolean;
  publicExploit: boolean;
  source: string | null;
  publishedAt: string | null;
  modifiedAt: string | null;
  vendor: string | null;
  product: string | null;
  products: Array<{ vendor: string; product: string }>;
  affectedVersions: string[];
  fixedIn: string[];
  remediation: string[];
  patchLinks: Array<{ label: string; url: string }>;
  bduIds: string[];
  kevDetail: {
    dateAdded: string | null;
    dueDate: string | null;
    requiredAction: string | null;
    ransomwareUse: string | null;
    name: string | null;
  } | null;
  bdu: Array<{
    id: string;
    name: string | null;
    solution: string | null;
    exploitStatus: string | null;
    fixStatus: string | null;
    hasExploit: boolean;
    hasFix: boolean;
  }>;
  facts: Array<{
    source: string;
    factType: string;
    title: string | null;
    detail: string | null;
    url: string | null;
    updatedAt: string | null;
  }>;
  links: { nvd?: string; kev?: string; epss?: string };
  advisories: Array<{ title: string; link: string; vendorSlug: string }>;
  signals: Array<{ at: string | null; source: string; type: string; title: string; url: string | null }>;
  nuclei: boolean;
  tasks: LiveTask[];
};

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function text(value: unknown) {
  return typeof value === "string" ? value.trim() : "";
}

function lines(value: unknown) {
  if (Array.isArray(value)) return value.map((item) => text(item)).filter(Boolean);
  const one = text(value);
  return one ? [one] : [];
}

function covered(existing: string[], line: string) {
  const nums = line.match(/\d+\.\d+(?:\.\d+)*/g) ?? [];
  if (!nums.length) return true;
  return nums.every((num) => existing.some((item) => item.includes(num)));
}

function mergeVersions(existing: string[], incoming: string[]) {
  const out = [...existing];
  for (const line of incoming) {
    if (!line || line.length > 48 || covered(out, line) || out.includes(line)) continue;
    if (out.length < 12) out.push(line);
  }
  return out;
}

function closingVersions(rows: string[]) {
  const out: string[] = [];
  const push = (value: string) => {
    if (/\d+\.\d+/.test(value) && !out.includes(value) && out.length < 8) out.push(value);
  };
  for (const row of rows) {
    const closers = [...row.matchAll(/(?:до|before|версии|version)\s+(\d+\.\d+(?:\.\d+)*)/gi)].map((match) => match[1] ?? "").filter(Boolean);
    if (closers.length) {
      closers.forEach(push);
      continue;
    }
    const only = row.match(/\d+\.\d+(?:\.\d+)*/g) ?? [];
    if (only.length === 1 && only[0]) push(only[0]);
  }
  return out;
}

function attackStages(value: unknown) {
  if (!Array.isArray(value)) return [];
  const roles = ["condition", "entry", "weakness", "impact"] as const;
  return value.flatMap((item) => {
    const row = asRecord(item);
    const role = text(row?.role);
    if (!roles.includes(role as (typeof roles)[number])) return [];
    const title = text(row?.title).replace(/^(условие|точка входа|слабое место|результат)\s*:\s*/i, "");
    const detail = text(row?.detail);
    if (!title || !detail) return [];
    if (/не раскрыт|нет в сыр|не указан в материал|недостаточно данных/i.test(detail)) return [];
    return [{ role: role as (typeof roles)[number], title, detail }];
  }).slice(0, 4);
}

function sourcesOf(value: unknown) {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const row = asRecord(item);
    const url = text(row?.url);
    if (!url.startsWith("http")) return [];
    return [{ url, title: text(row?.title) || url }];
  }).slice(0, 8);
}

function nvdDescription(raw: unknown) {
  const root = asRecord(raw);
  const cve = asRecord(root?.cve) ?? root;
  const descriptions = Array.isArray(cve?.descriptions) ? cve.descriptions : [];
  const english = descriptions.find((item) => text(asRecord(item)?.lang) === "en");
  return text(asRecord(english)?.value);
}

export function formatEpss(epss: number | null | undefined) {
  if (epss == null || !Number.isFinite(epss)) return "—";
  const pct = epss * 100;
  if (pct >= 10) return `${Math.round(pct)}%`;
  if (pct >= 1) return `${pct.toFixed(1)}%`;
  return `${pct.toFixed(2)}%`;
}

function versionLabel(match: Record<string, unknown>) {
  const start = text(match.versionStartIncluding);
  const endEx = text(match.versionEndExcluding);
  const endIn = text(match.versionEndIncluding);
  if (start || endEx || endIn) {
    return [start ? `от ${start}` : "", endEx ? `до ${endEx}` : "", endIn ? `по ${endIn}` : ""].filter(Boolean).join(" ");
  }
  const criteria = text(match.criteria || match.cpe23Uri);
  const version = criteria.split(":")[5] ?? "";
  if (!version || version === "*" || version === "-") return "";
  return version.replace(/_/g, " ");
}

function collectVersions(raw: unknown) {
  const root = asRecord(raw);
  const configs = root?.configurations ?? asRecord(root?.cve)?.configurations;
  const affected: string[] = [];
  const fixed: string[] = [];
  const visit = (node: unknown) => {
    if (Array.isArray(node)) {
      node.forEach(visit);
      return;
    }
    const rec = asRecord(node);
    if (!rec) return;
    const matches = rec.cpeMatch ?? rec.cpe_match;
    if (Array.isArray(matches)) {
      for (const item of matches) {
        const match = asRecord(item);
        if (!match) continue;
        const label = versionLabel(match);
        if (!label) continue;
        const bucket = match.vulnerable === false ? fixed : affected;
        if (!bucket.includes(label) && bucket.length < 8) bucket.push(label);
      }
    }
    if (Array.isArray(rec.nodes)) visit(rec.nodes);
  };
  visit(configs);
  return { affected, fixed };
}

function patchLinksFrom(raw: unknown) {
  const root = asRecord(raw);
  const refs = root?.references ?? asRecord(root?.cve)?.references;
  if (!Array.isArray(refs)) return [];
  const links: Array<{ label: string; url: string }> = [];
  for (const item of refs) {
    const rec = asRecord(item);
    const url = text(rec?.url);
    const tags = Array.isArray(rec?.tags) ? rec.tags.map((tag) => text(tag).toLowerCase()) : [];
    if (!url || !tags.some((tag) => tag.includes("patch") || tag.includes("vendor advisory"))) continue;
    links.push({ label: tags.includes("patch") ? "Патч" : "Advisory", url });
    if (links.length >= 6) break;
  }
  return links;
}

function cvssVector(raw: unknown) {
  const root = asRecord(raw);
  const metrics = asRecord(root?.metrics) ?? asRecord(asRecord(root?.cve)?.metrics);
  const v31 = Array.isArray(metrics?.cvssMetricV31) ? asRecord(metrics?.cvssMetricV31[0]) : null;
  const v30 = Array.isArray(metrics?.cvssMetricV30) ? asRecord(metrics?.cvssMetricV30[0]) : null;
  const from31 = text(asRecord(v31?.cvssData)?.vectorString);
  const from30 = text(asRecord(v30?.cvssData)?.vectorString);
  return from31 || from30 || null;
}

export function buildVulnCard(cveId: string, detail: CveDetail | undefined, tasks: LiveTask[]): VulnCard | null {
  const cve = detail?.found ? detail.cve : undefined;
  if (!cve) return null;
  const json = detail?.ai?.output_json ?? {};
  const facts = lines(json.facts);
  const point = text(json.pointNote);
  const aiNote = facts.length ? point || "Дополнительная фактура из открытых источников." : null;
  const attack = attackStages(asRecord(json.attack)?.stages);
  const exploit = asRecord(json.exploitation);
  const exploitFlag = text(exploit?.publicExploit);
  const publicFromAi = exploitFlag === "yes" || exploitFlag === "no" || exploitFlag === "unknown" ? exploitFlag : null;
  const nvd = nvdDescription(cve.raw);
  const products = detail?.vendorProducts ?? [];
  const productName = products[0]?.product || products[0]?.vendor || "";
  const titleRaw = text(json.title);
  const title = point || aiNote
    ? `${cve.cve_id || cveId}${productName ? `: ${productName}` : ""}`
    : titleRaw && titleRaw !== "Комплексный анализ уязвимости"
      ? titleRaw
      : text(json.summary).split("\n")[0]?.slice(0, 180) || "Карточка CVE";
  const aiText = text(json.description) || text(json.summary) || detail?.ai?.output_text || "";
  const description = nvd || aiText;
  const versions = collectVersions(cve.raw);
  const patchLinks = patchLinksFrom(cve.raw);
  const signals = (detail?.exploitIntel?.signals ?? [])
    .filter((signal) => signal.signal_type !== "nvd_refs_scanned")
    .map((signal) => ({
      at: signal.last_seen_at,
      source: signal.source,
      type: signal.signal_type,
      title: signal.title || signal.signal_type,
      url: signal.url
    }));
  const score = typeof cve.risk_score === "string" ? Number(cve.risk_score) : cve.risk_score;
  const cvss = typeof cve.cvss_base === "string" ? Number(cve.cvss_base) : cve.cvss_base;
  const epss = typeof cve.epss === "string" ? Number(cve.epss) : cve.epss;
  return {
    id: cve.cve_id || cveId,
    title,
    description,
    nvdText: nvd || null,
    aiNote,
    ai: aiNote
      ? {
          note: aiNote,
          facts,
          remediation: lines(json.remediation),
          exploitNotes: text(exploit?.exploitNotes) || null,
          publicExploit: publicFromAi,
          vulnClass: text(json.vulnerabilityClass) || null,
          attack,
          sources: sourcesOf(json.sources)
        }
      : null,
    cwe: text(json.vulnerabilityClass) || null,
    severity: cvssBand(cvss),
    riskScore: Number.isFinite(score) ? score : null,
    cvss: Number.isFinite(cvss) ? cvss : null,
    cvssVector: cvssVector(cve.raw),
    epss: Number.isFinite(epss) ? epss : null,
    kev: Boolean(cve.exploit_known),
    poc: Boolean(cve.has_poc) || signals.some((signal) => signal.type === "poc_github" || signal.type === "poc_public"),
    publicExploit: Boolean(cve.has_public_exploit) || publicFromAi === "yes" || signals.some((signal) => signal.type === "exploit_db" || signal.type === "metasploit" || signal.type === "nvd_exploit_tag"),
    source: cve.source,
    publishedAt: cve.published_at,
    modifiedAt: cve.modified_at,
    vendor: products[0]?.vendor ?? null,
    product: products[0]?.product ?? null,
    products,
    affectedVersions: mergeVersions(versions.affected, lines(json.affectedVersions)),
    fixedIn: mergeVersions(versions.fixed, closingVersions(lines(json.fixedVersions).concat(lines(json.remediation)))),
    remediation: lines(json.remediation),
    patchLinks,
    bduIds: cve.bdu_ids ?? [],
    kevDetail: detail?.kev ?? null,
    bdu: detail?.bdu ?? [],
    facts: detail?.contextFacts ?? [],
    links: detail?.links ?? {},
    advisories: (detail?.vendorAdvisories ?? []).filter((item) => item.link),
    signals,
    nuclei: signals.some((signal) => signal.type === "nuclei"),
    tasks
  };
}

export function priorityFor(card: VulnCard) {
  if (card.cvss != null && card.cvss >= 9) return "critical";
  if (card.cvss != null && card.cvss >= 7) return "high";
  if (card.cvss != null && card.cvss >= 4) return "medium";
  return "low";
}

export async function createRemediationTask(card: VulnCard) {
  if (!card.vendor) throw new Error("У записи нет вендора, задачу создать нельзя");
  const kevDueRaw = card.kevDetail?.dueDate?.trim() || null;
  const kevDueMs = kevDueRaw ? Date.parse(kevDueRaw) : NaN;
  const res = await apiFetch("/api/vuln-tasks", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      title: `Устранение ${card.id}`,
      vendorKey: card.vendor.toLowerCase().replace(/\s+/g, "_"),
      vendorDisplay: card.vendor,
      productKeyNorm: card.product ? card.product.toLowerCase().replace(/\s+/g, "_") : null,
      productDisplay: card.product,
      priorityLocal: priorityFor(card),
      dueDate: Number.isFinite(kevDueMs) ? new Date(kevDueMs).toISOString() : null,
      cveIds: [card.id]
    })
  });
  if (!res.ok) throw new Error(`Задача не создана (${res.status})`);
  return (await res.json()) as { id: string };
}

export async function patchTask(id: string, body: { owner?: string | null; status?: string; notesMd?: string; dueDate?: string | null }) {
  const res = await apiFetch(`/api/vuln-tasks/${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(`Задача не обновлена (${res.status})`);
}

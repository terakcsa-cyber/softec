export type TgFeedChannel = { slug: string; title: string };

export type TgFeedItem = {
  id: string;
  title: string;
  link: string;
  pubDate: string | null;
  descriptionText: string;
  channel: TgFeedChannel;
  cveIds: string[];
};

export type TgFeedResponse = {
  items: TgFeedItem[];
  source: { fetchedAt: string; kind: string; channels: TgFeedChannel[] };
  errors?: { url: string; error: string }[];
};

export type TgCveIntel = {
  cve_id: string;
  risk_score: number | null;
  epss?: number | null;
  cvss_base?: number | null;
  exploit_known?: boolean;
  vp_vendor?: string | null;
  vp_product?: string | null;
  short_ru?: string | null;
  short_description?: string | null;
};

export type TgCriticalRow = {
  item: TgFeedItem;
  score: number;
  reasons: string[];
  criticalCveIds: string[];
  cveIntel: TgCveIntel[];
};

const CRITICAL_TEXT =
  /\b(0\s*day|0day|zero[\s-]?day|actively\s+exploited|in\s+the\s+wild|emergency\s+patch|critical\s+vuln|remote\s+code\s+execution|\brce\b|публичн\w*\s+эксплойт|эксплуатируется|срочн\w*|критич\w*|уязвимост\w*\s+нулев\w*\s+дн\w*|kev\b|cisa\b|\bpoc\b|wormable|mass\s+exploitation)\b/i;

const HOURS_24_MS = 24 * 60 * 60 * 1000;

export function isWithinLast24h(pubDate: string | null | undefined, now = Date.now()): boolean {
  if (!pubDate) return false;
  const t = new Date(pubDate).getTime();
  return Number.isFinite(t) && now - t <= HOURS_24_MS;
}

export function textLooksCritical(text: string): boolean {
  return CRITICAL_TEXT.test(text);
}

export function cveIntelIsHot(cve: TgCveIntel): boolean {
  const highEpss = typeof cve.epss === "number" && cve.epss >= 0.5;
  const criticalCvss = typeof cve.cvss_base === "number" && cve.cvss_base >= 9;
  const highRisk = typeof cve.risk_score === "number" && cve.risk_score >= 70;
  return Boolean(cve.exploit_known) || highEpss || criticalCvss || highRisk;
}

export function scoreTgFeedItem(item: TgFeedItem, intelByCve: Map<string, TgCveIntel>): {
  score: number;
  reasons: string[];
  criticalCveIds: string[];
  cveIntel: TgCveIntel[];
} {
  const text = `${item.title}\n${item.descriptionText ?? ""}`.trim();
  let score = 0;
  const reasons: string[] = [];
  const cveIntel: TgCveIntel[] = [];
  const criticalCveIds: string[] = [];

  for (const id of item.cveIds ?? []) {
    const key = id.toUpperCase();
    const intel = intelByCve.get(key) ?? intelByCve.get(id);
    if (intel) cveIntel.push(intel);
    if (intel && cveIntelIsHot(intel)) {
      criticalCveIds.push(id);
      score += 35;
      if (intel.exploit_known) {
        score += 25;
        reasons.push(`${id}: KEV`);
      } else if (typeof intel.epss === "number" && intel.epss >= 0.5) {
        score += 18;
        reasons.push(`${id}: EPSS ${(intel.epss * 100).toFixed(0)}%`);
      } else if (typeof intel.cvss_base === "number" && intel.cvss_base >= 9) {
        score += 15;
        reasons.push(`${id}: CVSS ${intel.cvss_base.toFixed(1)}`);
      } else {
        reasons.push(`${id}: высокий риск`);
      }
    } else if (intel) {
      score += 8;
    } else if (id) {
      score += 12;
      reasons.push(`${id}: упоминание в TG`);
    }
  }

  if ((item.cveIds?.length ?? 0) > 0 && score < 20) score += 16;

  if (textLooksCritical(text)) {
    score += 28;
    reasons.push("критичный сигнал в тексте");
  }

  if (item.cveIds.length >= 2) {
    score += 10;
    reasons.push("несколько CVE в посте");
  }

  return { score, reasons: [...new Set(reasons)], criticalCveIds, cveIntel };
}

export function buildTgCriticalRows(
  items: TgFeedItem[],
  intelByCve: Map<string, TgCveIntel>,
  opts?: { minScore?: number; now?: number }
): TgCriticalRow[] {
  const minScore = opts?.minScore ?? 28;
  const now = opts?.now ?? Date.now();
  const rows: TgCriticalRow[] = [];

  for (const item of items) {
    if (!isWithinLast24h(item.pubDate, now)) continue;
    const scored = scoreTgFeedItem(item, intelByCve);
    const hasHotCve = scored.criticalCveIds.length > 0;
    const hasCve = (item.cveIds?.length ?? 0) > 0;
    const hotText = textLooksCritical(`${item.title}\n${item.descriptionText ?? ""}`);
    if (scored.score < minScore && !hasHotCve && !(hasCve && hotText)) continue;
    rows.push({ item, ...scored });
  }

  return rows.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    const ta = a.item.pubDate ? new Date(a.item.pubDate).getTime() : 0;
    const tb = b.item.pubDate ? new Date(b.item.pubDate).getTime() : 0;
    return tb - ta;
  });
}

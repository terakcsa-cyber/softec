import type { FstecFeedItem, FstecLocalBduLink } from "./fstec-rss";
import { extractBduCvePairs } from "./fstec-bdu-cve";
import { getUpstreamApiBase } from "./upstream-api";

export type LocalBduEnrichmentStatus = "ok" | "unavailable" | "noop";

function dedupeLinks(links: FstecLocalBduLink[]): FstecLocalBduLink[] {
  const seen = new Set<string>();
  const out: FstecLocalBduLink[] = [];
  for (const l of links) {
    const k = `${l.cveId}|${l.bduId}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(l);
  }
  return out;
}

async function lookupCvesPresent(
  cveIds: string[],
  authorization?: string | null
): Promise<Set<string> | null> {
  if (cveIds.length === 0) return new Set();
  const base = getUpstreamApiBase();
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json"
  };
  if (authorization) headers.authorization = authorization;
  const res = await fetch(`${base}/cves/lookup`, {
    method: "POST",
    headers,
    body: JSON.stringify({ cveIds }),
    cache: "no-store"
  });
  if (!res.ok) return null;
  const data = (await res.json()) as { present?: string[] };
  return new Set(data.present ?? []);
}

/** Дополняет элементы ленты связками BDU↔CVE, если CVE есть в таблице `cve`. */
export async function enrichFeedItemsWithLocalBdu(
  items: FstecFeedItem[],
  opts?: { authorization?: string | null }
): Promise<LocalBduEnrichmentStatus> {
  const perItem = new Map<FstecFeedItem, { bduId: string; cveId: string }[]>();
  const allCves = new Set<string>();

  for (const item of items) {
    const pairs = extractBduCvePairs(`${item.title}\n${item.descriptionText}`);
    if (pairs.length === 0) continue;
    perItem.set(item, pairs);
    for (const p of pairs) allCves.add(p.cveId);
  }

  if (allCves.size === 0) return "noop";

  let present: Set<string> | null;
  try {
    present = await lookupCvesPresent([...allCves], opts?.authorization);
  } catch {
    return "unavailable";
  }
  if (present === null) return "unavailable";

  for (const [item, pairs] of perItem) {
    const links = dedupeLinks(
      pairs.filter((p) => present.has(p.cveId)).map((p) => ({ cveId: p.cveId, bduId: p.bduId }))
    );
    if (links.length > 0) item.localBduLinks = links;
  }
  return "ok";
}

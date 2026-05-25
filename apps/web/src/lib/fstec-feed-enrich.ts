import type { FstecFeedItem, FstecLocalBduLink, FstecRegistryBduLink } from "./fstec-rss";
import { extractBduCvePairs, extractBduIds } from "./fstec-bdu-cve";
import { getUpstreamApiBase } from "./upstream-api";
import { forwardAuthHeaders } from "./upstream-proxy";

export type LocalBduEnrichmentStatus = "ok" | "unavailable" | "noop";

const LOOKUP_CHUNK = 2500;
const BDU_LINKS_POST_CHUNK = 500;

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

/** Bearer от клиента или сервисный токен (тот же `INTERNAL_API_BEARER`, что у Nest) — для lookup/sync без сессии в браузере. */
export function resolveFstecUpstreamAuth(authorizationFromRequest?: string | null): Record<string, string> | null {
  const a = authorizationFromRequest?.trim();
  if (a) return { authorization: a };
  const internal = process.env.INTERNAL_API_BEARER?.trim();
  if (internal) return { authorization: `Bearer ${internal}` };
  return null;
}

async function lookupCvesPresentBatched(
  cveIds: string[],
  auth: Record<string, string> | null
): Promise<Set<string> | null> {
  if (cveIds.length === 0) return new Set();
  if (!auth) return new Set();

  const base = getUpstreamApiBase();
  const uniq = [...new Set(cveIds.map((id) => id.trim().toUpperCase()).filter((id) => /^CVE-\d{4}-\d+$/.test(id)))];
  const present = new Set<string>();

  for (let i = 0; i < uniq.length; i += LOOKUP_CHUNK) {
    const chunk = uniq.slice(i, i + LOOKUP_CHUNK);
    const res = await fetch(`${base}/cves/lookup`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        ...auth
      },
      body: JSON.stringify({ cveIds: chunk }),
      cache: "no-store"
    });
    if (res.status === 401 || res.status === 403) return new Set();
    if (!res.ok) return null;
    const data = (await res.json()) as { present?: string[] };
    for (const id of data.present ?? []) present.add(id);
  }
  return present;
}

/** Дополняет элементы ленты связками BDU↔CVE, если CVE уже есть в таблице `cve`. */
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

  const auth = resolveFstecUpstreamAuth(opts?.authorization ?? null);
  let present: Set<string> | null;
  try {
    present = await lookupCvesPresentBatched([...allCves], auth);
  } catch {
    return "unavailable";
  }
  if (present === null) return "unavailable";
  if (present.size === 0) return "noop";

  for (const [item, pairs] of perItem) {
    const links = dedupeLinks(
      pairs.filter((p) => present.has(p.cveId)).map((p) => ({ cveId: p.cveId, bduId: p.bduId }))
    );
    if (links.length > 0) item.localBduLinks = links;
  }
  return "ok";
}

async function lookupBduRegistryBatched(
  bduIds: string[],
  auth: Record<string, string> | null
): Promise<Map<string, FstecRegistryBduLink> | null> {
  if (bduIds.length === 0) return new Map();
  if (!auth) return new Map();
  const base = getUpstreamApiBase();
  const uniq = [...new Set(bduIds.map((id) => id.trim()).filter((id) => /^\d{4}-\d+$/.test(id)))];
  const out = new Map<string, FstecRegistryBduLink>();
  const chunk = 200;
  for (let i = 0; i < uniq.length; i += chunk) {
    const slice = uniq.slice(i, i + chunk);
    const res = await fetch(`${base}/bdu/lookup`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        ...auth
      },
      body: JSON.stringify({ bduIds: slice }),
      cache: "no-store"
    });
    if (res.status === 401 || res.status === 403) return new Map();
    if (!res.ok) return null;
    const data = (await res.json()) as {
      items?: Array<{
        bduId: string;
        name: string;
        cveIds?: string[];
        linkedCveIds?: string[];
      }>;
    };
    for (const row of data.items ?? []) {
      out.set(row.bduId, {
        bduId: row.bduId,
        name: row.name,
        cveIds: row.cveIds ?? [],
        linkedCveIds: row.linkedCveIds ?? []
      });
    }
  }
  return out;
}

/** Дополняет посты записями из таблицы `bdu_vuln` (отдельные карточки БДУ без CVE в базе). */
export async function enrichFeedItemsWithRegistryBdu(
  items: FstecFeedItem[],
  opts?: { authorization?: string | null }
): Promise<LocalBduEnrichmentStatus> {
  const perItem = new Map<FstecFeedItem, string[]>();
  const allBdus = new Set<string>();

  for (const item of items) {
    const text = `${item.title}\n${item.descriptionText}`;
    const pairs = extractBduCvePairs(text);
    const pairedInItem = new Set(pairs.map((p) => p.bduId));
    const ids = extractBduIds(text).filter((id) => !pairedInItem.has(id));
    if (ids.length === 0) continue;
    perItem.set(item, ids);
    for (const id of ids) allBdus.add(id);
  }

  if (allBdus.size === 0) return "noop";

  const auth = resolveFstecUpstreamAuth(opts?.authorization ?? null);
  let registry: Map<string, FstecRegistryBduLink> | null;
  try {
    registry = await lookupBduRegistryBatched([...allBdus], auth);
  } catch {
    return "unavailable";
  }
  if (registry === null) return "unavailable";
  if (registry.size === 0) return "noop";

  for (const [item, ids] of perItem) {
    const links: FstecRegistryBduLink[] = [];
    for (const id of ids) {
      const row = registry.get(id);
      if (row) links.push(row);
    }
    if (links.length > 0) item.registryBduLinks = links;
  }
  return "ok";
}

/**
 * Собирает все пары BDU↔CVE из **всей** текущей выборки ленты, проверяет CVE в БД батчами и пишет в `cve_bdu_link`.
 * Не зависит от полей `localBduLinks` на элементах — дублирует разбор текста, чтобы ничего не потерять.
 */
export async function syncAllFstecBduPairsToDatabase(items: FstecFeedItem[], req: Request): Promise<void> {
  const seen = new Set<string>();
  const allPairs: { cveId: string; bduId: string }[] = [];
  for (const it of items) {
    const pairs = extractBduCvePairs(`${it.title}\n${it.descriptionText}`);
    for (const p of pairs) {
      const k = `${p.cveId}|${p.bduId}`;
      if (seen.has(k)) continue;
      seen.add(k);
      allPairs.push({ cveId: p.cveId, bduId: p.bduId });
    }
  }
  if (allPairs.length === 0) return;

  const auth =
    (() => {
      const h = forwardAuthHeaders(req);
      if (h.authorization) return h;
      return resolveFstecUpstreamAuth(null);
    })();
  if (!auth?.authorization) return;

  const cveIds = [...new Set(allPairs.map((p) => p.cveId))];
  let present: Set<string> | null;
  try {
    present = await lookupCvesPresentBatched(cveIds, auth);
  } catch {
    return;
  }
  if (present == null) return;

  const toWrite = allPairs.filter((p) => present.has(p.cveId));
  if (toWrite.length === 0) return;

  const base = getUpstreamApiBase();
  for (let i = 0; i < toWrite.length; i += BDU_LINKS_POST_CHUNK) {
    const slice = toWrite.slice(i, i + BDU_LINKS_POST_CHUNK);
    try {
      await fetch(`${base}/cves/bdu-links`, {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          ...auth
        },
        body: JSON.stringify({ pairs: slice }),
        cache: "no-store"
      });
    } catch {
      // не ломаем выдачу ленты
    }
  }
}

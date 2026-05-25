/**
 * One-shot NVD published-window sync (pubStart/pubEnd) into Postgres.
 * Usage: node --env-file=.env scripts/nvd-pub-sync-now.mjs
 */
import pg from "pg";

const DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://vuln:vuln@localhost:5432/vuln_intel";
const NVD_API_KEY = process.env.NVD_API_KEY?.trim();
const BASE_URL = process.env.NVD_API_BASE ?? "https://services.nvd.nist.gov/rest/json/cves/2.0";
const RESULTS_PER_PAGE = Math.max(20, Math.min(2000, Number(process.env.NVD_RESULTS_PER_PAGE ?? 100)));
const PAGE_SLEEP_MS = Number(process.env.NVD_PAGE_SLEEP_MS ?? 6500);
const HOT_HOURS = Number(process.env.NVD_PUB_HOT_HOURS ?? 27);
const GAP_DAYS = Number(process.env.NVD_PUB_GAP_BACKFILL_DAYS ?? 21);

function parseIso(value) {
  if (!value) return undefined;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return undefined;
  return d.toISOString();
}

function extractCvss(raw) {
  const metrics = raw?.metrics;
  if (!metrics || typeof metrics !== "object") return null;
  for (const k of Object.keys(metrics)) {
    const arr = metrics[k];
    if (!Array.isArray(arr)) continue;
    for (const c of arr) {
      const score = c?.cvssData?.baseScore;
      if (typeof score === "number" && score >= 0 && score <= 10) return score;
    }
  }
  return null;
}

function resolveWindow(maxPublishedAt) {
  const now = new Date();
  const pubEndIso = now.toISOString();
  const slidingStart = new Date(now.getTime() - HOT_HOURS * 3600 * 1000);
  let pubStart = slidingStart;
  let reason = `sliding_${HOT_HOURS}h`;
  if (maxPublishedAt) {
    const gapStart = new Date(maxPublishedAt.getTime() - 3600_000);
    const minGapStart = new Date(now.getTime() - GAP_DAYS * 24 * 3600_000);
    if (gapStart < pubStart) {
      pubStart = gapStart > minGapStart ? gapStart : minGapStart;
      reason = gapStart > minGapStart ? "gap_from_max_published" : `gap_capped_${GAP_DAYS}d`;
    }
  }
  return { pubStartIso: pubStart.toISOString(), pubEndIso, reason };
}

let nvdApiKeyDisabled = false;

async function fetchJson(url) {
  const headers = { accept: "application/json" };
  const useKey = NVD_API_KEY && !nvdApiKeyDisabled;
  if (useKey) headers.apiKey = NVD_API_KEY;
  let res = await fetch(url, { headers });
  if (!res.ok && res.status === 404 && useKey) {
    nvdApiKeyDisabled = true;
    console.warn("[nvd-pub-sync-now] API key rejected (404) — continuing without apiKey");
    res = await fetch(url, { headers: { accept: "application/json" } });
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`NVD ${res.status} ${text.slice(0, 200)}`);
  }
  return res.json();
}

async function main() {
  const pool = new pg.Pool({ connectionString: DATABASE_URL });
  const maxR = await pool.query(`SELECT MAX(published_at) AS max_pub FROM cve`);
  const maxPub = maxR.rows[0]?.max_pub ?? null;
  const { pubStartIso, pubEndIso, reason } = resolveWindow(maxPub);
  console.log(`[nvd-pub-sync-now] window=${pubStartIso}..${pubEndIso} reason=${reason} maxBefore=${maxPub?.toISOString?.() ?? "none"}`);

  let startIndex = 0;
  let processed = 0;
  let totalResults = 0;
  const maxEmptyRetries = Number(process.env.NVD_EMPTY_PAGE_RETRIES ?? 12);
  let emptyRetries = 0;

  for (;;) {
    if (startIndex > 0 || emptyRetries > 0) await new Promise((r) => setTimeout(r, PAGE_SLEEP_MS));
    const url = new URL(BASE_URL);
    url.searchParams.set("pubStartDate", pubStartIso);
    url.searchParams.set("pubEndDate", pubEndIso);
    url.searchParams.set("startIndex", String(startIndex));
    url.searchParams.set("resultsPerPage", String(RESULTS_PER_PAGE));

    const page = await fetchJson(url.toString());
    const vulnerabilities = page?.vulnerabilities ?? [];
    totalResults = Number(page?.totalResults ?? vulnerabilities.length);

    if (vulnerabilities.length === 0 && startIndex < totalResults) {
      emptyRetries++;
      if (emptyRetries <= maxEmptyRetries) {
        console.warn(
          `[nvd-pub-sync-now] empty page startIndex=${startIndex} total=${totalResults} retry=${emptyRetries}/${maxEmptyRetries}`
        );
        continue;
      }
      console.error(`[nvd-pub-sync-now] giving up empty page startIndex=${startIndex} total=${totalResults}`);
      break;
    }
    emptyRetries = 0;
    if (vulnerabilities.length === 0) break;

    for (const item of vulnerabilities) {
      const cveId = String(item?.cve?.id ?? "");
      if (!cveId.startsWith("CVE-")) continue;
      const publishedAt = parseIso(item?.cve?.published);
      const modifiedAt = parseIso(item?.cve?.lastModified);
      const cvss = extractCvss(item.cve);
      await pool.query(
        `INSERT INTO cve(cve_id, source, published_at, modified_at, cvss_base, raw)
         VALUES ($1,'nvd',$2,$3,$4,$5)
         ON CONFLICT (cve_id) DO UPDATE SET
           raw = EXCLUDED.raw,
           source = EXCLUDED.source,
           published_at = CASE WHEN EXCLUDED.published_at IS NOT NULL THEN EXCLUDED.published_at ELSE cve.published_at END,
           modified_at = COALESCE(EXCLUDED.modified_at, cve.modified_at),
           cvss_base = COALESCE(EXCLUDED.cvss_base, cve.cvss_base),
           updated_at = now()`,
        [
          cveId,
          publishedAt ? new Date(publishedAt) : null,
          modifiedAt ? new Date(modifiedAt) : null,
          cvss,
          JSON.stringify(item.cve)
        ]
      );
      processed++;
    }

    startIndex += vulnerabilities.length;
    console.log(`[nvd-pub-sync-now] progress ${startIndex}/${totalResults}`);
    if (startIndex >= totalResults) break;
  }

  await pool.query(
    `INSERT INTO audit_log(actor_type, action, metadata) VALUES ('system', 'nvd.pub_sync', $1)`,
    [JSON.stringify({ pubStart: pubStartIso, pubEnd: pubEndIso, processed, reason, script: "nvd-pub-sync-now.mjs" })]
  );

  const after = await pool.query(`
    SELECT COUNT(*)::int AS pub_24h,
           MAX(published_at)::text AS max_pub
      FROM cve
     WHERE published_at >= now() - interval '24 hours'`);
  console.log(`[nvd-pub-sync-now] done processed=${processed} pub_24h=${after.rows[0].pub_24h} max_pub=${after.rows[0].max_pub}`);
  await pool.end();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

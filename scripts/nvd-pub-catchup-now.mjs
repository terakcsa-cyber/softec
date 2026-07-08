/**
 * Догон NVD по дате публикации от watermark modifiedEnd до сейчас (чанками).
 * Usage: node --env-file=.env scripts/nvd-pub-catchup-now.mjs
 */
import pg from "pg";

const DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://vuln:vuln@localhost:5432/vuln_intel";
const NVD_API_KEY = process.env.NVD_API_KEY?.trim();
const BASE_URL = process.env.NVD_API_BASE ?? "https://services.nvd.nist.gov/rest/json/cves/2.0";
const RESULTS_PER_PAGE = Math.max(20, Math.min(2000, Number(process.env.NVD_RESULTS_PER_PAGE ?? 100)));
const PAGE_SLEEP_MS = Number(process.env.NVD_PAGE_SLEEP_MS ?? 6500);
const CHUNK_DAYS = Math.max(1, Math.min(30, Number(process.env.NVD_PUB_CATCHUP_CHUNK_DAYS ?? 7)));
const OVERLAP_MS = Number(process.env.NVD_PUB_CATCHUP_OVERLAP_MS ?? 3_600_000);
const MAX_CHUNKS = Math.max(1, Number(process.env.NVD_PUB_CATCHUP_MAX_CHUNKS ?? 40));

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

let nvdApiKeyDisabled = false;

async function fetchJson(url) {
  const maxAttempts = Number(process.env.NVD_FETCH_RETRIES ?? 6);
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const headers = { accept: "application/json" };
      const useKey = NVD_API_KEY && !nvdApiKeyDisabled;
      if (useKey) headers.apiKey = NVD_API_KEY;
      let res = await fetch(url, { headers });
      if (!res.ok && res.status === 404 && useKey) {
        nvdApiKeyDisabled = true;
        console.warn("[nvd-pub-catchup] API key rejected (404) — continuing without apiKey");
        res = await fetch(url, { headers: { accept: "application/json" } });
      }
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`NVD ${res.status} ${text.slice(0, 200)}`);
      }
      return res.json();
    } catch (e) {
      if (attempt === maxAttempts) throw e;
      const backoffMs = Math.min(30_000, 500 * attempt * attempt);
      console.warn(
        `[nvd-pub-catchup] fetch retry ${attempt}/${maxAttempts}: ${e instanceof Error ? e.message : e}`
      );
      await new Promise((r) => setTimeout(r, backoffMs));
    }
  }
  throw new Error("unreachable");
}

async function syncWindow(pool, pubStartIso, pubEndIso) {
  let startIndex = 0;
  let processed = 0;
  const maxEmptyRetries = Number(process.env.NVD_EMPTY_PAGE_RETRIES ?? 12);
  let emptyRetries = 0;
  let totalResults = 0;

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
      if (emptyRetries <= maxEmptyRetries) continue;
      console.error(`[nvd-pub-catchup] giving up empty page startIndex=${startIndex} total=${totalResults}`);
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
    if (startIndex >= totalResults) break;
  }

  await pool.query(
    `INSERT INTO audit_log(actor_type, action, metadata) VALUES ('system', 'nvd.pub_catchup', $1)`,
    [
      JSON.stringify({
        pubStart: pubStartIso,
        pubEnd: pubEndIso,
        processed,
        reason: "script_nvd-pub-catchup-now",
        script: "nvd-pub-catchup-now.mjs"
      })
    ]
  );

  return processed;
}

async function main() {
  const pool = new pg.Pool({ connectionString: DATABASE_URL });
  const wm = await pool.query(
    `SELECT COALESCE(
       (SELECT NULLIF(TRIM(metadata->>'pubEnd'), '')
          FROM audit_log
         WHERE action = 'nvd.pub_catchup'
           AND NULLIF(TRIM(metadata->>'pubEnd'), '') IS NOT NULL
      ORDER BY (metadata->>'pubEnd')::timestamptz DESC, ts DESC
         LIMIT 1),
       (SELECT NULLIF(TRIM(metadata->>'modifiedEnd'), '')
          FROM audit_log
         WHERE action = 'nvd.watermark'
           AND NULLIF(TRIM(metadata->>'modifiedEnd'), '') IS NOT NULL
      ORDER BY (metadata->>'modifiedEnd')::timestamptz DESC, ts DESC
         LIMIT 1)
     ) AS cursor_end`
  );
  let cursorMs = wm.rows[0]?.cursor_end
    ? new Date(wm.rows[0].cursor_end).getTime()
    : Date.now() - 90 * 24 * 3600_000;
  if (Number.isNaN(cursorMs)) cursorMs = Date.now() - 90 * 24 * 3600_000;

  const nowMs = Date.now();
  let total = 0;
  let chunks = 0;

  console.log(
    `[nvd-pub-catchup] start from watermark=${new Date(cursorMs).toISOString()} chunkDays=${CHUNK_DAYS}`
  );

  while (cursorMs < nowMs - 60_000 && chunks < MAX_CHUNKS) {
    const pubStartIso = new Date(Math.max(0, cursorMs - OVERLAP_MS)).toISOString();
    const chunkEndMs = Math.min(nowMs, cursorMs + CHUNK_DAYS * 24 * 3600_000);
    const pubEndIso = new Date(chunkEndMs).toISOString();
    chunks++;
    console.log(`[nvd-pub-catchup] chunk ${chunks} window=${pubStartIso}..${pubEndIso}`);
    // eslint-disable-next-line no-await-in-loop
    const n = await syncWindow(pool, pubStartIso, pubEndIso);
    total += n;
    console.log(`[nvd-pub-catchup] chunk ${chunks} processed=${n}`);
    cursorMs = chunkEndMs;
  }

  const may30 = await pool.query(
    `SELECT count(*)::int AS n FROM cve WHERE published_at >= '2026-05-30' AND published_at < '2026-05-31'`
  );
  console.log(`[nvd-pub-catchup] done total=${total} may30_in_db=${may30.rows[0]?.n ?? "?"}`);
  await pool.end();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

import pg from "pg";

const DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://vuln:vuln@localhost:5432/vuln_intel";

const BASE_URL = process.env.NVD_API_BASE ?? "https://services.nvd.nist.gov/rest/json/cves/2.0";

// Backfill by published date windows. Defaults: from 1999-01-01 to now, 30-day windows.
const START_DATE = new Date(process.env.NVD_PUB_START ?? "1999-01-01T00:00:00.000Z");
const END_DATE = new Date(process.env.NVD_PUB_END ?? new Date().toISOString());
const WINDOW_DAYS = Number(process.env.NVD_WINDOW_DAYS ?? 30);

const RESULTS_PER_PAGE = Math.max(1, Math.min(2000, Number(process.env.NVD_RESULTS_PER_PAGE ?? 2000)));
const MAX_ATTEMPTS = Number(process.env.NVD_FETCH_RETRIES ?? 6);
const WAIT_FOR_KEY_MS = Math.max(0, Number(process.env.NVD_BACKFILL_WAIT_FOR_KEY_MS ?? 600_000));

const UPSERT_BATCH = Math.max(1, Number(process.env.NVD_UPSERT_BATCH ?? 500));
const WRITE_AUDIT = (process.env.NVD_WRITE_AUDIT ?? "true") !== "false";

let nvdApiKey = process.env.NVD_API_KEY?.trim() || "";
let nvdApiKeyDisabled = false;

function resolvePageSleepMs() {
  const configured = Number(process.env.NVD_PAGE_SLEEP_MS);
  if (Number.isFinite(configured) && configured > 0) return configured;
  return nvdApiKey && !nvdApiKeyDisabled ? 650 : 6000;
}

async function loadNvdApiKeyFromDb(db) {
  try {
    const r = await db.query(`SELECT value FROM app_integration_settings WHERE key = 'nvd' LIMIT 1`);
    const v = r.rows[0]?.value;
    const k = v && typeof v === "object" && !Array.isArray(v) ? v.apiKey : undefined;
    if (typeof k === "string" && k.trim()) return k.trim();
  } catch {
    // table may not exist on very first boot
  }
  return "";
}

async function refreshNvdApiKey(db) {
  const fromDb = await loadNvdApiKeyFromDb(db);
  const fromEnv = process.env.NVD_API_KEY?.trim() || "";
  const next = fromDb || fromEnv;
  if (next !== nvdApiKey) {
    nvdApiKey = next;
    nvdApiKeyDisabled = false;
  }
  return Boolean(nvdApiKey && !nvdApiKeyDisabled);
}

async function waitForNvdApiKey(db) {
  const deadline = Date.now() + WAIT_FOR_KEY_MS;
  for (;;) {
    const fromDb = await loadNvdApiKeyFromDb(db);
    if (fromDb) {
      nvdApiKey = fromDb;
      nvdApiKeyDisabled = false;
      // eslint-disable-next-line no-console
      console.log("[nvd-backfill] API key ready (source=settings)");
      return;
    }
    const fromEnv = process.env.NVD_API_KEY?.trim() || "";
    if (fromEnv && WAIT_FOR_KEY_MS <= 0) {
      nvdApiKey = fromEnv;
      nvdApiKeyDisabled = false;
      // eslint-disable-next-line no-console
      console.log("[nvd-backfill] API key ready (source=env)");
      return;
    }
    if (fromEnv && Date.now() >= deadline) {
      nvdApiKey = fromEnv;
      nvdApiKeyDisabled = false;
      // eslint-disable-next-line no-console
      console.warn("[nvd-backfill] settings key not found — falling back to NVD_API_KEY from env");
      return;
    }
    if (Date.now() >= deadline) {
      // eslint-disable-next-line no-console
      console.warn("[nvd-backfill] no API key — continuing unauthenticated (slower NVD limits)");
      return;
    }
    // eslint-disable-next-line no-console
    console.log("[nvd-backfill] waiting for NVD API key in web settings…");
    // eslint-disable-next-line no-await-in-loop
    await new Promise((r) => setTimeout(r, 5000));
  }
}

function toIsoZ(d) {
  if (!(d instanceof Date) || Number.isNaN(d.getTime())) return undefined;
  return d.toISOString();
}

function addDays(d, days) {
  return new Date(d.getTime() + days * 24 * 60 * 60 * 1000);
}

function extractCvssBaseScore(raw) {
  const metrics = raw?.metrics;
  if (!metrics || typeof metrics !== "object") return undefined;
  const candidates = [];
  for (const k of Object.keys(metrics)) {
    const v = metrics[k];
    if (Array.isArray(v)) candidates.push(...v);
  }
  for (const c of candidates) {
    const score = c?.cvssData?.baseScore;
    if (typeof score === "number" && score >= 0 && score <= 10) return score;
  }
  return undefined;
}

async function fetchJson(url, db) {
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const headers = { accept: "application/json" };
    const useKey = nvdApiKey && !nvdApiKeyDisabled;
    if (useKey) headers.apiKey = nvdApiKey;

    // eslint-disable-next-line no-await-in-loop
    let res = await fetch(url, { headers });
    if (!res.ok && res.status === 404 && useKey) {
      const hadDbKey = Boolean(await loadNvdApiKeyFromDb(db));
      if (db) await refreshNvdApiKey(db);
      if (nvdApiKey && !nvdApiKeyDisabled && nvdApiKey !== headers.apiKey) {
        // eslint-disable-next-line no-console
        console.warn("[nvd-backfill] API key rejected (404) — retrying with refreshed key");
        continue;
      }
      nvdApiKeyDisabled = true;
      // eslint-disable-next-line no-console
      console.warn(
        `[nvd-backfill] API key rejected (404) — continuing without apiKey${hadDbKey ? "" : " (save a valid key in settings)"}`
      );
      // eslint-disable-next-line no-await-in-loop
      res = await fetch(url, { headers: { accept: "application/json" } });
    }
    if (res.ok) return res.json();

    const retryAfter = res.headers.get("retry-after");
    const backoffMs = retryAfter
      ? Number(retryAfter) * 1000
      : Math.min(30_000, 300 * attempt * attempt);

    if (attempt === MAX_ATTEMPTS) {
      const text = await res.text().catch(() => "");
      throw new Error(`NVD fetch failed: ${res.status} ${res.statusText} ${text}`);
    }
    // eslint-disable-next-line no-console
    console.warn(`[nvd-backfill] retrying attempt=${attempt} status=${res.status} sleep=${backoffMs}ms`);
    // eslint-disable-next-line no-await-in-loop
    await new Promise((r) => setTimeout(r, backoffMs));
  }
  throw new Error("unreachable");
}

async function upsertBatch(db, rows) {
  if (rows.length === 0) return 0;
  const cveIds = rows.map((r) => r.cveId);
  const sources = rows.map(() => "nvd");
  const published = rows.map((r) => (r.publishedAt ? new Date(r.publishedAt) : null));
  const modified = rows.map((r) => (r.modifiedAt ? new Date(r.modifiedAt) : null));
  const cvss = rows.map((r) => (typeof r.cvss === "number" ? r.cvss : null));
  const raw = rows.map((r) => JSON.stringify(r.raw));

  await db.query(
    `INSERT INTO cve(cve_id, source, published_at, modified_at, cvss_base, raw)
     SELECT * FROM UNNEST($1::text[], $2::text[], $3::timestamptz[], $4::timestamptz[], $5::double precision[], $6::jsonb[])
     ON CONFLICT (cve_id)
     DO UPDATE SET raw = EXCLUDED.raw,
                   source = EXCLUDED.source,
                   published_at = COALESCE(EXCLUDED.published_at, cve.published_at),
                   modified_at = COALESCE(EXCLUDED.modified_at, cve.modified_at),
                   cvss_base = COALESCE(EXCLUDED.cvss_base, cve.cvss_base),
                   updated_at = now()`,
    [cveIds, sources, published, modified, cvss, raw]
  );
  return rows.length;
}

function normalizeDate(value) {
  if (!value) return undefined;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return undefined;
  return d.toISOString();
}

async function main() {
  if (Number.isNaN(START_DATE.getTime()) || Number.isNaN(END_DATE.getTime())) {
    throw new Error("Invalid NVD_PUB_START / NVD_PUB_END (must be ISO date strings)");
  }
  if (END_DATE <= START_DATE) throw new Error("NVD_PUB_END must be > NVD_PUB_START");
  if (!Number.isFinite(WINDOW_DAYS) || WINDOW_DAYS <= 0) throw new Error("NVD_WINDOW_DAYS must be > 0");

  const db = new pg.Pool({ connectionString: DATABASE_URL });

  let totalUpserted = 0;
  let windowStart = START_DATE;

  try {
    await waitForNvdApiKey(db);
    // eslint-disable-next-line no-console
    console.log(
      `[nvd-backfill] start=${toIsoZ(windowStart)} end=${toIsoZ(END_DATE)} windowDays=${WINDOW_DAYS} rpp=${RESULTS_PER_PAGE} pageSleepMs=${resolvePageSleepMs()}`
    );

    while (windowStart < END_DATE) {
      await refreshNvdApiKey(db);
      const pageSleepMs = resolvePageSleepMs();
      const windowEnd = addDays(windowStart, WINDOW_DAYS);
      const pubStart = toIsoZ(windowStart);
      const pubEnd = toIsoZ(windowEnd < END_DATE ? windowEnd : END_DATE);
      if (!pubStart || !pubEnd) throw new Error("Invalid window dates");

      let startIndex = 0;
      let processedWindow = 0;
      const maxEmptyRetries = Number(process.env.NVD_EMPTY_PAGE_RETRIES ?? 12);
      let emptyRetries = 0;
      const t0 = Date.now();

      // eslint-disable-next-line no-console
      console.log(`[nvd-backfill] window pub=${pubStart}..${pubEnd}`);

      for (;;) {
        const url = new URL(BASE_URL);
        url.searchParams.set("pubStartDate", pubStart);
        url.searchParams.set("pubEndDate", pubEnd);
        url.searchParams.set("startIndex", String(startIndex));
        url.searchParams.set("resultsPerPage", String(RESULTS_PER_PAGE));

        // eslint-disable-next-line no-await-in-loop
        const page = await fetchJson(url.toString(), db);
        const vulnerabilities = Array.isArray(page?.vulnerabilities) ? page.vulnerabilities : [];
        const totalResults = Number(page?.totalResults ?? vulnerabilities.length);

        const batch = [];
        for (const item of vulnerabilities) {
          const rawCve = item?.cve;
          const cveId = String(rawCve?.id ?? "");
          if (!cveId.startsWith("CVE-")) continue;
          const publishedAt = normalizeDate(rawCve?.published);
          const modifiedAt = normalizeDate(rawCve?.lastModified);
          batch.push({
            cveId,
            raw: rawCve,
            publishedAt,
            modifiedAt,
            cvss: extractCvssBaseScore(rawCve)
          });
        }

        // upsert in chunks for memory safety
        for (let i = 0; i < batch.length; i += UPSERT_BATCH) {
          // eslint-disable-next-line no-await-in-loop
          const n = await upsertBatch(db, batch.slice(i, i + UPSERT_BATCH));
          processedWindow += n;
          totalUpserted += n;
        }

        if (vulnerabilities.length === 0 && startIndex < totalResults) {
          emptyRetries++;
          if (emptyRetries > maxEmptyRetries) {
            throw new Error(
              `[nvd-backfill] giving up empty page pub=${pubStart}..${pubEnd} startIndex=${startIndex} total=${totalResults}`
            );
          }
          const emptySleepMs = Number(process.env.NVD_EMPTY_PAGE_SLEEP_MS ?? Math.max(pageSleepMs, 6000));
          // eslint-disable-next-line no-console
          console.warn(
            `[nvd-backfill] empty page pub=${pubStart}..${pubEnd} startIndex=${startIndex} total=${totalResults} retry=${emptyRetries}/${maxEmptyRetries} sleep=${emptySleepMs}ms`
          );
          // eslint-disable-next-line no-await-in-loop
          await new Promise((r) => setTimeout(r, emptySleepMs));
          continue;
        }
        emptyRetries = 0;

        startIndex += vulnerabilities.length;
        if (startIndex >= totalResults) break;

        // eslint-disable-next-line no-await-in-loop
        await new Promise((r) => setTimeout(r, pageSleepMs));
      }

      const elapsedMs = Date.now() - t0;
      // eslint-disable-next-line no-console
      console.log(
        `[nvd-backfill] window_done upserted=${processedWindow} total=${totalUpserted} elapsed=${elapsedMs}ms`
      );

      if (WRITE_AUDIT) {
        // eslint-disable-next-line no-await-in-loop
        await db.query(
          `INSERT INTO audit_log(actor_type, action, metadata)
           VALUES ('system', 'nvd.backfill', $1)`,
          [
            JSON.stringify({
              pubStart,
              pubEnd,
              upserted: processedWindow,
              totalUpserted,
              resultsPerPage: RESULTS_PER_PAGE,
              windowDays: WINDOW_DAYS,
              ts: new Date().toISOString()
            })
          ]
        );
      }

      windowStart = windowEnd;
    }

    // eslint-disable-next-line no-console
    console.log(`[nvd-backfill] done totalUpserted=${totalUpserted}`);
  } finally {
    await db.end().catch(() => {});
  }
}

await main();


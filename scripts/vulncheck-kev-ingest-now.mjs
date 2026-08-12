/**
 * Разовый ingest VulnCheck KEV (токен из БД key vulncheck или VULNCHECK_API_TOKEN).
 * Usage: node --env-file=.env scripts/vulncheck-kev-ingest-now.mjs
 */
import pg from "pg";
import { gunzipSync } from "node:zlib";
import { unzipSync } from "fflate";
import { EXPLOIT_INTEL_UPSERT_SQL } from "../packages/shared/dist/exploit/exploit-intel-sql.js";

const DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://vuln:vuln@localhost:5432/vuln_intel";

async function resolveApiToken(client) {
  const r = await client.query(
    `SELECT value FROM app_integration_settings WHERE key = 'vulncheck' LIMIT 1`
  );
  const fromDb = r.rows[0]?.value?.apiToken?.trim();
  if (fromDb) return fromDb;
  return process.env.VULNCHECK_API_TOKEN?.trim() || undefined;
}

async function parseFeedPayload(buf) {
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    return JSON.parse(gunzipSync(buf).toString("utf8"));
  }
  if (buf.length >= 2 && buf[0] === 0x50 && buf[1] === 0x4b) {
    const files = unzipSync(new Uint8Array(buf));
    const jsonName = Object.keys(files).find((n) => n.endsWith(".json")) ?? Object.keys(files)[0];
    if (!jsonName) throw new Error("VulnCheck backup zip: no files");
    return JSON.parse(new TextDecoder().decode(files[jsonName]));
  }
  return JSON.parse(buf.toString("utf8"));
}

async function fetchFeedJson(token) {
  const directUrl = process.env.VULNCHECK_KEV_FEED_URL?.trim();
  if (directUrl) {
    const res = await fetch(directUrl, {
      headers: { accept: "application/json", Authorization: `Bearer ${token}` }
    });
    if (!res.ok) throw new Error(`VulnCheck feed ${res.status}`);
    const body = await res.json();
    return body.data ?? body.vulnerabilities ?? (Array.isArray(body) ? body : []);
  }

  const backupRes = await fetch("https://api.vulncheck.com/v3/backup/vulncheck-kev", {
    headers: { accept: "application/json", Authorization: `Bearer ${token}` }
  });
  if (!backupRes.ok) {
    const text = await backupRes.text().catch(() => "");
    throw new Error(`VulnCheck backup meta ${backupRes.status} ${text.slice(0, 200)}`);
  }
  const meta = await backupRes.json();
  const link = meta.data?.[0]?.url ?? meta.data?.[0]?.downloadUrl;
  if (!link) throw new Error("VulnCheck backup: no download url");

  let fileRes = await fetch(link, { headers: { Authorization: `Bearer ${token}` } });
  if (!fileRes.ok) fileRes = await fetch(link);
  if (!fileRes.ok) {
    const text = await fileRes.text().catch(() => "");
    throw new Error(`VulnCheck backup download ${fileRes.status} ${text.slice(0, 200)}`);
  }
  const buf = Buffer.from(await fileRes.arrayBuffer());
  const payload = await parseFeedPayload(buf);
  return payload.data ?? payload.vulnerabilities ?? (Array.isArray(payload) ? payload : []);
}

async function main() {
  const client = new pg.Client({ connectionString: DATABASE_URL });
  await client.connect();

  const token = await resolveApiToken(client);
  if (!token) {
    console.error("No VulnCheck token (settings vulncheck or VULNCHECK_API_TOKEN)");
    process.exit(1);
  }

  console.log("[vulncheck-kev-now] fetching feed…");
  const items = await fetchFeedJson(token);
  if (!items.length) {
    console.log("[vulncheck-kev-now] empty feed");
    await client.end();
    return;
  }

  const cisaR = await client.query(`SELECT cve_id FROM kev`);
  const cisaSet = new Set(cisaR.rows.map((r) => r.cve_id));

  const parsed = [];
  for (const it of items) {
    const cveId = String(it.cve ?? it.cveID ?? "")
      .trim()
      .toUpperCase();
    if (!/^CVE-\d{4}-\d+$/.test(cveId)) continue;
    parsed.push({ cveId, it });
  }

  const knownR = await client.query(
    `SELECT cve_id FROM cve WHERE cve_id = ANY($1::text[])`,
    [parsed.map((p) => p.cveId)]
  );
  const knownSet = new Set(knownR.rows.map((r) => r.cve_id));

  const touched = [];
  let vcOnly = 0;
  let skippedUnknown = 0;

  for (const { cveId, it } of parsed) {

    const dateAdded = it.date_added ? new Date(it.date_added) : null;
    const cisaDate = it.cisa_date_added ?? it.cisaDateAdded;
    const cisaDateAdded = cisaDate ? new Date(cisaDate) : null;
    const vckevOnly = !cisaSet.has(cveId);
    if (vckevOnly) vcOnly++;

    const evidence = Array.isArray(it.reported_exploitation)
      ? it.reported_exploitation
      : Array.isArray(it.references)
        ? it.references
        : [];
    const evidenceCount = evidence.length;
    const xdbUrl =
      it.xdb_url ??
      (Array.isArray(it.references)
        ? it.references.find((r) => String(r?.url ?? "").includes("vulncheck"))?.url
        : undefined) ??
      null;

    await client.query(
      `INSERT INTO vulncheck_kev (cve_id, date_added, cisa_date_added, vckev_only, ransomware_use, evidence_count, xdb_url, raw, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now())
       ON CONFLICT (cve_id) DO UPDATE SET
         date_added = EXCLUDED.date_added,
         cisa_date_added = EXCLUDED.cisa_date_added,
         vckev_only = EXCLUDED.vckev_only,
         ransomware_use = EXCLUDED.ransomware_use,
         evidence_count = EXCLUDED.evidence_count,
         xdb_url = EXCLUDED.xdb_url,
         raw = EXCLUDED.raw,
         updated_at = now()`,
      [
        cveId,
        dateAdded,
        cisaDateAdded,
        vckevOnly,
        it.knownRansomwareCampaignUse ?? null,
        evidenceCount,
        xdbUrl,
        JSON.stringify(it)
      ]
    );

    if (!knownSet.has(cveId)) {
      skippedUnknown++;
      continue;
    }

    await client.query(
      `INSERT INTO cve_exploit_signal (cve_id, signal_type, source, url, title, confidence, last_seen_at)
       VALUES ($1, 'vulncheck_kev', 'vulncheck', $2, 'VulnCheck KEV', 'high', now())
       ON CONFLICT (cve_id, signal_type, source, COALESCE(url, ''))
       DO UPDATE SET
         title = EXCLUDED.title,
         confidence = EXCLUDED.confidence,
         last_seen_at = CASE
           WHEN cve_exploit_signal.title IS DISTINCT FROM EXCLUDED.title
             OR cve_exploit_signal.confidence IS DISTINCT FROM EXCLUDED.confidence
             OR cve_exploit_signal.url IS DISTINCT FROM EXCLUDED.url
           THEN now()
           ELSE cve_exploit_signal.last_seen_at
         END`,
      [cveId, xdbUrl ?? `vulncheck:kev:${cveId}`]
    );

    touched.push(cveId);
  }

  if (touched.length > 0) {
    await client.query(EXPLOIT_INTEL_UPSERT_SQL, [touched]);
  }

  await client.query(
    `INSERT INTO audit_log(actor_type, action, metadata) VALUES ('system', 'vulncheck.kev.ingest', $1)`,
    [JSON.stringify({ items: items.length, touched: touched.length, vckev_only: vcOnly, manual: true })]
  );

  console.log(
    `[vulncheck-kev-now] ok items=${items.length} touched=${touched.length} vckev_only=${vcOnly} skipped_unknown_cve=${skippedUnknown}`
  );
  await client.end();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

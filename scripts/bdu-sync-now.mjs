#!/usr/bin/env node
/**
 * Однократная загрузка БДУ с bdu.fstec.ru (vulxml.zip) → `bdu_vuln` + `cve_bdu_link`.
 * node --env-file=.env scripts/bdu-sync-now.mjs
 *
 * Если Node не доверяет сертификату ФСТЭК: BDU_TLS_INSECURE=true в .env
 */
import pg from "pg";
import {
  bduFstecUrl,
  fetchBduVulxmlWithFallback,
  parseBduVulNode
} from "../packages/shared/dist/index.js";
import { XMLParser } from "fast-xml-parser";

const parser = new XMLParser({ ignoreAttributes: false, trimValues: true, processEntities: false });

function parseDocument(xmlBuf) {
  const parsed = parser.parse(xmlBuf.toString("utf8"));
  const root = parsed.vulnerabilities ?? parsed;
  const rawVul = root.vul ?? parsed.vul;
  const rows = Array.isArray(rawVul) ? rawVul : rawVul ? [rawVul] : [];
  return rows.map(parseBduVulNode).filter(Boolean);
}

async function main() {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) throw new Error("DATABASE_URL is required");

  const timeoutMs = Number(process.env.BDU_FETCH_TIMEOUT_MS ?? 600_000);
  const { xml, sourceUrl, usedFallback } = await fetchBduVulxmlWithFallback(timeoutMs);
  console.log(`[bdu-sync] source=${sourceUrl} fallback=${usedFallback} xmlBytes=${xml.length}`);

  const records = parseDocument(xml);
  console.log(`[bdu-sync] parsed ${records.length} records`);

  const pool = new pg.Pool({ connectionString: dbUrl });
  await pool.query(`CREATE TABLE IF NOT EXISTS cve_bdu_link (
    cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
    bdu_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (cve_id, bdu_id)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS bdu_vuln (
    bdu_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    software_names TEXT,
    vendors TEXT,
    cve_ids TEXT[] NOT NULL DEFAULT '{}',
    severity TEXT,
    severity_level INT NOT NULL DEFAULT 0,
    cvss_score DOUBLE PRECISION,
    cvss_vector TEXT,
    identify_date TEXT,
    publication_date TEXT,
    last_upd_date TEXT,
    identify_year INT,
    solution TEXT,
    status TEXT,
    exploit_status TEXT,
    fix_status TEXT,
    has_exploit BOOLEAN NOT NULL DEFAULT false,
    has_fix BOOLEAN NOT NULL DEFAULT false,
    sources TEXT,
    fstec_url TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`);

  const chunk = 250;
  for (let i = 0; i < records.length; i += chunk) {
    const slice = records.slice(i, i + chunk);
    const values = [];
    const params = [];
    let p = 1;
    for (const r of slice) {
      values.push(
        `($${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++})`
      );
      params.push(
        r.bduId,
        r.name,
        r.description || null,
        r.softwareNames || null,
        r.vendors || null,
        r.cveIds,
        r.severity || null,
        r.severityLevel,
        r.cvssScore,
        r.cvssVector || null,
        r.identifyDate || null,
        r.publicationDate || null,
        r.lastUpdDate || null,
        r.identifyYear,
        r.solution || null,
        r.status || null,
        r.exploitStatus || null,
        r.fixStatus || null,
        r.hasExploit,
        r.hasFix,
        r.sources || null,
        bduFstecUrl(r.bduId)
      );
    }
    await pool.query(
      `INSERT INTO bdu_vuln (
         bdu_id, name, description, software_names, vendors, cve_ids,
         severity, severity_level, cvss_score, cvss_vector,
         identify_date, publication_date, last_upd_date, identify_year,
         solution, status, exploit_status, fix_status, has_exploit, has_fix, sources, fstec_url
       ) VALUES ${values.join(",")}
       ON CONFLICT (bdu_id) DO UPDATE SET
         name=EXCLUDED.name, description=EXCLUDED.description,
         software_names=EXCLUDED.software_names, vendors=EXCLUDED.vendors,
         cve_ids=EXCLUDED.cve_ids, severity=EXCLUDED.severity,
         severity_level=EXCLUDED.severity_level, cvss_score=EXCLUDED.cvss_score,
         cvss_vector=EXCLUDED.cvss_vector, identify_date=EXCLUDED.identify_date,
         publication_date=EXCLUDED.publication_date, last_upd_date=EXCLUDED.last_upd_date,
         solution=EXCLUDED.solution, status=EXCLUDED.status,
         exploit_status=EXCLUDED.exploit_status, fix_status=EXCLUDED.fix_status,
         has_exploit=EXCLUDED.has_exploit, has_fix=EXCLUDED.has_fix,
         sources=EXCLUDED.sources, fstec_url=EXCLUDED.fstec_url, updated_at=now()`,
      params
    );
    console.log(`[bdu-sync] ${Math.min(i + chunk, records.length)}/${records.length}`);
  }

  const probe = await pool.query(`SELECT bdu_id, name FROM bdu_vuln WHERE bdu_id = $1`, ["2026-07273"]);
  console.log("[bdu-sync] probe 2026-07273:", probe.rows[0] ?? "NOT FOUND");

  const link = await pool.query(
    `INSERT INTO cve_bdu_link (cve_id, bdu_id)
     SELECT DISTINCT u.cve_id, b.bdu_id
       FROM bdu_vuln b
       CROSS JOIN LATERAL unnest(b.cve_ids) AS u(cve_id)
       JOIN cve c ON c.cve_id = u.cve_id
     ON CONFLICT DO NOTHING`
  );
  console.log(`[bdu-sync] new cve_bdu_link rows: ${link.rowCount ?? 0}`);
  await pool.end();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

import { Inject, Injectable, OnModuleInit } from "@nestjs/common";
import { bduFstecUrl } from "@vuln-intel/shared";
import { loadBduVulxmlRecords } from "../lib/bdu-vulxml-fetch.js";
import { DbService } from "../services/db.service.js";

@Injectable()
export class BduIngestJob implements OnModuleInit {
  constructor(@Inject(DbService) private readonly db: DbService) {}

  async onModuleInit() {
    if (process.env.BDU_INGEST_ENABLED === "false") return;
    const intervalMs = Number(process.env.BDU_POLL_INTERVAL_MS ?? 30 * 60 * 1000);
    // Stagger after EPSS boot / before heavy NVD overlap on long-AFK restarts.
    const initialDelayMs = Number(process.env.BDU_INITIAL_DELAY_MS ?? 35_000);
    setTimeout(() => {
      void this.runForever(intervalMs);
    }, initialDelayMs);
  }

  private async runForever(intervalMs: number) {
    const failureBackoffMs = Number(process.env.BDU_INGEST_FAILURE_BACKOFF_MS ?? 5 * 60_000);
    let consecutiveFailures = 0;
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const startedAt = Date.now();
      try {
        await this.ensureSchema();
        await this.runOnce();
        consecutiveFailures = 0;
      } catch (e) {
        consecutiveFailures += 1;
        const retryMs = Math.min(
          intervalMs,
          failureBackoffMs * Math.min(consecutiveFailures, 12)
        );
        // eslint-disable-next-line no-console
        console.error(
          `[ingest:bdu] cycle failed (attempt ${consecutiveFailures}), retry in ${Math.round(retryMs / 1000)}s`,
          e
        );
        await new Promise((r) => setTimeout(r, retryMs));
        continue;
      }
      const sleep = Math.max(60_000, intervalMs - (Date.now() - startedAt));
      await new Promise((r) => setTimeout(r, sleep));
    }
  }

  async ensureSchema() {
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS bdu_vuln (
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
      )`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS bdu_vuln_year_idx ON bdu_vuln (identify_year DESC NULLS LAST)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS bdu_vuln_cvss_idx ON bdu_vuln (cvss_score DESC NULLS LAST)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS bdu_vuln_publication_date_idx ON bdu_vuln (publication_date)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS bdu_vuln_last_upd_date_idx ON bdu_vuln (last_upd_date)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS bdu_vuln_cve_ids_gin ON bdu_vuln USING gin (cve_ids)`);
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS cve_bdu_link (
        cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
        bdu_id TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (cve_id, bdu_id)
      )`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS cve_bdu_link_bdu_idx ON cve_bdu_link (bdu_id)`);
  }

  async runOnce() {
    const timeoutMs = Number(process.env.BDU_FETCH_TIMEOUT_MS ?? 600_000);
    const chunkSize = Math.max(50, Math.min(1000, Number(process.env.BDU_UPSERT_CHUNK ?? 250)));

    const { records, sourceUrl, usedFallback } = await loadBduVulxmlRecords(timeoutMs);
    // eslint-disable-next-line no-console
    console.log(
      `[ingest:bdu] source=${sourceUrl} fallback=${usedFallback} parsed=${records.length} maxId=${records.reduce((a, r) => (a > r.bduId ? a : r.bduId), "")}`
    );

    let upserted = 0;
    for (let i = 0; i < records.length; i += chunkSize) {
      const chunk = records.slice(i, i + chunkSize);
      upserted += await this.upsertChunk(chunk);
    }

    const linkRes = await this.db.query(
      `INSERT INTO cve_bdu_link (cve_id, bdu_id)
       SELECT DISTINCT u.cve_id, b.bdu_id
         FROM bdu_vuln b
         CROSS JOIN LATERAL unnest(b.cve_ids) AS u(cve_id)
         JOIN cve c ON c.cve_id = u.cve_id
        ON CONFLICT (cve_id, bdu_id) DO NOTHING`
    );
    const linked = linkRes.rowCount ?? 0;
    const maxBduId = records.reduce((a, r) => (a > r.bduId ? a : r.bduId), "");
    const nowIso = new Date().toISOString();
    await this.db.query(
      `INSERT INTO audit_log(actor_type, action, metadata)
       VALUES ('system', 'bdu.ingest', $1)`,
      [
        JSON.stringify({
          sourceUrl,
          usedFallback,
          records: records.length,
          upserted,
          linked,
          maxBduId,
          ts: nowIso
        })
      ]
    );
    // eslint-disable-next-line no-console
    console.log(`[ingest:bdu] upserted=${upserted} new_cve_links=${linked}`);
  }

  private async upsertChunk(chunk: Awaited<ReturnType<typeof loadBduVulxmlRecords>>["records"]) {
    if (chunk.length === 0) return 0;
    const cols = 22;
    const values: string[] = [];
    const params: unknown[] = [];
    let p = 1;
    for (const r of chunk) {
      const placeholders: string[] = [];
      for (let c = 0; c < cols; c++) placeholders.push(`$${p++}`);
      values.push(`(${placeholders.join(", ")})`);
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

    const res = await this.db.query(
      `INSERT INTO bdu_vuln (
         bdu_id, name, description, software_names, vendors, cve_ids,
         severity, severity_level, cvss_score, cvss_vector,
         identify_date, publication_date, last_upd_date, identify_year,
         solution, status, exploit_status, fix_status, has_exploit, has_fix, sources, fstec_url
       ) VALUES ${values.join(", ")}
       ON CONFLICT (bdu_id) DO UPDATE SET
         name = EXCLUDED.name,
         description = EXCLUDED.description,
         software_names = EXCLUDED.software_names,
         vendors = EXCLUDED.vendors,
         cve_ids = EXCLUDED.cve_ids,
         severity = EXCLUDED.severity,
         severity_level = EXCLUDED.severity_level,
         cvss_score = EXCLUDED.cvss_score,
         cvss_vector = EXCLUDED.cvss_vector,
         identify_date = EXCLUDED.identify_date,
         publication_date = EXCLUDED.publication_date,
         last_upd_date = EXCLUDED.last_upd_date,
         identify_year = EXCLUDED.identify_year,
         solution = EXCLUDED.solution,
         status = EXCLUDED.status,
         exploit_status = EXCLUDED.exploit_status,
         fix_status = EXCLUDED.fix_status,
         has_exploit = EXCLUDED.has_exploit,
         has_fix = EXCLUDED.has_fix,
         sources = EXCLUDED.sources,
         fstec_url = EXCLUDED.fstec_url,
         updated_at = now()`,
      params
    );
    return res.rowCount ?? chunk.length;
  }
}

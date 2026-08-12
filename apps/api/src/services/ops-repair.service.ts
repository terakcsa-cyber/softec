import { Inject, Injectable, Logger } from "@nestjs/common";
import { XMLParser } from "fast-xml-parser";
import {
  bduFstecUrl,
  buildScoreEventsForCveIds,
  extractNvdPublishedIso,
  fetchBduVulxmlWithFallback,
  hot24ScoreHourBucket,
  hot24ScoreIdempotencyKey,
  ingestEpssFeed,
  listHot24CvesNeedingScore,
  parseBduVulNode,
  parseNvdTimestampIso,
  publishScoreEvents,
  type BduVulxmlRecord
} from "@vuln-intel/shared";
import { DbService } from "./db.service.js";
import { QueueService } from "./queue.service.js";
import { IntegrationSettingsService } from "./integration-settings.service.js";

export type OpsJobKind = "epss" | "bdu" | "nvd_hot" | "hot24_score";

type JobState = {
  kind: OpsJobKind;
  running: boolean;
  startedAt: string | null;
  finishedAt: string | null;
  ok: boolean | null;
  message: string | null;
  detail?: Record<string, unknown>;
};

const PRODUCER = { service: "api", version: "0.0.1" } as const;

@Injectable()
export class OpsRepairService {
  private readonly logger = new Logger(OpsRepairService.name);
  private readonly jobs = new Map<OpsJobKind, JobState>();

  constructor(
    @Inject(DbService) private readonly db: DbService,
    @Inject(QueueService) private readonly queue: QueueService,
    @Inject(IntegrationSettingsService) private readonly integrations: IntegrationSettingsService
  ) {
    for (const kind of ["epss", "bdu", "nvd_hot", "hot24_score"] as OpsJobKind[]) {
      this.jobs.set(kind, {
        kind,
        running: false,
        startedAt: null,
        finishedAt: null,
        ok: null,
        message: null
      });
    }
  }

  getStatus() {
    return {
      jobs: Object.fromEntries([...this.jobs.entries()].map(([k, v]) => [k, v])),
      anyRunning: [...this.jobs.values()].some((j) => j.running)
    };
  }

  async runEpss(actorEmail?: string) {
    return this.run("epss", async () => {
      const result = await ingestEpssFeed(this.db, {
        auditMeta: { reason: "manual", via: "system-health", actor: actorEmail ?? null },
        force: true
      });
      const rescored = result.changedCveIds.slice(0, Number(process.env.EPSS_RESCORE_LIMIT ?? 5_000));
      const events = await buildScoreEventsForCveIds(rescored, {
        producer: PRODUCER,
        tag: "epss-manual",
        tsBucket: "day"
      });
      publishScoreEvents((ex, rk, payload) => this.queue.publish(ex, rk, payload), events);
      return {
        message: `EPSS: rows=${result.rows} upserted=${result.upserted} rescored=${events.length} source=${result.sourceUrl}${result.skippedFresh ? " (fresh)" : ""}`,
        detail: {
          sourceUrl: result.sourceUrl,
          rows: result.rows,
          upserted: result.upserted,
          rescored: events.length,
          scoreDate: result.scoreDate ?? null,
          exploitIntelRefreshed: result.exploitIntelRefreshed ?? 0
        }
      };
    });
  }

  async runHot24(actorEmail?: string) {
    return this.run("hot24_score", async () => {
      const limit = Math.max(1, Math.min(2000, Number(process.env.HOT24_SCORE_SWEEP_LIMIT ?? 500)));
      const staleHours = Math.max(0, Math.min(168, Number(process.env.HOT24_SCORE_STALE_HOURS ?? 6)));
      const bucket = hot24ScoreHourBucket();
      const rows = await listHot24CvesNeedingScore(this.db, { limit, staleHours, bucket });
      const events = await buildScoreEventsForCveIds(
        rows.map((r) => r.cve_id),
        {
          producer: PRODUCER,
          tag: "hot24-manual",
          idempotencyKeyFor: (cveId) => hot24ScoreIdempotencyKey(cveId, bucket)
        }
      );
      const n = publishScoreEvents((ex, rk, payload) => this.queue.publish(ex, rk, payload), events);
      await this.db.query(
        `INSERT INTO audit_log(actor_type, actor_id, action, metadata)
         VALUES ('user', $1, 'ops.hot24_score', $2)`,
        [actorEmail ?? null, JSON.stringify({ enqueued: n, limit, staleHours, bucket })]
      );
      return {
        message: `Hot24 score: enqueued=${n}`,
        detail: { enqueued: n, limit, staleHours, bucket }
      };
    });
  }

  async runBdu(actorEmail?: string) {
    return this.run("bdu", async () => {
      await this.ensureBduSchema();
      const timeoutMs = Number(process.env.BDU_FETCH_TIMEOUT_MS ?? 600_000);
      const chunkSize = Math.max(50, Math.min(1000, Number(process.env.BDU_UPSERT_CHUNK ?? 250)));
      const { xml, sourceUrl, usedFallback } = await fetchBduVulxmlWithFallback(timeoutMs);
      const records = parseBduXml(xml);
      let upserted = 0;
      for (let i = 0; i < records.length; i += chunkSize) {
        upserted += await this.upsertBduChunk(records.slice(i, i + chunkSize));
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
      const nowIso = new Date().toISOString();
      await this.db.query(
        `INSERT INTO audit_log(actor_type, actor_id, action, metadata)
         VALUES ('user', $1, 'bdu.ingest', $2)`,
        [
          actorEmail ?? null,
          JSON.stringify({
            sourceUrl,
            usedFallback,
            records: records.length,
            upserted,
            linked,
            ts: nowIso,
            via: "system-health"
          })
        ]
      );
      return {
        message: `BDU: records=${records.length} upserted=${upserted} links=${linked}`,
        detail: { sourceUrl, usedFallback, records: records.length, upserted, linked }
      };
    });
  }

  /** Bounded NVD published-window sync (default last 48h) — safe after long AFK. */
  async runNvdHot(actorEmail?: string) {
    return this.run("nvd_hot", async () => {
      const hours = Math.max(6, Math.min(168, Number(process.env.OPS_NVD_HOT_HOURS ?? 48)));
      const end = new Date();
      const start = new Date(end.getTime() - hours * 3_600_000);
      const pubStartIso = start.toISOString();
      const pubEndIso = end.toISOString();
      const apiKey = await this.integrations.resolveNvdApiKey();
      const baseUrl =
        process.env.NVD_API_BASE?.trim() || "https://services.nvd.nist.gov/rest/json/cves/2.0";
      const pageSize = Math.max(20, Math.min(200, Number(process.env.NVD_RESULTS_PER_PAGE ?? 100)));
      const pageSleepMs = Math.max(1000, Number(process.env.NVD_PAGE_SLEEP_MS ?? 6500));

      let startIndex = 0;
      let upserted = 0;
      let totalResults = 0;
      // Cap pages to keep UI-triggered repair bounded.
      const maxPages = Math.max(1, Math.min(40, Number(process.env.OPS_NVD_HOT_MAX_PAGES ?? 20)));

      for (let page = 0; page < maxPages; page++) {
        if (page > 0) await sleep(pageSleepMs);
        const url = new URL(baseUrl);
        url.searchParams.set("pubStartDate", pubStartIso);
        url.searchParams.set("pubEndDate", pubEndIso);
        url.searchParams.set("startIndex", String(startIndex));
        url.searchParams.set("resultsPerPage", String(pageSize));
        const json = (await fetchNvd(url.toString(), apiKey ?? null)) as {
          vulnerabilities?: Array<{ cve?: Record<string, unknown> }>;
          totalResults?: number;
        };
        const vulns = json.vulnerabilities ?? [];
        totalResults = Number(json.totalResults ?? vulns.length);
        if (vulns.length === 0) break;
        for (const item of vulns) {
          const raw = item.cve;
          if (!raw || typeof raw.id !== "string" || !raw.id.startsWith("CVE-")) continue;
          const publishedAt =
            parseNvdTimestampIso(typeof raw.published === "string" ? raw.published : undefined) ??
            extractNvdPublishedIso(raw);
          const modifiedAt = parseNvdTimestampIso(
            typeof raw.lastModified === "string" ? raw.lastModified : undefined
          );
          const cvss = extractCvss(raw);
          await this.db.query(
            `INSERT INTO cve (cve_id, source, published_at, modified_at, cvss_base, raw)
             VALUES ($1, 'nvd', $2::timestamptz, $3::timestamptz, $4, $5::jsonb)
             ON CONFLICT (cve_id) DO UPDATE SET
               published_at = COALESCE(EXCLUDED.published_at, cve.published_at),
               modified_at = COALESCE(EXCLUDED.modified_at, cve.modified_at),
               cvss_base = COALESCE(EXCLUDED.cvss_base, cve.cvss_base),
               raw = EXCLUDED.raw`,
            [
              raw.id,
              publishedAt,
              modifiedAt,
              cvss,
              JSON.stringify(raw)
            ]
          );
          upserted += 1;
        }
        startIndex += vulns.length;
        if (startIndex >= totalResults) break;
      }

      await this.db.query(
        `INSERT INTO audit_log(actor_type, actor_id, action, metadata)
         VALUES ('user', $1, 'nvd.pub_sync', $2)`,
        [
          actorEmail ?? null,
          JSON.stringify({
            reason: "manual_hot",
            via: "system-health",
            pubStartIso,
            pubEndIso,
            upserted,
            totalResults,
            hours
          })
        ]
      );
      return {
        message: `NVD hot (${hours}h): upserted=${upserted} totalResults=${totalResults}`,
        detail: { hours, pubStartIso, pubEndIso, upserted, totalResults }
      };
    });
  }

  private async run(
    kind: OpsJobKind,
    fn: () => Promise<{ message: string; detail?: Record<string, unknown> }>
  ) {
    const cur = this.jobs.get(kind)!;
    if (cur.running) {
      return { ok: false, job: kind, message: "already running", status: cur };
    }
    cur.running = true;
    cur.startedAt = new Date().toISOString();
    cur.finishedAt = null;
    cur.ok = null;
    cur.message = "running";
    cur.detail = undefined;
    try {
      const out = await fn();
      cur.ok = true;
      cur.message = out.message;
      cur.detail = out.detail;
      this.logger.log(`[ops] ${kind} ok: ${out.message}`);
      return { ok: true, job: kind, message: out.message, detail: out.detail, status: { ...cur } };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      cur.ok = false;
      cur.message = msg;
      this.logger.error(`[ops] ${kind} failed: ${msg}`);
      return { ok: false, job: kind, message: msg, status: { ...cur } };
    } finally {
      cur.running = false;
      cur.finishedAt = new Date().toISOString();
    }
  }

  private async ensureBduSchema() {
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
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS cve_bdu_link (
        cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
        bdu_id TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (cve_id, bdu_id)
      )`
    );
  }

  private async upsertBduChunk(chunk: BduVulxmlRecord[]) {
    if (!chunk.length) return 0;
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

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

function parseBduXml(xml: Buffer | string): BduVulxmlRecord[] {
  const parser = new XMLParser({ ignoreAttributes: false, trimValues: true, processEntities: false });
  const parsed = parser.parse(typeof xml === "string" ? xml : xml.toString("utf8")) as Record<
    string,
    unknown
  >;
  const root = (parsed.vulnerabilities ?? parsed) as Record<string, unknown>;
  const rawVul = root.vul ?? parsed.vul;
  const rows = Array.isArray(rawVul) ? rawVul : rawVul ? [rawVul] : [];
  const out: BduVulxmlRecord[] = [];
  for (const row of rows) {
    const rec = parseBduVulNode(row);
    if (rec) out.push(rec);
  }
  return out;
}

function extractCvss(raw: Record<string, unknown>): number | null {
  const metrics = raw.metrics as Record<string, unknown> | undefined;
  if (!metrics || typeof metrics !== "object") return null;
  for (const k of Object.keys(metrics)) {
    const arr = metrics[k];
    if (!Array.isArray(arr)) continue;
    for (const c of arr) {
      const score = (c as { cvssData?: { baseScore?: unknown } })?.cvssData?.baseScore;
      if (typeof score === "number" && score >= 0 && score <= 10) return score;
    }
  }
  return null;
}

async function fetchNvd(url: string, apiKey: string | null) {
  const headers: Record<string, string> = { accept: "application/json" };
  if (apiKey) headers.apiKey = apiKey;
  let res = await fetch(url, { headers, signal: AbortSignal.timeout(60_000) });
  if (!res.ok && res.status === 404 && apiKey) {
    res = await fetch(url, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(60_000)
    });
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`NVD ${res.status} ${text.slice(0, 200)}`);
  }
  return res.json();
}

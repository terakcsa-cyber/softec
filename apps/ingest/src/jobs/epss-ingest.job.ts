import { Inject, Injectable, OnModuleInit } from "@nestjs/common";
import { v4 as uuidv4 } from "uuid";
import { QueueEventType, stableJsonStringify, sha256Hex } from "@vuln-intel/shared";
import { gunzipSync } from "node:zlib";
import { DbService } from "../services/db.service.js";
import { QueueService } from "../services/queue.service.js";

type ParsedRow = { cveId: string; epss: number; percentile?: number; scoredAt?: string };

@Injectable()
export class EpssIngestJob implements OnModuleInit {
  constructor(
    @Inject(DbService) private readonly db: DbService,
    @Inject(QueueService) private readonly queue: QueueService
  ) {}

  async onModuleInit() {
    const intervalMs = Number(process.env.EPSS_POLL_INTERVAL_MS ?? 24 * 60 * 60 * 1000); // daily
    const initialDelayMs = Number(process.env.EPSS_INITIAL_DELAY_MS ?? 12_000);
    setTimeout(() => {
      this.runForever(intervalMs).catch((e) => {
        // eslint-disable-next-line no-console
        console.error(e);
        process.exit(1);
      });
    }, initialDelayMs);
  }

  private async runForever(intervalMs: number) {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const startedAt = Date.now();
      try {
        await this.ensureSchema();
        await this.runOnce();
      } catch (e) {
        // eslint-disable-next-line no-console
        console.error("EPSS ingest failed", e);
      } finally {
        const sleep = Math.max(30_000, intervalMs - (Date.now() - startedAt));
        await new Promise((r) => setTimeout(r, sleep));
      }
    }
  }

  private async ensureSchema() {
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS epss_score (
        cve_id TEXT PRIMARY KEY,
        score DOUBLE PRECISION NOT NULL CHECK (score >= 0 AND score <= 1),
        percentile DOUBLE PRECISION CHECK (percentile >= 0 AND percentile <= 1),
        scored_at DATE,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS epss_score_score_idx ON epss_score (score DESC)`);
  }

  private async runOnce() {
    const url = process.env.EPSS_FEED_URL ?? "https://epss.cyentia.com/epss_scores-current.csv.gz";
    const res = await fetch(url, { headers: { accept: "application/gzip, text/csv;q=0.9,*/*;q=0.8" } });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`EPSS fetch failed: ${res.status} ${res.statusText} ${text}`);
    }

    const buf = Buffer.from(await res.arrayBuffer());
    const csv = this.maybeGunzip(buf);
    const rows = this.parseCsv(csv);
    if (rows.length === 0) return;

    const nowIso = new Date().toISOString();
    const batchSize = Number(process.env.EPSS_BATCH_SIZE ?? 1500);
    let upserted = 0;

    for (let i = 0; i < rows.length; i += batchSize) {
      const batch = rows.slice(i, i + batchSize);
      const cveIds = batch.map((r) => r.cveId);
      const scores = batch.map((r) => r.epss);
      const percentiles = batch.map((r) => (r.percentile == null ? null : r.percentile));
      const scoredAts = batch.map((r) => (r.scoredAt ? new Date(r.scoredAt) : null));

      await this.db.query(
        `INSERT INTO epss_score(cve_id, score, percentile, scored_at, updated_at)
         SELECT * FROM UNNEST($1::text[], $2::double precision[], $3::double precision[], $4::date[], $5::timestamptz[])
         ON CONFLICT (cve_id)
         DO UPDATE SET score = EXCLUDED.score,
                       percentile = EXCLUDED.percentile,
                       scored_at = EXCLUDED.scored_at,
                       updated_at = now()`,
        [cveIds, scores, percentiles, scoredAts, Array(batch.length).fill(new Date())]
      );
      upserted += batch.length;
    }

    // Deterministic rescore: find CVEs we have AND which had EPSS updated since last watermark.
    const last = await this.db.query<{ metadata: any }>(
      `SELECT metadata FROM audit_log
        WHERE action = 'epss.watermark'
     ORDER BY ts DESC
        LIMIT 1`
    );
    const sinceIso =
      (last.rowCount ?? 0) > 0 && last.rows[0]?.metadata?.updatedSince
        ? String(last.rows[0]?.metadata?.updatedSince)
        : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();

    const changed = await this.db.query<{ cve_id: string }>(
      `SELECT e.cve_id
         FROM epss_score e
         JOIN cve c ON c.cve_id = e.cve_id
        WHERE e.updated_at >= $1
        ORDER BY e.updated_at DESC
        LIMIT $2`,
      [sinceIso, Number(process.env.EPSS_RESCORE_LIMIT ?? 20000)]
    );

    for (const r of changed.rows) {
      const idempotencyKey = await sha256Hex(stableJsonStringify({ t: "epss", cveId: r.cve_id, ts: nowIso }));
      this.queue.publish("vuln.events", "vuln.score.requested.v1", {
        id: uuidv4(),
        type: QueueEventType.ScoreCveRequested,
        ts: nowIso,
        producer: { service: "ingest", version: "0.0.1" },
        idempotencyKey: `score:${idempotencyKey}`,
        payload: { cveId: r.cve_id }
      });
    }

    await this.db.query(
      `INSERT INTO audit_log(actor_type, action, metadata)
       VALUES ('system', 'epss.watermark', $1)`,
      [JSON.stringify({ updatedSince: nowIso, rescored: changed.rowCount, ts: nowIso })]
    );

    await this.db.query(
      `INSERT INTO audit_log(actor_type, action, metadata)
       VALUES ('system', 'epss.ingest', $1)`,
      [JSON.stringify({ url, rows: rows.length, upserted, rescored: changed.rowCount, ts: nowIso })]
    );
  }

  private maybeGunzip(buf: Buffer): string {
    // gzip magic header: 1f 8b
    if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
      return gunzipSync(buf).toString("utf8");
    }
    return buf.toString("utf8");
  }

  private parseCsv(csv: string): ParsedRow[] {
    const lines = csv.split(/\r?\n/);
    if (lines.length <= 1) return [];
    const header = lines[0] ?? "";
    const idx = this.headerIndexes(header);

    const out: ParsedRow[] = [];
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (!line) continue;
      // Simple CSV split (EPSS feed does not include quoted commas for these columns).
      const cols = line.split(",");
      const cveId = cols[idx.cve] ?? "";
      if (!/^CVE-\d{4}-\d+$/.test(cveId)) continue;

      const epssRaw = cols[idx.epss];
      const epss = epssRaw ? Number(epssRaw) : NaN;
      if (!Number.isFinite(epss) || epss < 0 || epss > 1) continue;

      const pRaw = idx.percentile != null ? cols[idx.percentile] : undefined;
      const percentile = pRaw != null && pRaw.length > 0 ? Number(pRaw) : undefined;

      const scoredAt = idx.date != null ? cols[idx.date] : undefined;
      out.push({ cveId, epss, percentile: Number.isFinite(percentile) ? percentile : undefined, scoredAt });
    }
    return out;
  }

  private headerIndexes(headerLine: string): {
    cve: number;
    epss: number;
    percentile?: number;
    date?: number;
  } {
    const cols = headerLine.split(",").map((c) => c.trim().toLowerCase());
    const cve = cols.indexOf("cve");
    const epss = cols.indexOf("epss");
    const percentile = cols.indexOf("percentile");
    const date = cols.indexOf("date");
    if (cve < 0 || epss < 0) return { cve: 0, epss: 1 };
    return {
      cve,
      epss,
      percentile: percentile >= 0 ? percentile : undefined,
      date: date >= 0 ? date : undefined
    };
  }
}


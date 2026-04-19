import { Inject, Injectable, OnModuleInit } from "@nestjs/common";
import { v4 as uuidv4 } from "uuid";
import {
  QueueEventType,
  extractVendorProductPairsFromCveRaw,
  stableJsonStringify,
  sha256Hex
} from "@vuln-intel/shared";
import { DbService } from "../services/db.service.js";
import { QueueService } from "../services/queue.service.js";

type NvdApiItem = {
  cve: any;
};

@Injectable()
export class NvdIngestJob implements OnModuleInit {
  constructor(
    @Inject(DbService) private readonly db: DbService,
    @Inject(QueueService) private readonly queue: QueueService
  ) {}

  async onModuleInit() {
    const intervalMs = Number(process.env.NVD_POLL_INTERVAL_MS ?? 15 * 60 * 1000);
    const initialDelayMs = Number(process.env.NVD_INITIAL_DELAY_MS ?? 3_000);

    setTimeout(() => {
      this.runForever(intervalMs).catch((e) => {
        // eslint-disable-next-line no-console
        console.error(e);
        process.exit(1);
      });
    }, initialDelayMs);

    const sweepOnStartMs = Number(process.env.HOT24_AI_SWEEP_ON_START_MS ?? 8_000);
    if (sweepOnStartMs > 0 && process.env.HOT24_AI_SWEEP !== "false") {
      setTimeout(() => {
        this.sweepHotWindowEnrich().catch((e) => {
          // eslint-disable-next-line no-console
          console.error("[ingest:nvd] hot24h sweep on start failed", e);
        });
      }, sweepOnStartMs);
    }

    const sweepIntervalMs = Number(process.env.HOT24_AI_SWEEP_INTERVAL_MS ?? 0);
    if (sweepIntervalMs > 0 && process.env.HOT24_AI_SWEEP !== "false") {
      setInterval(() => {
        this.sweepHotWindowEnrich().catch((e) => {
          // eslint-disable-next-line no-console
          console.error("[ingest:nvd] hot24h sweep interval failed", e);
        });
      }, sweepIntervalMs);
    }

    // Старше 24ч: по умолчанию не догоняем в фоне — только по открытию CVE в UI. Включить: BACKLOG_AI_SWEEP=true
    const backlogOnStartMs = Number(process.env.BACKLOG_AI_SWEEP_ON_START_MS ?? 20_000);
    if (backlogOnStartMs > 0 && process.env.BACKLOG_AI_SWEEP === "true") {
      setTimeout(() => {
        this.sweepBacklogEnrich().catch((e) => {
          // eslint-disable-next-line no-console
          console.error("[ingest:nvd] backlog AI sweep on start failed", e);
        });
      }, backlogOnStartMs);
    }

    const backlogIntervalMs = Number(process.env.BACKLOG_AI_SWEEP_INTERVAL_MS ?? 30_000);
    if (backlogIntervalMs > 0 && process.env.BACKLOG_AI_SWEEP === "true") {
      setInterval(() => {
        this.sweepBacklogEnrich().catch((e) => {
          // eslint-disable-next-line no-console
          console.error("[ingest:nvd] backlog AI sweep interval failed", e);
        });
      }, backlogIntervalMs);
    }
  }

  private async runForever(intervalMs: number) {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const startedAt = Date.now();
      try {
        // eslint-disable-next-line no-console
        console.log("[ingest:nvd] cycle started");
        await this.runOnce();
        // eslint-disable-next-line no-console
        console.log("[ingest:nvd] cycle completed");
      } catch (e) {
        // eslint-disable-next-line no-console
        console.error("NVD ingest failed", e);
      } finally {
        const sleep = Math.max(5_000, intervalMs - (Date.now() - startedAt));
        await new Promise((r) => setTimeout(r, sleep));
      }
    }
  }

  /** Окно «горячих» CVE на дашборде: published за последние 24 часа (как view=last24h в API). */
  static isPublishedInDashboardHotWindow(publishedAtIso: string | null | undefined): boolean {
    if (!publishedAtIso) return false;
    const t = new Date(publishedAtIso).getTime();
    if (Number.isNaN(t)) return false;
    return t >= Date.now() - 24 * 60 * 60 * 1000;
  }

  private async runOnce() {
    const apiKey = process.env.NVD_API_KEY;
    const baseUrl = process.env.NVD_API_BASE ?? "https://services.nvd.nist.gov/rest/json/cves/2.0";

    // Watermark stored in DB (audit_log used as lightweight kv for now).
    const last = await this.db.query<{ metadata: any }>(
      `SELECT metadata FROM audit_log
        WHERE action = 'nvd.watermark'
     ORDER BY ts DESC
        LIMIT 1`
    );

    const sinceIso =
      (last.rowCount ?? 0) > 0 && last.rows[0]?.metadata?.modifiedStart
        ? String(last.rows[0]?.metadata?.modifiedStart)
        : // First run: backfill a longer window to ensure we get data.
          new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();

    const nowIso = new Date().toISOString();
    // Overlap a bit to avoid missing late-arriving updates / clock skew.
    const overlapMs = Number(process.env.NVD_WATERMARK_OVERLAP_MS ?? 120_000);
    const nextStartIso = new Date(Date.now() - Math.max(0, overlapMs)).toISOString();

    let startIndex = 0;
    const resultsPerPage = 2000;
    let processed = 0;

    for (;;) {
      const url = new URL(baseUrl);
      url.searchParams.set("lastModStartDate", sinceIso);
      url.searchParams.set("lastModEndDate", nowIso);
      url.searchParams.set("startIndex", String(startIndex));
      url.searchParams.set("resultsPerPage", String(resultsPerPage));

      const page: any = await this.fetchJson(url.toString(), apiKey);
      const vulnerabilities = (page?.vulnerabilities ?? []) as NvdApiItem[];
      const totalResults = Number(page?.totalResults ?? vulnerabilities.length);

      for (const item of vulnerabilities) {
        const cveId = String(item?.cve?.id ?? "");
        if (!cveId.startsWith("CVE-")) continue;
        try {
          await this.upsertCveAndFanout({
            cveId,
            source: "nvd",
            raw: item.cve,
            publishedAt: item?.cve?.published,
            modifiedAt: item?.cve?.lastModified
          });
          processed++;
        } catch (e) {
          // eslint-disable-next-line no-console
          console.error(`[ingest:nvd] failed cve=${cveId}`, e);
        }
      }

      startIndex += vulnerabilities.length;
      if (startIndex >= totalResults || vulnerabilities.length === 0) break;
      await new Promise((r) => setTimeout(r, Number(process.env.NVD_PAGE_SLEEP_MS ?? 900)));
    }

    // eslint-disable-next-line no-console
    console.log(`[ingest:nvd] processed=${processed} window=${sinceIso}..${nowIso} nextStart=${nextStartIso}`);

    await this.backfillCvssBase();

    await this.sweepHotWindowEnrich();

    await this.db.query(
      `INSERT INTO audit_log(actor_type, action, metadata)
       VALUES ('system', 'nvd.watermark', $1)`,
      [
        JSON.stringify({
          modifiedStart: nextStartIso,
          modifiedEnd: nowIso,
          processed
        })
      ]
    );
  }

  private async upsertCveAndFanout(input: {
    cveId: string;
    source: string;
    raw: any;
    publishedAt?: string;
    modifiedAt?: string;
  }) {
    const publishedAtIso = this.toIsoZ(input.publishedAt);
    const modifiedAtIso = this.toIsoZ(input.modifiedAt);
    const cvss = this.extractCvssBaseScore(input.raw);

    const inserted = await this.db.query(
      `INSERT INTO cve(cve_id, source, published_at, modified_at, cvss_base, raw)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (cve_id)
       DO UPDATE SET raw = EXCLUDED.raw,
                     source = EXCLUDED.source,
                     published_at = COALESCE(EXCLUDED.published_at, cve.published_at),
                     modified_at = COALESCE(EXCLUDED.modified_at, cve.modified_at),
                     cvss_base = COALESCE(EXCLUDED.cvss_base, cve.cvss_base),
                     updated_at = now()
       RETURNING cve_id`,
      [
        input.cveId,
        input.source,
        publishedAtIso ? new Date(publishedAtIso) : null,
        modifiedAtIso ? new Date(modifiedAtIso) : null,
        cvss ?? null,
        JSON.stringify(input.raw)
      ]
    );

    if (inserted.rowCount === 0) return;

    // Pipeline-level vendor/product index: always keep it in sync with CVE raw.
    await this.upsertVendorProductIndex(input.cveId, input.raw);

    const idempotencyKey = await sha256Hex(
      stableJsonStringify({
        t: "ingest",
        cveId: input.cveId,
        modifiedAt: input.modifiedAt ?? null
      })
    );

    // Фоновое ИИ: только CVE за последние 24ч (как view=last24h). Остальные — по открытию в UI (POST /enrich).
    // Отключить весь fanout: NVD_FANOUT_ENRICH=false.
    if (process.env.NVD_FANOUT_ENRICH !== "false" && NvdIngestJob.isPublishedInDashboardHotWindow(publishedAtIso)) {
      this.queue.publish(
        "vuln.events",
        "vuln.enrich.requested.v1",
        {
          id: uuidv4(),
          type: QueueEventType.EnrichCveRequested,
          ts: new Date().toISOString(),
          producer: { service: "ingest", version: "0.0.1" },
          idempotencyKey: `enrich:${idempotencyKey}`,
          payload: {
            cveId: input.cveId,
            source: input.source,
            raw: input.raw
          }
        },
        { priority: 9 }
      );
    }

    // Score request (EPSS/KEV enrichment comes later)
    this.queue.publish("vuln.events", "vuln.score.requested.v1", {
      id: uuidv4(),
      type: QueueEventType.ScoreCveRequested,
      ts: new Date().toISOString(),
      producer: { service: "ingest", version: "0.0.1" },
      idempotencyKey: `score:${idempotencyKey}`,
      payload: {
        cveId: input.cveId,
        cvss,
        publishedAt: publishedAtIso,
        modifiedAt: modifiedAtIso
      }
    });
  }

  private async upsertVendorProductIndex(cveId: string, raw: any) {
    const pairsRaw = extractVendorProductPairsFromCveRaw(raw);
    // Dedupe within one CVE: duplicate constrained rows in a single INSERT break Postgres ON CONFLICT.
    const dedup = new Map<string, (typeof pairsRaw)[number]>();
    for (const p of pairsRaw) {
      const productKeyNorm = p.product ?? "";
      const key = `${p.vendor}\0${productKeyNorm}`;
      if (!dedup.has(key)) dedup.set(key, p);
    }
    const pairs = Array.from(dedup.values());
    // Replace the index rows for this CVE deterministically.
    await this.db.query(`DELETE FROM cve_vendor_product WHERE cve_id = $1`, [cveId]);
    if (pairs.length === 0) return;

    const values: string[] = [];
    const params: any[] = [];
    for (const p of pairs) {
      const vendorKey = p.vendor;
      const productKey = p.product;
      const productKeyNorm = productKey ?? "";
      params.push(cveId, vendorKey, vendorKey, productKey, productKey, productKeyNorm, p.source);
      const base = params.length - 6;
      values.push(
        `($${base}, $${base + 1}, $${base + 2}, $${base + 3}, $${base + 4}, $${base + 5}, $${base + 6})`
      );
    }

    await this.db.query(
      `INSERT INTO cve_vendor_product (cve_id, vendor_key, vendor, product_key, product, product_key_norm, source)
       VALUES ${values.join(", ")}
       ON CONFLICT (cve_id, vendor_key, product_key_norm)
       DO UPDATE SET source = EXCLUDED.source,
                     product_key = EXCLUDED.product_key,
                     product = EXCLUDED.product,
                     vendor = EXCLUDED.vendor,
                     updated_at = now()`,
      params
    );
  }

  private toIsoZ(value?: string): string | undefined {
    if (!value) return undefined;
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return undefined;
    return d.toISOString();
  }

  private extractCvssBaseScore(raw: any): number | undefined {
    const metrics = raw?.metrics;
    if (!metrics || typeof metrics !== "object") return undefined;
    const candidates: unknown[] = [];
    for (const k of Object.keys(metrics)) {
      const v = (metrics as any)[k];
      if (Array.isArray(v)) candidates.push(...v);
    }
    for (const c of candidates) {
      const score = (c as any)?.cvssData?.baseScore;
      if (typeof score === "number" && score >= 0 && score <= 10) return score;
    }
    return undefined;
  }

  private async backfillCvssBase() {
    const limit = Number(process.env.CVSS_BACKFILL_LIMIT ?? 500);
    const batch = await this.db.query<{ cve_id: string; raw: any }>(
      `SELECT cve_id, raw
         FROM cve
        WHERE cvss_base IS NULL
        ORDER BY published_at DESC NULLS LAST
        LIMIT $1`,
      [limit]
    );
    if ((batch.rowCount ?? 0) === 0) return;

    let updated = 0;
    for (const row of batch.rows) {
      const cvss = this.extractCvssBaseScore(row.raw);
      if (cvss == null) continue;
      // eslint-disable-next-line no-await-in-loop
      await this.db.query(`UPDATE cve SET cvss_base = $2, updated_at = now() WHERE cve_id = $1 AND cvss_base IS NULL`, [
        row.cve_id,
        cvss
      ]);
      updated++;
    }

    if (updated > 0) {
      // eslint-disable-next-line no-console
      console.log(`[ingest:nvd] cvss_backfill updated=${updated}`);
    }
  }

  /**
   * Догоняем ИИ для CVE из окна 24ч, у которых нет успешной записи в enrichment_ai:
   * бэкфилл без fanout, сбой до фикса LLM, «LLM not configured», последняя строка — enrich_error.
   * Ключ idempotency отдельный от ingest (`enrich:hot24h:…`), чтобы после настройки Llama повторить обработку.
   */
  private async sweepHotWindowEnrich() {
    if (process.env.NVD_FANOUT_ENRICH === "false" || process.env.HOT24_AI_SWEEP === "false") return;

    const limit = Math.max(1, Math.min(500, Number(process.env.HOT24_AI_SWEEP_LIMIT ?? 200)));
    const hourBucket = new Date();
    hourBucket.setMinutes(0, 0, 0);
    const bucket = hourBucket.toISOString().slice(0, 13);

    const r = await this.db.query<{ cve_id: string; raw: unknown }>(
      `SELECT c.cve_id, c.raw
         FROM cve c
    LEFT JOIN LATERAL (
          SELECT output_text, output_json
            FROM enrichment_ai
           WHERE cve_id = c.cve_id
        ORDER BY created_at DESC
           LIMIT 1
         ) latest ON true
        WHERE c.published_at >= now() - interval '24 hours'
          AND (
            latest.output_text IS NULL
            OR latest.output_text = 'LLM not configured.'
            OR COALESCE(latest.output_json->>'summary', '') LIKE 'LLM not configured%'
            OR (latest.output_json @> '{"_enrich_error": true}'::jsonb)
          )
     ORDER BY c.published_at DESC NULLS LAST
        LIMIT $1`,
      [limit]
    );

    let n = 0;
    for (const row of r.rows) {
      const raw = row.raw;
      const rawObj =
        raw != null && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {};
      this.queue.publish(
        "vuln.events",
        "vuln.enrich.requested.v1",
        {
          id: uuidv4(),
          type: QueueEventType.EnrichCveRequested,
          ts: new Date().toISOString(),
          producer: { service: "ingest", version: "0.0.1" },
          idempotencyKey: `enrich:hot24h:${row.cve_id}:${bucket}`,
          payload: {
            cveId: row.cve_id,
            // VulnerabilitySourceSchema: nvd | mitre | other — sweep не отдельный enum
            source: "other",
            raw: rawObj
          }
        },
        { priority: 9 }
      );
      n++;
    }
    if (n > 0) {
      // eslint-disable-next-line no-console
      console.log(`[ingest:nvd] hot24h AI sweep enqueued=${n} (limit=${limit}, bucket=${bucket})`);
    }
  }

  /**
   * Опционально: догон CVE старше 24ч в фоне. По умолчанию выкл.; включить BACKLOG_AI_SWEEP=true.
   */
  private async sweepBacklogEnrich() {
    if (process.env.BACKLOG_AI_SWEEP !== "true") return;

    const limit = Math.max(1, Math.min(2000, Number(process.env.BACKLOG_AI_SWEEP_LIMIT ?? 400)));
    const d = new Date();
    const dayBucket = d.toISOString().slice(0, 10);

    const r = await this.db.query<{ cve_id: string; raw: unknown }>(
      `SELECT c.cve_id, c.raw
         FROM cve c
    LEFT JOIN LATERAL (
          SELECT output_text, output_json
            FROM enrichment_ai
           WHERE cve_id = c.cve_id
        ORDER BY created_at DESC
           LIMIT 1
         ) latest ON true
        WHERE (c.published_at IS NULL OR c.published_at < now() - interval '24 hours')
          AND (
            latest.output_text IS NULL
            OR latest.output_text = 'LLM not configured.'
            OR COALESCE(latest.output_json->>'summary', '') LIKE 'LLM not configured%'
            OR (latest.output_json @> '{"_enrich_error": true}'::jsonb)
          )
     ORDER BY c.published_at DESC NULLS LAST
        LIMIT $1`,
      [limit]
    );

    let n = 0;
    for (const row of r.rows) {
      const raw = row.raw;
      const rawObj =
        raw != null && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {};
      this.queue.publish(
        "vuln.events",
        "vuln.enrich.requested.v1",
        {
          id: uuidv4(),
          type: QueueEventType.EnrichCveRequested,
          ts: new Date().toISOString(),
          producer: { service: "ingest", version: "0.0.1" },
          idempotencyKey: `enrich:backlog:${row.cve_id}:${dayBucket}`,
          payload: {
            cveId: row.cve_id,
            source: "other",
            raw: rawObj
          }
        },
        { priority: 6 }
      );
      n++;
    }
    if (n > 0) {
      // eslint-disable-next-line no-console
      console.log(`[ingest:nvd] backlog AI sweep enqueued=${n} (limit=${limit}, day=${dayBucket})`);
    }
  }

  private async fetchJson(url: string, apiKey?: string) {
    const headers: Record<string, string> = { accept: "application/json" };
    if (apiKey) headers["apiKey"] = apiKey;

    const maxAttempts = Number(process.env.NVD_FETCH_RETRIES ?? 4);
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const res = await fetch(url, { headers });
      if (res.ok) return res.json();
      const retryAfter = res.headers.get("retry-after");
      const backoffMs = retryAfter ? Number(retryAfter) * 1000 : 250 * attempt * attempt;
      if (attempt === maxAttempts) {
        const text = await res.text().catch(() => "");
        throw new Error(`NVD fetch failed: ${res.status} ${res.statusText} ${text}`);
      }
      await new Promise((r) => setTimeout(r, backoffMs));
    }
    throw new Error("unreachable");
  }
}


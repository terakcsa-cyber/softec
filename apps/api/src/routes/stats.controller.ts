import { randomUUID } from "node:crypto";
import { Controller, Get, Logger, Post, Query } from "@nestjs/common";
import { DbService } from "../services/db.service.js";
import { QueueService } from "../services/queue.service.js";

type VendorAgg = { vendor: string; count: number };
type ProductAgg = { vendor: string; product: string; count: number };

@Controller("stats")
export class StatsController {
  private readonly logger = new Logger(StatsController.name);

  constructor(
    private readonly db: DbService,
    private readonly queue: QueueService
  ) {}

  @Get("summary")
  async summary() {
    const total = await this.db.query<{ n: string }>(`SELECT COUNT(*)::text AS n FROM cve`);
    const lastHour = await this.db.query<{ n: string }>(
      `SELECT COUNT(*)::text AS n
         FROM cve
        WHERE modified_at IS NOT NULL
          AND modified_at >= now() - interval '60 minutes'`
    );
    const kev = await this.db.query<{ n: string }>(`SELECT COUNT(*)::text AS n FROM kev`);
    const epss = await this.db.query<{ n: string }>(`SELECT COUNT(*)::text AS n FROM epss_score`);
    const cvss = await this.db.query<{ n: string }>(`SELECT COUNT(*)::text AS n FROM cve WHERE cvss_base IS NOT NULL`);
    const scored = await this.db.query<{ n: string }>(`SELECT COUNT(*)::text AS n FROM risk_score`);
    const aiEnriched = await this.db.query<{ n: string }>(
      `SELECT COUNT(DISTINCT cve_id)::text AS n FROM enrichment_ai`
    );
    const lastAi = await this.db.query<{ ts: string | null }>(
      `SELECT to_char(MAX(created_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS ts
         FROM enrichment_ai`
    );
    const aiLastMinute = await this.db.query<{ n: string }>(
      `SELECT COUNT(*)::text AS n
         FROM enrichment_ai
        WHERE created_at >= now() - interval '60 seconds'`
    );
    const lastNvd = await this.db.query<{ ts: string | null }>(
      `SELECT to_char(MAX(ts) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS ts
         FROM audit_log
        WHERE action = 'nvd.watermark'`
    );
    const lastEpss = await this.db.query<{ ts: string | null }>(
      `SELECT to_char(MAX(ts) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS ts
         FROM audit_log
        WHERE action = 'epss.ingest'`
    );
    const lastKev = await this.db.query<{ ts: string | null }>(
      `SELECT to_char(MAX(ts) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS ts
         FROM audit_log
        WHERE action = 'kev.ingest'`
    );
    const lastScore = await this.db.query<{ ts: string | null }>(
      `SELECT to_char(MAX(computed_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS ts
         FROM risk_score`
    );

    /** По умолчанию включено: обогащение по открытию CVE и POST /enrich. Явно `false` — только фон (ingest/очередь). */
    const allowManualEnrich = process.env.ALLOW_MANUAL_ENRICH !== "false";

    return {
      totalCves: Number(total.rows[0]?.n ?? 0),
      cvesLastHourCount: Number(lastHour.rows[0]?.n ?? 0),
      kevCount: Number(kev.rows[0]?.n ?? 0),
      epssCount: Number(epss.rows[0]?.n ?? 0),
      cvssCount: Number(cvss.rows[0]?.n ?? 0),
      scoredCount: Number(scored.rows[0]?.n ?? 0),
      aiEnrichedCount: Number(aiEnriched.rows[0]?.n ?? 0),
      aiLastEnrichAt: lastAi.rows[0]?.ts ?? null,
      aiEnrichPerMinute: Number(aiLastMinute.rows[0]?.n ?? 0),
      freshness: {
        nvdWatermarkTs: lastNvd.rows[0]?.ts ?? null,
        epssIngestTs: lastEpss.rows[0]?.ts ?? null,
        kevIngestTs: lastKev.rows[0]?.ts ?? null,
        riskScoreComputedAt: lastScore.rows[0]?.ts ?? null
      },
      /** When false, POST /cves/:id/enrich is disabled (pipeline-only AI). */
      manualEnrichAllowed: allowManualEnrich
    };
  }

  /**
   * Top vendors/products from NVD CPEs for quick triage.
   * Uses last 24h by default (published_at).
   */
  @Get("vendors")
  async vendors(@Query("windowHours") windowHoursRaw?: string, @Query("limit") limitRaw?: string) {
    const windowHours = Math.max(1, Math.min(24 * 30, Number(windowHoursRaw ?? 24)));
    const limit = Math.max(3, Math.min(50, Number(limitRaw ?? 12)));
    const sampleLimit = Math.max(200, Math.min(8000, Number(process.env.STATS_VENDOR_SAMPLE_LIMIT ?? 4000)));

    const sampled = await this.db.query<{ n: string }>(
      `SELECT COUNT(*)::text AS n
         FROM cve
        WHERE published_at IS NOT NULL
          AND published_at >= now() - ($1::text || ' hours')::interval`,
      [String(windowHours)]
    );

    const used = await this.db.query<{ used_cpe: string; used_fallback: string }>(
      `SELECT
         COUNT(DISTINCT CASE WHEN vp.source = 'cpe' THEN vp.cve_id END)::text AS used_cpe,
         COUNT(DISTINCT CASE WHEN vp.source <> 'cpe' THEN vp.cve_id END)::text AS used_fallback
       FROM cve_vendor_product vp
       JOIN cve c ON c.cve_id = vp.cve_id
      WHERE c.published_at IS NOT NULL
        AND c.published_at >= now() - ($1::text || ' hours')::interval`,
      [String(windowHours)]
    );

    const vendorRows = await this.db.query<{ vendor: string; count: string }>(
      `SELECT vp.vendor AS vendor, COUNT(DISTINCT vp.cve_id)::text AS count
         FROM cve_vendor_product vp
         JOIN cve c ON c.cve_id = vp.cve_id
        WHERE c.published_at IS NOT NULL
          AND c.published_at >= now() - ($1::text || ' hours')::interval
     GROUP BY vp.vendor
     ORDER BY COUNT(DISTINCT vp.cve_id) DESC
        LIMIT $2`,
      [String(windowHours), limit]
    );
    const productRows = await this.db.query<{ vendor: string; product: string; count: string }>(
      `SELECT vp.vendor AS vendor, vp.product AS product, COUNT(DISTINCT vp.cve_id)::text AS count
         FROM cve_vendor_product vp
         JOIN cve c ON c.cve_id = vp.cve_id
        WHERE c.published_at IS NOT NULL
          AND c.published_at >= now() - ($1::text || ' hours')::interval
          AND vp.product_key_norm <> ''
     GROUP BY vp.vendor, vp.product
     ORDER BY COUNT(DISTINCT vp.cve_id) DESC
        LIMIT $2`,
      [String(windowHours), limit]
    );

    const vendors: VendorAgg[] = vendorRows.rows.map((x) => ({ vendor: x.vendor, count: Number(x.count) }));
    const products: ProductAgg[] = productRows.rows.map((x) => ({
      vendor: x.vendor,
      product: x.product,
      count: Number(x.count)
    }));

    return {
      windowHours,
      sampledCves: Number(sampled.rows[0]?.n ?? 0),
      method: "indexed",
      usedCpe: Number(used.rows[0]?.used_cpe ?? 0),
      usedFallback: Number(used.rows[0]?.used_fallback ?? 0),
      vendors,
      products
    };
  }

  @Get("queue")
  async queueHealth() {
    try {
      const [enrich, score, dlqEnrich, dlqScore] = await Promise.all([
        this.queue.getQueueDepth("ai.enrich"),
        this.queue.getQueueDepth("ai.score"),
        this.queue.getQueueDepth("dlq.ai.enrich"),
        this.queue.getQueueDepth("dlq.ai.score")
      ]);
      return {
        ok: true,
        queues: { enrich, score, dlqEnrich, dlqScore }
      };
    } catch (e) {
      return {
        ok: false,
        error: e instanceof Error ? e.message : String(e)
      };
    }
  }

  @Get("dlq/sample")
  async dlqSample(@Query("queue") queueRaw?: string, @Query("limit") limitRaw?: string) {
    const queue = String(queueRaw ?? "");
    if (queue !== "dlq.ai.enrich" && queue !== "dlq.ai.score") {
      return { ok: false, error: "Invalid queue (expected dlq.ai.enrich or dlq.ai.score)" };
    }
    const limit = Math.max(1, Math.min(50, Number(limitRaw ?? 10)));
    try {
      const messages = await this.queue.sampleQueueRequeue(queue, limit);
      return { ok: true, queue, messages };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  }

  @Post("dlq/clear")
  async dlqClear(@Query("queue") queueRaw?: string, @Query("limit") limitRaw?: string) {
    const queue = String(queueRaw ?? "");
    if (queue !== "dlq.ai.enrich" && queue !== "dlq.ai.score") {
      return { ok: false, error: "Invalid queue (expected dlq.ai.enrich or dlq.ai.score)" };
    }
    const limit = Math.max(1, Math.min(50_000, Number(limitRaw ?? 1000)));
    try {
      const r = await this.queue.drainQueue(queue, limit);
      return { ok: true, queue, ...r };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  }

  @Post("dlq/retry")
  async dlqRetry(@Query("queue") queueRaw?: string, @Query("limit") limitRaw?: string) {
    const queue = String(queueRaw ?? "");
    if (queue !== "dlq.ai.enrich" && queue !== "dlq.ai.score") {
      return { ok: false, error: "Invalid queue (expected dlq.ai.enrich or dlq.ai.score)" };
    }
    const limit = Math.max(1, Math.min(50_000, Number(limitRaw ?? 1000)));
    try {
      const r = await this.queue.drainQueue(queue, limit, async (body) => {
        const env = JSON.parse(body) as {
          type?: string;
          idempotencyKey?: string;
          [k: string]: unknown;
        };
        // Новый idempotencyKey — иначе повтор из DLQ часто молча отбрасывается (ключ уже в idempotency_key).
        // Обрезаем base: повторные dlq/retry иначе раздувают ключ без конца.
        const withReplayKey = (e: typeof env) => {
          let base = typeof e.idempotencyKey === "string" && e.idempotencyKey.length > 0 ? e.idempotencyKey : "unknown";
          const maxBase = 512;
          if (base.length > maxBase) base = base.slice(0, maxBase);
          return { ...e, idempotencyKey: `${base}:dlq:${randomUUID()}` };
        };
        if (env?.type === "vuln.enrich.requested.v1") {
          await this.queue.publish("vuln.events", "vuln.enrich.requested.v1", withReplayKey(env), {
            priority: 9
          });
        } else if (env?.type === "vuln.score.requested.v1") {
          await this.queue.publish("vuln.events", "vuln.score.requested.v1", withReplayKey(env));
        } else {
          this.logger.warn(
            `dlq/retry: unknown or missing event type ${String(env?.type)}, message removed from DLQ without republish`
          );
        }
      });
      return { ok: true, queue, ...r };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  }
}


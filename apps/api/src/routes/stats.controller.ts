import { randomUUID } from "node:crypto";
import { Controller, Get, Logger, Post, Query } from "@nestjs/common";
import { llmEndpointRequiresApiKey, parseBduVendorProductPairs } from "@vuln-intel/shared";
import { DbService } from "../services/db.service.js";
import { QueueService } from "../services/queue.service.js";
import { IntegrationSettingsService } from "../services/integration-settings.service.js";

type VendorAgg = { vendor: string; count: number };
type ProductAgg = { vendor: string; product: string; count: number };

function vendorMergeKey(vendor: string): string {
  return vendor.trim().toLowerCase();
}

function mergeVendorCounts(rows: VendorAgg[], limit: number): VendorAgg[] {
  const map = new Map<string, { label: string; count: number }>();
  for (const row of rows) {
    const key = vendorMergeKey(row.vendor);
    if (!key || key === "—") continue;
    const cur = map.get(key);
    if (cur) cur.count += row.count;
    else map.set(key, { label: row.vendor.trim(), count: row.count });
  }
  return [...map.values()]
    .sort((a, b) => b.count - a.count)
    .slice(0, limit)
    .map((x) => ({ vendor: x.label, count: x.count }));
}

function mergeProductCounts(rows: ProductAgg[], limit: number): ProductAgg[] {
  const map = new Map<string, { vendor: string; product: string; count: number }>();
  for (const row of rows) {
    const vk = vendorMergeKey(row.vendor);
    const pk = row.product.trim().toLowerCase();
    if (!vk || pk === "—" || pk === "") continue;
    const key = `${vk}\0${pk}`;
    const cur = map.get(key);
    if (cur) cur.count += row.count;
    else {
      map.set(key, {
        vendor: row.vendor.trim(),
        product: row.product.trim(),
        count: row.count
      });
    }
  }
  return [...map.values()]
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

function aggregateBduVendorProduct(
  rows: Array<{ bdu_id: string; vendors: string | null; software_names: string | null }>
): { vendors: VendorAgg[]; products: ProductAgg[] } {
  const vendorCounts = new Map<string, { label: string; bduIds: Set<string> }>();
  const productCounts = new Map<
    string,
    { vendor: string; product: string; bduIds: Set<string> }
  >();

  for (const row of rows) {
    const pairs = parseBduVendorProductPairs(row.software_names, row.vendors);
    if (pairs.length === 0) {
      const fallback = (row.vendors ?? row.software_names ?? "").trim();
      if (fallback) {
        const key = vendorMergeKey(fallback);
        const cur = vendorCounts.get(key) ?? { label: fallback, bduIds: new Set() };
        cur.bduIds.add(row.bdu_id);
        vendorCounts.set(key, cur);
      }
      continue;
    }
    const seenVendor = new Set<string>();
    for (const p of pairs) {
      const vk = vendorMergeKey(p.vendor);
      if (vk && vk !== "—" && !seenVendor.has(vk)) {
        seenVendor.add(vk);
        const cur = vendorCounts.get(vk) ?? { label: p.vendor, bduIds: new Set() };
        cur.bduIds.add(row.bdu_id);
        vendorCounts.set(vk, cur);
      }
      const pk = p.product.trim().toLowerCase();
      if (pk && pk !== "—") {
        const pkKey = `${vk}\0${pk}`;
        let cur = productCounts.get(pkKey);
        if (!cur) {
          cur = { vendor: p.vendor, product: p.product, bduIds: new Set<string>() };
          productCounts.set(pkKey, cur);
        }
        cur.bduIds.add(row.bdu_id);
      }
    }
  }

  const vendors: VendorAgg[] = [...vendorCounts.values()].map((v) => ({
    vendor: v.label,
    count: v.bduIds.size
  }));
  const products: ProductAgg[] = [...productCounts.values()].map((p) => ({
    vendor: p.vendor,
    product: p.product,
    count: p.bduIds.size
  }));
  return { vendors, products };
}

@Controller("stats")
export class StatsController {
  private readonly logger = new Logger(StatsController.name);

  constructor(
    private readonly db: DbService,
    private readonly queue: QueueService,
    private readonly integration: IntegrationSettingsService
  ) {}

  @Get("summary")
  async summary() {
    const total = await this.db.query<{ n: string }>(`SELECT COUNT(*)::text AS n FROM cve`);
    const maxPublished = await this.db.query<{ ts: string | null }>(
      `SELECT to_char(MAX(published_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS ts FROM cve`
    );
    const lastHour = await this.db.query<{ n: string }>(
      `SELECT COUNT(*)::text AS n
         FROM cve
        WHERE COALESCE(
                published_at,
                (NULLIF(TRIM(BOTH FROM raw->>'published'), ''))::timestamptz
              ) IS NOT NULL
          AND COALESCE(
                published_at,
                (NULLIF(TRIM(BOTH FROM raw->>'published'), ''))::timestamptz
              ) >= now() - interval '24 hours'`
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
        WHERE action = 'nvd.watermark'
          AND COALESCE((metadata->>'processed')::int, 0) > 0`
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
    const totalBdu = await this.db.query<{ n: string }>(`SELECT COUNT(*)::text AS n FROM bdu_vuln`);
    const bduLast24h = await this.db.query<{ n: string }>(
      `SELECT COUNT(*)::text AS n
         FROM bdu_vuln
        WHERE publication_date ~ '^\\d{2}\\.\\d{2}\\.\\d{4}$'
          AND to_timestamp(publication_date, 'DD.MM.YYYY') >= now() - interval '24 hours'`
    );
    const bduLinks = await this.db.query<{ n: string }>(`SELECT COUNT(*)::text AS n FROM cve_bdu_link`);
    const maxBduPublication = await this.db.query<{ ts: string | null }>(
      `SELECT to_char(
                MAX(to_timestamp(publication_date, 'DD.MM.YYYY')) AT TIME ZONE 'UTC',
                'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
              ) AS ts
         FROM bdu_vuln
        WHERE publication_date ~ '^\\d{2}\\.\\d{2}\\.\\d{4}$'`
    );
    const lastBduIngest = await this.db.query<{ ts: string | null }>(
      `SELECT to_char(MAX(ts) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS ts
         FROM audit_log
        WHERE action = 'bdu.ingest'`
    );

    /** По умолчанию включено: обогащение по открытию CVE и POST /enrich. Явно `false` — только фон (ingest/очередь). */
    const allowManualEnrich = process.env.ALLOW_MANUAL_ENRICH !== "false";

    return {
      totalCves: Number(total.rows[0]?.n ?? 0),
      /** CVE с published в NVD за последние 24ч (не modified / не catch-up ingest). */
      cvesLastHourCount: Number(lastHour.rows[0]?.n ?? 0),
      cvesPublishedLast24hCount: Number(lastHour.rows[0]?.n ?? 0),
      kevCount: Number(kev.rows[0]?.n ?? 0),
      epssCount: Number(epss.rows[0]?.n ?? 0),
      cvssCount: Number(cvss.rows[0]?.n ?? 0),
      scoredCount: Number(scored.rows[0]?.n ?? 0),
      aiEnrichedCount: Number(aiEnriched.rows[0]?.n ?? 0),
      aiLastEnrichAt: lastAi.rows[0]?.ts ?? null,
      aiEnrichPerMinute: Number(aiLastMinute.rows[0]?.n ?? 0),
      maxPublishedAt: maxPublished.rows[0]?.ts ?? null,
      totalBduCount: Number(totalBdu.rows[0]?.n ?? 0),
      bduPublishedLast24hCount: Number(bduLast24h.rows[0]?.n ?? 0),
      cveBduLinkCount: Number(bduLinks.rows[0]?.n ?? 0),
      maxBduPublicationAt: maxBduPublication.rows[0]?.ts ?? null,
      freshness: {
        nvdWatermarkTs: lastNvd.rows[0]?.ts ?? null,
        epssIngestTs: lastEpss.rows[0]?.ts ?? null,
        kevIngestTs: lastKev.rows[0]?.ts ?? null,
        riskScoreComputedAt: lastScore.rows[0]?.ts ?? null,
        bduIngestTs: lastBduIngest.rows[0]?.ts ?? null
      },
      /** When false, POST /cves/:id/enrich is disabled (pipeline-only AI). */
      manualEnrichAllowed: allowManualEnrich
    };
  }

  /**
   * Top vendors/products: CVE (NVD/CPE) + БДУ ФСТЭК за окно publication.
   */
  @Get("vendors")
  async vendors(@Query("windowHours") windowHoursRaw?: string, @Query("limit") limitRaw?: string) {
    const windowHours = Math.max(1, Math.min(24 * 30, Number(windowHoursRaw ?? 24)));
    const limit = Math.max(3, Math.min(50, Number(limitRaw ?? 12)));

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

    const cveVendors: VendorAgg[] = vendorRows.rows.map((x) => ({
      vendor: x.vendor,
      count: Number(x.count)
    }));
    const cveProducts: ProductAgg[] = productRows.rows.map((x) => ({
      vendor: x.vendor,
      product: x.product,
      count: Number(x.count)
    }));

    const sampledBdu = await this.db.query<{ n: string }>(
      `SELECT COUNT(*)::text AS n
         FROM bdu_vuln b
        WHERE b.publication_date ~ '^\\d{2}\\.\\d{2}\\.\\d{4}$'
          AND to_timestamp(b.publication_date, 'DD.MM.YYYY') >= now() - ($1::text || ' hours')::interval`,
      [String(windowHours)]
    );

    const bduRows = await this.db.query<{
      bdu_id: string;
      vendors: string | null;
      software_names: string | null;
    }>(
      `SELECT bdu_id, vendors, software_names
         FROM bdu_vuln b
        WHERE b.publication_date ~ '^\\d{2}\\.\\d{2}\\.\\d{4}$'
          AND to_timestamp(b.publication_date, 'DD.MM.YYYY') >= now() - ($1::text || ' hours')::interval`,
      [String(windowHours)]
    );

    const bduAgg = aggregateBduVendorProduct(bduRows.rows);
    const vendors = mergeVendorCounts([...cveVendors, ...bduAgg.vendors], limit);
    const products = mergeProductCounts([...cveProducts, ...bduAgg.products], limit);

    const sampledBduN = Number(sampledBdu.rows[0]?.n ?? 0);
    const sampledCvesN = Number(sampled.rows[0]?.n ?? 0);

    return {
      windowHours,
      sampledCves: sampledCvesN,
      sampledBdu: sampledBduN,
      sampledTotal: sampledCvesN + sampledBduN,
      method: "cve_cpe+bdu_fstec",
      usedCpe: Number(used.rows[0]?.used_cpe ?? 0),
      usedFallback: Number(used.rows[0]?.used_fallback ?? 0),
      usedBdu: bduRows.rowCount ?? 0,
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

      const [llm, nvd, bdu] = await Promise.all([
        (async () => {
        const cfg = await this.integration.getEffectiveLlmConfig();
        const requiresApiKey = llmEndpointRequiresApiKey(cfg.endpoint);
        const hasApiKey = Boolean(cfg.apiKey?.length);
        const authReady = !requiresApiKey || hasApiKey;
        const authHint = authReady
          ? null
          : "Для этого LLM endpoint нужен API-ключ (LLM_API_KEY / XAI_API_KEY / DASHSCOPE_API_KEY) или Ollama без ключа: LLM_ENDPOINT=http://<ollama-host>:11434/v1/chat/completions (например LAN 192.168.x.x)";

        const endpointRaw = cfg.endpoint?.trim() || "";
        const model = cfg.model || null;
        if (!endpointRaw) {
          return {
            configured: false,
            ok: false,
            endpoint: null,
            model,
            ms: 0,
            error: "LLM endpoint is empty",
            requiresApiKey,
            hasApiKey,
            authReady: false,
            authHint
          };
        }
        const endpoint = endpointRaw;
        const started = Date.now();
        const ac = new AbortController();
        const timeoutMs = Math.max(800, Math.min(10_000, Number(process.env.LLM_HEALTH_TIMEOUT_MS ?? 2500)));
        const t = setTimeout(() => ac.abort(), timeoutMs);
        try {
          // Prefer root for Ollama (cheap), fallback to OpenAI-compatible models list.
          const url = endpoint.includes("/v1/") ? endpoint.replace(/\/v1\/.*$/i, "/") : endpoint;
          const res = await fetch(url, { method: "GET", signal: ac.signal });
          const ms = Date.now() - started;
          const ok = res.ok;
          return {
            configured: true,
            ok,
            endpoint,
            model,
            ms,
            status: res.status,
            requiresApiKey,
            hasApiKey,
            authReady,
            authHint
          };
        } catch (e) {
          const ms = Date.now() - started;
          return {
            configured: true,
            ok: false,
            endpoint,
            model,
            ms,
            error: e instanceof Error ? e.message : String(e),
            requiresApiKey,
            hasApiKey,
            authReady,
            authHint
          };
        } finally {
          clearTimeout(t);
        }
      })(),
        this.integration.probeNvdHealth(),
        this.integration.probeBduHealth()
      ]);

      return {
        ok: true,
        checkedAt: new Date().toISOString(),
        queues: { enrich, score, dlqEnrich, dlqScore },
        llm,
        nvd,
        bdu
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


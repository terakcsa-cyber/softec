import { randomUUID } from "node:crypto";
import { Controller, ForbiddenException, Get, Logger, Post, Query } from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import {
  UserRole,
  getTextEngineSettingsFromEnv,
  isAdminUser,
  isAiScoreEnabled,
  shouldEnrichViaQueue,
  shouldScoreViaQueue,
  llmEndpointRequiresApiKey,
  parseBduVendorProductPairs,
  parseUserRole,
  QueueEventType,
  SQL_EFFECTIVE_PUBLISHED_AT,
  sqlBduFstecAttentionWithinHours
} from "@vuln-intel/shared";
import { DbService } from "../services/db.service.js";
import { QueueService } from "../services/queue.service.js";
import { IntegrationSettingsService } from "../services/integration-settings.service.js";
import { ThreatFeedService } from "../services/threat-feed.service.js";
import { ThreatDigestPdfService } from "../services/threat-digest-pdf.service.js";
import { ThreatIntelRefreshService } from "../services/threat-intel-refresh.service.js";
import { ReconciliationService } from "../services/reconciliation.service.js";
import { OpsRepairService } from "../services/ops-repair.service.js";
import { TelegramPostService } from "../services/telegram-post.service.js";
import { CveEnrichRunnerService } from "../services/cve-enrich-runner.service.js";
import { CurrentUser } from "../auth/current-user.decorator.js";
import { Roles } from "../auth/roles.decorator.js";
import type { AuthUser } from "../auth/jwt.strategy.js";

type VendorAgg = { vendor: string; count: number };
type ProductAgg = { vendor: string; product: string; count: number };

type LlmHealth = {
  configured: boolean;
  ok: boolean;
  endpoint: string | null;
  model: string | null;
  ms: number;
  status?: number;
  error?: string | null;
  requiresApiKey: boolean;
  hasApiKey: boolean;
  authReady: boolean;
  authHint: string | null;
  cached?: boolean;
  checkedAt?: string;
};

let llmHealthCache: { key: string; ts: number; value: LlmHealth } | null = null;

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
    private readonly integration: IntegrationSettingsService,
    private readonly threatFeedSvc: ThreatFeedService,
    private readonly threatDigestPdf: ThreatDigestPdfService,
    private readonly threatIntelRefresh: ThreatIntelRefreshService,
    private readonly reconciliation: ReconciliationService,
    private readonly opsRepair: OpsRepairService,
    private readonly telegram: TelegramPostService,
    private readonly cveEnrichRunner: CveEnrichRunnerService
  ) {}

  private isAdmin(user: AuthUser): boolean {
    return isAdminUser({
      userId: user.userId,
      email: user.email,
      role: user.role,
      adminEmailsEnv: process.env.ADMIN_EMAILS
    });
  }

  private requireAdmin(user: AuthUser) {
    if (!this.isAdmin(user)) throw new ForbiddenException("admin only");
  }

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
    /** Hot 24h “актуальные”: denominator = published last 24h; AI = has non-placeholder enrichment. */
    const hot24Coverage = await this.db.query<{
      hot_total: string;
      hot_ai: string;
      hot_scored: string;
      hot_epss: string;
      hot_cvss: string;
    }>(
      `SELECT
         COUNT(*)::text AS hot_total,
         COUNT(*) FILTER (
           WHERE EXISTS (
             SELECT 1
               FROM enrichment_ai e
              WHERE e.cve_id = c.cve_id
                AND e.output_text IS DISTINCT FROM 'LLM not configured.'
                AND COALESCE(e.output_json->>'summary', '') NOT LIKE 'LLM not configured%'
                AND NOT (e.output_json @> '{"_enrich_error": true}'::jsonb)
           )
         )::text AS hot_ai,
         COUNT(*) FILTER (
           WHERE EXISTS (SELECT 1 FROM risk_score rs WHERE rs.cve_id = c.cve_id)
         )::text AS hot_scored,
         COUNT(*) FILTER (
           WHERE EXISTS (SELECT 1 FROM epss_score es WHERE es.cve_id = c.cve_id)
         )::text AS hot_epss,
         COUNT(*) FILTER (WHERE c.cvss_base IS NOT NULL)::text AS hot_cvss
         FROM cve c
        WHERE ${SQL_EFFECTIVE_PUBLISHED_AT} IS NOT NULL
          AND ${SQL_EFFECTIVE_PUBLISHED_AT} >= now() - interval '24 hours'`
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
        WHERE action IN (
          'nvd.watermark', 'nvd.pub_sync', 'nvd.pub_catchup',
          'nvd.catalog_backfill', 'nvd.catalog_complete'
        )`
    );
    const lastEpss = await this.db.query<{ ts: string | null }>(
      `SELECT to_char(MAX(ts) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS ts
         FROM audit_log
        WHERE action IN ('epss.ingest', 'epss.watermark')`
    );
    const lastKev = await this.db.query<{ ts: string | null }>(
      `SELECT to_char(MAX(ts) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS ts
         FROM audit_log
        WHERE action IN ('kev.ingest', 'vulncheck.kev.ingest')`
    );
    const lastScore = await this.db.query<{ ts: string | null }>(
      `SELECT to_char(MAX(computed_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS ts
         FROM risk_score`
    );
    const totalBdu = await this.db.query<{ n: string }>(`SELECT COUNT(*)::text AS n FROM bdu_vuln`);
    const bduAttentionHours = Math.max(
      1,
      Math.min(168, Number(process.env.BDU_ATTENTION_WINDOW_HOURS ?? 24))
    );
    const bduLast24h = await this.db.query<{ n: string }>(
      `SELECT COUNT(*)::text AS n
         FROM bdu_vuln b
        WHERE ${sqlBduFstecAttentionWithinHours("b", bduAttentionHours)}`
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
      /** Primary “актуальность”: CVE published in last 24h. */
      hot24CveCount: Number(hot24Coverage.rows[0]?.hot_total ?? 0),
      hot24AiEnrichedCount: Number(hot24Coverage.rows[0]?.hot_ai ?? 0),
      hot24ScoredCount: Number(hot24Coverage.rows[0]?.hot_scored ?? 0),
      hot24EpssCount: Number(hot24Coverage.rows[0]?.hot_epss ?? 0),
      hot24CvssCount: Number(hot24Coverage.rows[0]?.hot_cvss ?? 0),
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

  /** Компактные KPI для виджета «Exploit radar» на дашборде. */
  @Get("exploit-radar")
  async exploitRadar() {
    const r = await this.db.query<{
      vckev_only: string;
      epss_spikes: string;
      new_vckev_7d: string;
      with_poc: string;
      with_public_exploit: string;
      intel_rows: string;
      last_vckev_ingest: string | null;
    }>(
      `SELECT
         (SELECT count(*)::text FROM cve_exploit_intel WHERE vckev_only) AS vckev_only,
         (SELECT count(*)::text FROM cve_exploit_intel WHERE epss_spike) AS epss_spikes,
         (SELECT count(*)::text FROM vulncheck_kev WHERE date_added >= now() - interval '7 days') AS new_vckev_7d,
         (SELECT count(*)::text FROM cve_exploit_intel WHERE has_poc) AS with_poc,
         (SELECT count(*)::text FROM cve_exploit_intel WHERE has_public_exploit) AS with_public_exploit,
         (SELECT count(*)::text FROM cve_exploit_intel) AS intel_rows,
         (SELECT to_char(MAX(ts) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
            FROM audit_log WHERE action = 'vulncheck.kev.ingest') AS last_vckev_ingest`
    );
    const row = r.rows[0];
    const highlightsR = await this.db.query<{
      cve_id: string;
      epss: number | null;
      cvss_base: number | null;
      vckev_only: boolean;
      epss_spike: boolean;
      has_poc: boolean;
      has_public_exploit: boolean;
      radar_reason: string;
    }>(
      `SELECT c.cve_id,
              es.score AS epss,
              c.cvss_base,
              ei.vckev_only,
              ei.epss_spike,
              ei.has_poc,
              ei.has_public_exploit,
              CASE
                WHEN ei.vckev_only THEN 'vckev_only'
                WHEN ei.epss_spike THEN 'epss_spike'
                WHEN ei.has_public_exploit THEN 'has_public_exploit'
                WHEN ei.has_poc THEN 'has_poc'
                ELSE 'other'
              END AS radar_reason
         FROM cve_exploit_intel ei
         JOIN cve c ON c.cve_id = ei.cve_id
    LEFT JOIN epss_score es ON es.cve_id = c.cve_id
        WHERE ei.vckev_only OR ei.epss_spike OR ei.has_public_exploit OR ei.has_poc
        ORDER BY ei.vckev_only DESC,
                 ei.epss_spike DESC,
                 ei.has_public_exploit DESC,
                 COALESCE(es.score, 0) DESC,
                 c.published_at DESC NULLS LAST
        LIMIT 10`
    );
    return {
      vckevOnly: Number(row?.vckev_only ?? 0),
      epssSpikes: Number(row?.epss_spikes ?? 0),
      newVckev7d: Number(row?.new_vckev_7d ?? 0),
      withPoc: Number(row?.with_poc ?? 0),
      withPublicExploit: Number(row?.with_public_exploit ?? 0),
      intelRows: Number(row?.intel_rows ?? 0),
      lastVckevIngestAt: row?.last_vckev_ingest ?? null,
      highlights: highlightsR.rows
    };
  }

  /** Синхронизация VulnCheck + пересчёт exploit intel (старт TI / ручной refresh). */
  @Roles(UserRole.Admin)
  @Post("threat-feed/refresh")
  async threatFeedRefresh(@Query("force") forceRaw?: string) {
    const force = forceRaw === "1" || forceRaw === "true";
    return this.threatIntelRefresh.refresh({ reason: "ti_open", force });
  }

  @Get("threat-feed/refresh/status")
  threatFeedRefreshStatus() {
    return this.threatIntelRefresh.getStatus();
  }

  /** Лента exploit-сигналов для модуля Threat. */
  @Get("threat-feed")
  async threatFeed(
    @Query("limit") limitRaw?: string,
    @Query("offset") offsetRaw?: string,
    @Query("windowHours") windowHoursRaw?: string,
    @Query("signalType") signalTypeRaw?: string,
    @Query("sort") sortRaw?: string,
    @Query("newOnly") newOnlyRaw?: string,
    @Query("since") sinceRaw?: string,
    @Query("vendor") vendorRaw?: string | string[],
    @Query("watchlistOnly") watchlistOnlyRaw?: string
  ) {
    const limit = Math.max(1, Math.min(100, Number(limitRaw ?? 40)));
    const offset = Math.max(0, Number(offsetRaw ?? 0));
    const windowAll = windowHoursRaw === "all" || windowHoursRaw === "0";
    const windowHours = windowAll
      ? null
      : Math.max(1, Math.min(720, Number(windowHoursRaw ?? 168)));
    const signalType = signalTypeRaw?.trim() || null;
    const sort = (sortRaw ?? "threat").toLowerCase() === "recent" ? "recent" : "threat";
    const newOnly = newOnlyRaw === "1" || newOnlyRaw === "true";
    const watchlistOnly = watchlistOnlyRaw === "1" || watchlistOnlyRaw === "true";
    const since = sinceRaw?.trim() ? new Date(sinceRaw.trim()) : null;
    if (since != null && Number.isNaN(since.getTime())) {
      return { error: "invalid since" };
    }
    const vendorKeys = (Array.isArray(vendorRaw) ? vendorRaw : vendorRaw ? [vendorRaw] : [])
      .flatMap((v) => String(v).split(","))
      .map((v) => v.trim().toLowerCase())
      .filter(Boolean);

    return this.threatFeedSvc.getFeed({
      limit,
      offset,
      windowHours,
      signalType,
      sort,
      newOnly,
      since: since && !Number.isNaN(since.getTime()) ? since : null,
      vendorKeys,
      watchlistOnly
    });
  }

  /** Отправить threat digest в Telegram. */
  @Roles(UserRole.Admin)
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  @Post("threat-digest/telegram")
  async threatDigestTelegram(@CurrentUser() user: AuthUser) {
    this.requireAdmin(user);
    const payload = await this.threatFeedSvc.collectDailyDigestPayload(20);
    const messages = await this.threatFeedSvc.buildDailyDigestMessages(20);
    const sent = await this.telegram.sendTelegramMessages(messages, { parseMode: "HTML" });
    if (!sent.ok) {
      return sent;
    }

    const pdf = await this.threatDigestPdf.build(payload);
    const pdfSent = await this.telegram.sendTelegramDocument({
      buffer: pdf.buffer,
      filename: pdf.filename,
      caption: `📊 <b>Суточный Threat Digest (PDF)</b> · ${payload.windowHours}ч · ${payload.hotCves.length} hot CVE`,
      parseMode: "HTML"
    });

    try {
      await this.db.query(
        `INSERT INTO audit_log (actor_type, action, metadata) VALUES ('user', 'telegram.threat_digest', $1::jsonb)`,
        [
          JSON.stringify({
            actorUserId: user.userId,
            actorEmail: user.email,
            ok: sent.ok && pdfSent.ok,
            parts: sent.sent,
            messageIds: sent.messageIds,
            pdfMessageId: pdfSent.messageId,
            pdfFilename: pdf.filename,
            pdfBytes: pdf.buffer.length,
            error: pdfSent.error ?? sent.error,
            chars: messages.reduce((a, m) => a + m.length, 0)
          })
        ]
      );
    } catch {
      // ignore audit failures
    }

    return {
      ok: sent.ok && pdfSent.ok,
      sent: sent.sent,
      messageIds: sent.messageIds,
      pdf: pdfSent,
      pdfFilename: pdf.filename
    };
  }

  /**
   * Подготовить дайджест: запустить LLM-обогащение CVE, которые попадут в суточный отчёт.
   * UI может показать прогресс и дождаться готовности перед отправкой PDF в Telegram.
   */
  @Roles(UserRole.Admin)
  @Throttle({ default: { limit: 3, ttl: 60_000 } })
  @Post("threat-digest/prepare")
  async threatDigestPrepare(
    @CurrentUser() user: AuthUser,
    @Query("hotLimit") hotLimitRaw?: string,
    @Query("windowHours") windowHoursRaw?: string
  ) {
    this.requireAdmin(user);
    // hotLimit — сколько hot CVE включить; windowHours зарезервирован (дайджест SQL = 24h).
    void windowHoursRaw;
    const hotLimit = Math.max(1, Math.min(100, Number(hotLimitRaw ?? 20)));
    const payload = await this.threatFeedSvc.collectDailyDigestPayload(hotLimit);
    const jobId = randomUUID();
    const cveIds = (payload.hotCves ?? []).map((c) => c.cve_id).filter(Boolean);
    const nowIso = new Date().toISOString();
    const textEngine = await this.integration.getTextEngineSettings();

    if (!cveIds.length) {
      return { ok: true, jobId, hotLimit, total: 0, enqueued: 0 };
    }

    if (textEngine.textEngine !== "llm" || !shouldEnrichViaQueue(textEngine.textEngine)) {
      let ready = 0;
      for (const cveId of cveIds) {
        const res = await this.cveEnrichRunner.enrichNow(cveId, { force: false, allowOutsideHotWindow: true });
        if (res) ready += 1;
      }
      try {
        await this.db.query(
          `INSERT INTO audit_log (actor_type, action, metadata) VALUES ('user', 'threat_digest.prepare', $1::jsonb)`,
          [
            JSON.stringify({
              actorUserId: user.userId,
              actorEmail: user.email,
              jobId,
              hotLimit,
              total: cveIds.length,
              enqueued: 0,
              ready,
              cveIds,
              textEngine: textEngine.textEngine,
              enrichViaQueue: shouldEnrichViaQueue(textEngine.textEngine),
              ts: nowIso
            })
          ]
        );
      } catch {
        // ignore audit failures
      }
      return { ok: true, jobId, hotLimit, total: cveIds.length, enqueued: 0, ready };
    }

    // Determine which CVEs already have a successful enrichment.
    const readyRows = await this.db.query<{ cve_id: string; ai_ready: boolean; raw: unknown; source: string }>(
      `SELECT c.cve_id,
              EXISTS (
                SELECT 1 FROM enrichment_ai ea
                 WHERE ea.cve_id = c.cve_id
                   AND (ea.output_json->>'_enrich_error') IS DISTINCT FROM 'true'
                   AND NOT (
                     COALESCE(ea.output_text, '') = 'LLM not configured.'
                     OR COALESCE(ea.output_json->>'summary', '') LIKE 'LLM not configured%'
                   )
              ) AS ai_ready,
              c.raw,
              c.source
         FROM cve c
        WHERE c.cve_id = ANY($1::text[])`,
      [cveIds]
    );
    const ready = new Set(readyRows.rows.filter((r) => r.ai_ready).map((r) => r.cve_id));

    let enqueued = 0;
    const dayBucket = nowIso.slice(0, 10);
    for (const row of readyRows.rows) {
      if (ready.has(row.cve_id)) continue;
      const idempotencyKey = `enrich:digest:${row.cve_id}:${dayBucket}`;
      const raw =
        row.raw != null && typeof row.raw === "object" && !Array.isArray(row.raw)
          ? (row.raw as Record<string, unknown>)
          : {};
      await this.queue.publish(
        "vuln.events",
        "vuln.enrich.requested.v1",
        {
          id: randomUUID(),
          type: QueueEventType.EnrichCveRequested,
          ts: nowIso,
          producer: { service: "api", version: "0.0.1" },
          idempotencyKey,
          payload: { cveId: row.cve_id, source: row.source ?? "other", raw }
        },
        { priority: 9 }
      );
      enqueued += 1;
    }

    try {
      await this.db.query(
        `INSERT INTO audit_log (actor_type, action, metadata) VALUES ('user', 'threat_digest.prepare', $1::jsonb)`,
        [
          JSON.stringify({
            actorUserId: user.userId,
            actorEmail: user.email,
            jobId,
            hotLimit,
            total: cveIds.length,
            enqueued,
            cveIds,
            ts: nowIso
          })
        ]
      );
    } catch {
      // ignore audit failures
    }

    return {
      ok: true,
      jobId,
      hotLimit,
      total: cveIds.length,
      enqueued
    };
  }

  @Get("threat-digest/prepare/status")
  async threatDigestPrepareStatus(@CurrentUser() user: AuthUser, @Query("jobId") jobIdRaw?: string) {
    const jobId = String(jobIdRaw ?? "").trim();
    if (!jobId) return { ok: false, error: "jobId required" };

    const job = await this.db.query<{ ts: Date; metadata: any }>(
      `SELECT ts, metadata
         FROM audit_log
        WHERE action = 'threat_digest.prepare'
          AND metadata->>'jobId' = $1
     ORDER BY ts DESC
        LIMIT 1`,
      [jobId]
    );
    const meta = job.rows[0]?.metadata ?? null;
    if (meta?.actorUserId && String(meta.actorUserId) !== String(user.userId) && !this.isAdmin(user)) {
      throw new ForbiddenException("Not your job");
    }
    const cveIds = Array.isArray(meta?.cveIds) ? (meta.cveIds as string[]).map(String) : [];
    const total = Number(meta?.total ?? cveIds.length ?? 0);
    const textEngine = typeof meta?.textEngine === "string" ? meta.textEngine : (await this.integration.getTextEngineSettings()).textEngine;
    if (textEngine !== "llm") {
      return { ok: true, jobId, total, done: total, pending: 0, completed: true, textEngine };
    }
    if (!cveIds.length) return { ok: true, jobId, total, done: 0, pending: 0, completed: true };

    const doneR = await this.db.query<{ n: string }>(
      `SELECT COUNT(*)::text AS n
         FROM cve c
        WHERE c.cve_id = ANY($1::text[])
          AND EXISTS (
            SELECT 1 FROM enrichment_ai ea
             WHERE ea.cve_id = c.cve_id
               AND (ea.output_json->>'_enrich_error') IS DISTINCT FROM 'true'
               AND NOT (
                 COALESCE(ea.output_text, '') = 'LLM not configured.'
                 OR COALESCE(ea.output_json->>'summary', '') LIKE 'LLM not configured%'
               )
          )`,
      [cveIds]
    );
    const done = Number(doneR.rows[0]?.n ?? "0");
    const pending = Math.max(0, total - done);
    return {
      ok: true,
      jobId,
      total,
      done,
      pending,
      completed: pending === 0
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

  @Get("reconciliation")
  async reconciliationStatus() {
    return this.reconciliation.reconcile();
  }

  @Get("readiness")
  async readinessStatus() {
    let queueDepths:
      | { enrich?: number; score?: number; dlqEnrich?: number; dlqScore?: number }
      | undefined;
    try {
      // DLQ only — ai.enrich backlog must not block product readiness
      const [dlqEnrich, dlqScore] = await Promise.all([
        this.queue.getQueueDepth("dlq.ai.enrich"),
        this.queue.getQueueDepth("dlq.ai.score")
      ]);
      queueDepths = {
        dlqEnrich: dlqEnrich.messages,
        dlqScore: dlqScore.messages
      };
    } catch {
      queueDepths = undefined;
    }
    const ops = this.opsRepair.getStatus();
    const ti = this.threatIntelRefresh.getStatus();
    const runningJobs: Array<{ kind: string; startedAt: string | null; expectedSeconds?: number }> = [];
    const expectedByKind: Record<string, number> = {
      epss: 180,
      bdu: 420,
      nvd_hot: 120,
      hot24_score: 90,
      threat_intel: 150
    };
    for (const [kind, job] of Object.entries(ops.jobs ?? {})) {
      const j = job as { running?: boolean; startedAt?: string | null };
      if (j?.running) {
        runningJobs.push({
          kind,
          startedAt: j.startedAt ?? null,
          expectedSeconds: expectedByKind[kind] ?? 180
        });
      }
    }
    if (ti.running) {
      runningJobs.push({
        kind: "threat_intel",
        startedAt: ti.startedAt ?? new Date().toISOString(),
        expectedSeconds: expectedByKind.threat_intel
      });
    }
    return this.reconciliation.readiness({
      queueDepths,
      jobsRunning: ops.anyRunning || ti.running,
      runningJobs
    });
  }

  @Get("ops/status")
  opsStatus() {
    return {
      ...this.opsRepair.getStatus(),
      threatIntel: this.threatIntelRefresh.getStatus()
    };
  }

  @Roles(UserRole.Admin)
  @Throttle({ default: { limit: 3, ttl: 60_000 } })
  @Post("ops/epss/sync")
  async opsEpssSync(@CurrentUser() user: AuthUser) {
    this.requireAdmin(user);
    return this.opsRepair.runEpss(user.email);
  }

  @Roles(UserRole.Admin)
  @Throttle({ default: { limit: 2, ttl: 120_000 } })
  @Post("ops/bdu/sync")
  async opsBduSync(@CurrentUser() user: AuthUser) {
    this.requireAdmin(user);
    return this.opsRepair.runBdu(user.email);
  }

  @Roles(UserRole.Admin)
  @Throttle({ default: { limit: 3, ttl: 120_000 } })
  @Post("ops/nvd/hot-sync")
  async opsNvdHotSync(@CurrentUser() user: AuthUser) {
    this.requireAdmin(user);
    return this.opsRepair.runNvdHot(user.email);
  }

  @Roles(UserRole.Admin)
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  @Post("ops/hot24/rescore")
  async opsHot24Rescore(@CurrentUser() user: AuthUser) {
    this.requireAdmin(user);
    return this.opsRepair.runHot24(user.email);
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

      const textEngine = getTextEngineSettingsFromEnv().textEngine;
      const scoreEnabled = isAiScoreEnabled();
      const scoreViaQueue = shouldScoreViaQueue();
      const enrichViaQueue = shouldEnrichViaQueue(textEngine);
      const scoreBacklogOn = scoreEnabled && process.env.BACKLOG_SCORE_SWEEP !== "false";
      const enrichBacklogOn =
        process.env.TEXT_ENGINE_BG_ENRICH !== "false" && process.env.BACKLOG_AI_SWEEP !== "false";

      const [llm, nvd, bdu, coverageRow] = await Promise.all([
        (async (): Promise<LlmHealth> => {
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

        const cacheTtlMs = Math.max(15_000, Math.min(10 * 60_000, Number(process.env.LLM_HEALTH_CACHE_MS ?? 120_000)));
        const cacheKey = `${endpoint}|${model ?? ""}|${hasApiKey ? "k" : "no-k"}`;
        if (llmHealthCache && llmHealthCache.key === cacheKey && Date.now() - llmHealthCache.ts < cacheTtlMs) {
          return { ...llmHealthCache.value, cached: true };
        }

        const started = Date.now();
        const ac = new AbortController();
        const defaultTimeoutMs = 12_000;
        const timeoutMs = Math.max(
          800,
          Math.min(30_000, Number(process.env.LLM_HEALTH_TIMEOUT_MS ?? defaultTimeoutMs))
        );
        const t = setTimeout(() => ac.abort(), timeoutMs);
        try {
          const headers: Record<string, string> = { accept: "application/json" };
          if (cfg.apiKey?.trim()) headers.Authorization = `Bearer ${cfg.apiKey.trim()}`;

          // For OpenAI-compatible chat endpoints, do a tiny POST. A plain GET often returns 404 (Gemini, OpenAI).
          const isChatCompletions = /\/chat\/completions\/?$/i.test(endpoint);
          // Ollama is commonly hosted on :11434 (localhost or LAN). Prefer a cheap GET to root.
          const isOllama = /(^|\/\/)[^/]+:11434(\/|$)/.test(endpoint);

          const res = isChatCompletions && model && !isOllama
            ? await fetch(endpoint, {
                method: "POST",
                headers: { "content-type": "application/json", ...headers },
                body: JSON.stringify({
                  model,
                  messages: [{ role: "user", content: "ping" }],
                  max_tokens: 2
                }),
                signal: ac.signal
              })
            : await fetch(
                // Prefer root for Ollama (cheap).
                endpoint.includes("/v1/") ? endpoint.replace(/\/v1\/.*$/i, "/") : endpoint,
                { method: "GET", headers, signal: ac.signal }
              );
          const ms = Date.now() - started;
          // Some providers (Gemini free tier, proxies) may respond with 429 even when endpoint+auth are correct.
          // Treat 429 as "reachable" but surface as warning.
          const ok = res.ok || res.status === 429;
          const error =
            res.status === 429
              ? "Rate limit (429). Endpoint доступен, но превышены лимиты. Подождите или снизьте частоту запросов."
              : undefined;
          const out: LlmHealth = {
            configured: true,
            ok,
            endpoint,
            model,
            ms,
            status: res.status,
            error,
            requiresApiKey,
            hasApiKey,
            authReady,
            authHint,
            checkedAt: new Date().toISOString()
          };
          llmHealthCache = { key: cacheKey, ts: Date.now(), value: out };
          return out;
        } catch (e) {
          const ms = Date.now() - started;
          const out: LlmHealth = {
            configured: true,
            ok: false,
            endpoint,
            model,
            ms,
            error: e instanceof Error ? e.message : String(e),
            requiresApiKey,
            hasApiKey,
            authReady,
            authHint,
            checkedAt: new Date().toISOString()
          };
          llmHealthCache = { key: cacheKey, ts: Date.now(), value: out };
          return out;
        } finally {
          clearTimeout(t);
        }
      })(),
        this.integration.probeNvdHealth(),
        this.integration.probeBduHealth(),
        this.db.query<{
          total: string;
          scored: string;
          enriched: string;
          hot_total: string;
          hot_scored: string;
          hot_enriched: string;
          last_score: string | null;
          last_enrich: string | null;
        }>(
          `SELECT
             (SELECT COUNT(*)::text FROM cve) AS total,
             (SELECT COUNT(*)::text FROM risk_score) AS scored,
             (SELECT COUNT(DISTINCT cve_id)::text
                FROM enrichment_ai e
               WHERE e.output_text IS DISTINCT FROM 'LLM not configured.'
                 AND COALESCE(e.output_json->>'summary', '') NOT LIKE 'LLM not configured%'
                 AND NOT (e.output_json @> '{"_enrich_error": true}'::jsonb)
                 AND (
                   $1::text <> 'translate'
                   OR COALESCE(e.output_json->>'_display_source', '') IN ('translated', 'baseline_ru')
                   OR e.model = 'translate'
                   OR e.prompt_version = 'translate-v1'
                 )
             ) AS enriched,
             (SELECT COUNT(*)::text
                FROM cve c
               WHERE ${SQL_EFFECTIVE_PUBLISHED_AT} IS NOT NULL
                 AND ${SQL_EFFECTIVE_PUBLISHED_AT} >= now() - interval '24 hours'
             ) AS hot_total,
             (SELECT COUNT(*)::text
                FROM cve c
               WHERE ${SQL_EFFECTIVE_PUBLISHED_AT} IS NOT NULL
                 AND ${SQL_EFFECTIVE_PUBLISHED_AT} >= now() - interval '24 hours'
                 AND EXISTS (SELECT 1 FROM risk_score rs WHERE rs.cve_id = c.cve_id)
             ) AS hot_scored,
             (SELECT COUNT(*)::text
                FROM cve c
               WHERE ${SQL_EFFECTIVE_PUBLISHED_AT} IS NOT NULL
                 AND ${SQL_EFFECTIVE_PUBLISHED_AT} >= now() - interval '24 hours'
                 AND EXISTS (
                   SELECT 1
                     FROM enrichment_ai e
                    WHERE e.cve_id = c.cve_id
                      AND e.output_text IS DISTINCT FROM 'LLM not configured.'
                      AND COALESCE(e.output_json->>'summary', '') NOT LIKE 'LLM not configured%'
                      AND NOT (e.output_json @> '{"_enrich_error": true}'::jsonb)
                      AND (
                        $1::text <> 'translate'
                        OR COALESCE(e.output_json->>'_display_source', '') IN ('translated', 'baseline_ru')
                        OR e.model = 'translate'
                        OR e.prompt_version = 'translate-v1'
                      )
                 )
             ) AS hot_enriched,
             (SELECT to_char(MAX(computed_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
                FROM risk_score) AS last_score,
             (SELECT to_char(MAX(created_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
                FROM enrichment_ai) AS last_enrich`,
          [textEngine]
        )
      ]);

      const cov = coverageRow.rows[0];
      const totalCves = Number(cov?.total ?? 0);
      const scoredCount = Number(cov?.scored ?? 0);
      const enrichedCount = Number(cov?.enriched ?? 0);
      const hotTotal = Number(cov?.hot_total ?? 0);
      const hotScored = Number(cov?.hot_scored ?? 0);
      const hotEnriched = Number(cov?.hot_enriched ?? 0);
      const pct = (n: number, d: number) => (d > 0 ? Math.round((n / d) * 1000) / 10 : 0);

      return {
        ok: true,
        checkedAt: new Date().toISOString(),
        queues: { enrich, score, dlqEnrich, dlqScore },
        llm,
        nvd,
        bdu,
        coverage: {
          textEngine,
          scoreEnabled,
          scoreViaQueue,
          enrichViaQueue,
          scoreBacklogOn,
          enrichBacklogOn,
          totalCves,
          scoredCount,
          scoredMissing: Math.max(0, totalCves - scoredCount),
          scoredPct: pct(scoredCount, totalCves),
          enrichedCount,
          enrichedMissing: Math.max(0, totalCves - enrichedCount),
          enrichedPct: pct(enrichedCount, totalCves),
          hot24: {
            total: hotTotal,
            scored: hotScored,
            scoredMissing: Math.max(0, hotTotal - hotScored),
            scoredPct: pct(hotScored, hotTotal),
            enriched: hotEnriched,
            enrichedMissing: Math.max(0, hotTotal - hotEnriched),
            enrichedPct: pct(hotEnriched, hotTotal)
          },
          lastScoreAt: cov?.last_score ?? null,
          lastEnrichAt: cov?.last_enrich ?? null
        }
      };
    } catch (e) {
      return {
        ok: false,
        error: e instanceof Error ? e.message : String(e)
      };
    }
  }

  @Roles(UserRole.Admin)
  @Get("dlq/sample")
  async dlqSample(@CurrentUser() user: AuthUser, @Query("queue") queueRaw?: string, @Query("limit") limitRaw?: string) {
    this.requireAdmin(user);
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

  @Roles(UserRole.Admin)
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  @Post("dlq/clear")
  async dlqClear(@CurrentUser() user: AuthUser, @Query("queue") queueRaw?: string, @Query("limit") limitRaw?: string) {
    this.requireAdmin(user);
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

  @Roles(UserRole.Admin)
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  @Post("dlq/retry")
  async dlqRetry(@CurrentUser() user: AuthUser, @Query("queue") queueRaw?: string, @Query("limit") limitRaw?: string) {
    this.requireAdmin(user);
    const queue = String(queueRaw ?? "");
    if (queue !== "dlq.ai.enrich" && queue !== "dlq.ai.score") {
      return { ok: false, error: "Invalid queue (expected dlq.ai.enrich or dlq.ai.score)" };
    }
    if (queue === "dlq.ai.score" && (!isAiScoreEnabled() || !shouldScoreViaQueue())) {
      return {
        ok: false,
        error:
          "score DLQ retry needs AI_SCORE_ENABLED=true and AI_SCORE_VIA_QUEUE=true (default scoring is inline — purge dlq.ai.score instead)"
      };
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


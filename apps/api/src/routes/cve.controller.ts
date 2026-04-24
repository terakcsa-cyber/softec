import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  NotFoundException,
  Param,
  Post,
  Query
} from "@nestjs/common";
import { isLlmEnrichFailureRow, isLlmNotConfiguredEnrichment } from "@vuln-intel/shared";
import { CveEnrichRunnerService } from "../services/cve-enrich-runner.service.js";
import { DbService } from "../services/db.service.js";

type EnrichmentAiQueryRow = {
  model?: string;
  prompt_version?: string;
  output_json: unknown;
  output_text: string | null;
  created_at?: Date;
};

/** jsonb обычно объект; на всякий случай разворачиваем двойную сериализацию. */
function normalizeEnrichmentOutputJson<T extends { output_json: unknown }>(row: T): T {
  let oj = row.output_json;
  if (typeof oj === "string") {
    try {
      oj = JSON.parse(oj) as unknown;
    } catch {
      return row;
    }
  }
  return { ...row, output_json: oj };
}

const ENRICHMENT_AI_RECENT_LIMIT = 20;

/**
 * Для GET: не показывать свежую строку ошибки (_enrich_error), если среди последних строк
 * уже есть успешное обогащение (ручной API мог записать фейл после парсинга, воркер — успех с 200).
 */
function pickAiPayloadForGet(rows: EnrichmentAiQueryRow[]): EnrichmentAiQueryRow | null {
  if (!rows.length) return null;
  const normalized = rows.map(normalizeEnrichmentOutputJson);
  const successes = normalized.filter(
    (r) => !isLlmNotConfiguredEnrichment(r) && !isLlmEnrichFailureRow(r)
  );
  if (successes.length > 0) return successes[0] ?? null;
  const hit = normalized.find((r) => !isLlmNotConfiguredEnrichment(r));
  return hit ?? null;
}

/** Для POST /enrich без force: считаем кэшем любую успешную строку среди последних, не только самую свежую по времени. */
function pickRowForEnrichCacheHit(rows: EnrichmentAiQueryRow[]): EnrichmentAiQueryRow | null {
  if (!rows.length) return null;
  const normalized = rows.map(normalizeEnrichmentOutputJson);
  return (
    normalized.find(
      (r) => !isLlmNotConfiguredEnrichment(r) && !isLlmEnrichFailureRow(r)
    ) ?? null
  );
}

/** Экранирование для `LIKE ... ESCAPE '\\'` (совпадает с литеральным `strpos` по `%`, `_`, `\`). */
function escapePgLikePattern(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_");
}

@Controller("cves")
export class CveController {
  constructor(
    private readonly db: DbService,
    private readonly enrichRunner: CveEnrichRunnerService
  ) {}

  private buildCveLinks(cveId: string) {
    const id = String(cveId ?? "").trim();
    const nvd = id ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}` : null;
    // CISA KEV is a catalog; per-CVE deep links are not stable, so we keep a searchable entry point.
    const kev = id
      ? `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search=${encodeURIComponent(id)}`
      : `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`;
    const epss = id
      ? `https://www.first.org/epss/scorecard/${encodeURIComponent(id)}`
      : `https://www.first.org/epss/`;
    return {
      nvd,
      kev,
      epss
    };
  }

  @Get()
  async list(
    @Query("q") q?: string,
    @Query("limit") limitRaw?: string,
    @Query("view") viewRaw?: string,
    @Query("sort") sortRaw?: string,
    @Query("minCvss") minCvssRaw?: string,
    @Query("minEpss") minEpssRaw?: string,
    @Query("kevOnly") kevOnlyRaw?: string,
    @Query("vendor") vendorRaw?: string,
    @Query("product") productRaw?: string
  ) {
    const limit = Math.max(1, Math.min(200, Number(limitRaw ?? 50)));
    const view = (viewRaw ?? "latest").toLowerCase();
    const sort = (sortRaw ?? (view === "critical" ? "rank" : "fresh")).toLowerCase();
    const minCvss = minCvssRaw != null ? Number(minCvssRaw) : undefined;
    const minEpss = minEpssRaw != null ? Number(minEpssRaw) : undefined;
    const kevOnly = kevOnlyRaw === "1" || kevOnlyRaw === "true";
    const vendor = vendorRaw?.trim() ? vendorRaw.trim().toLowerCase() : null;
    const product = productRaw?.trim() ? productRaw.trim().toLowerCase() : null;

    const rankExpr = `(COALESCE(c.cvss_base, 0) * 0.7 + COALESCE(es.score, 0) * 10 * 0.3)`;
    // Critical v2: deterministic ordering, no "empty" records.
    // - KEV always included and always ranked first
    // - EPSS >= 0.2 or CVSS >= 8.0 included (configurable via query thresholds)
    // - Deterministic tiebreakers: published_at desc, cve_id asc
    const criticalV2OrderBy = `ORDER BY (k.cve_id IS NOT NULL) DESC,
                                      GREATEST(COALESCE(es.score, 0) * 100, COALESCE(c.cvss_base, 0) * 10) DESC,
                                      c.published_at DESC NULLS LAST,
                                      c.cve_id ASC`;
    const orderBy = (() => {
      if (sort === "risk") return `ORDER BY rs.score DESC NULLS LAST, c.published_at DESC NULLS LAST`;
      if (sort === "epss") return `ORDER BY es.score DESC NULLS LAST, c.published_at DESC NULLS LAST`;
      if (sort === "cvss") return `ORDER BY c.cvss_base DESC NULLS LAST, c.published_at DESC NULLS LAST`;
      if (sort === "rank")
        return `ORDER BY (k.cve_id IS NOT NULL) DESC, ${rankExpr} DESC, c.published_at DESC NULLS LAST`;
      return `ORDER BY c.published_at DESC NULLS LAST`;
    })();

    const filters: string[] = [];
    const params: any[] = [];
    const add = (cond: string, value?: any) => {
      if (value === undefined) return;
      params.push(value);
      filters.push(cond.replace(/\$(\d+)/g, () => `$${params.length}`));
    };

    if (kevOnly) filters.push(`k.cve_id IS NOT NULL`);
    if (Number.isFinite(minCvss)) add(`c.cvss_base >= $1`, minCvss);
    if (Number.isFinite(minEpss)) add(`es.score >= $1`, minEpss);

    if (view === "kev") filters.push(`k.cve_id IS NOT NULL`);
    if (view === "last24h" || view === "last_24h" || view === "last-24h") {
      // "New" vulnerabilities by publish time (fast triage view).
      filters.push(`c.published_at >= now() - interval '24 hours'`);
    }
    if (view === "critical") {
      filters.push(
        `(k.cve_id IS NOT NULL OR c.cvss_base >= 9.0 OR es.score >= 0.5) AND (k.cve_id IS NOT NULL OR c.cvss_base IS NOT NULL OR es.score IS NOT NULL)`
      );
    }
    if (view === "critical_v2" || view === "critical-v2" || view === "criticalv2") {
      // Default thresholds: epss >= 0.2 OR cvss >= 8.0 OR KEV
      // Also allow overriding via minCvss/minEpss/kevOnly query params.
      const epssMin = Number.isFinite(minEpss) ? (minEpss as number) : 0.2;
      const cvssMin = Number.isFinite(minCvss) ? (minCvss as number) : 8.0;
      params.push(epssMin);
      const epssIdx = params.length;
      params.push(cvssMin);
      const cvssIdx = params.length;
      filters.push(
        `((k.cve_id IS NOT NULL) OR (es.score IS NOT NULL AND es.score >= $${epssIdx}) OR (c.cvss_base IS NOT NULL AND c.cvss_base >= $${cvssIdx}))`
      );
    }

    const vendorJoin = vendor || product ? `JOIN cve_vendor_product vp ON vp.cve_id = c.cve_id` : ``;
    if (vendor) {
      params.push(vendor);
      const vIdx = params.length;
      filters.push(`vp.vendor_key = $${vIdx}`);
    }
    if (product) {
      params.push(product);
      const pIdx = params.length;
      filters.push(`vp.product_key_norm = $${pIdx}`);
    }

    if (q && q.trim().length > 0) {
      const qTrim = q.trim();
      const qLower = qTrim.toLowerCase();
      const isExactCveQuery = /^cve-\d{4}-\d{4,}$/i.test(qTrim);
      /** Подстрока: `LIKE` + ESCAPE, чтобы работали GIN (pg_trgm); литералы как у `strpos`. */
      const needleLike = escapePgLikePattern(qLower);
      params.push(needleLike);
      const needleIdx = params.length;
      const exactCond = `lower(c.cve_id) = $${needleIdx}::text`;
      const likeSuffix = `LIKE '%' || $${needleIdx}::text || '%' ESCAPE E'\\\\'`;
      const contextMatch = `(
        lower(c.cve_id) ${likeSuffix}
        OR lower(c.raw::text) ${likeSuffix}
        OR EXISTS (
          SELECT 1 FROM cve_vendor_product vp_q
          WHERE vp_q.cve_id = c.cve_id
            AND (
              lower(vp_q.vendor) ${likeSuffix}
              OR lower(COALESCE(vp_q.product, '')) ${likeSuffix}
              OR lower(vp_q.vendor_key) ${likeSuffix}
              OR lower(vp_q.product_key_norm) ${likeSuffix}
            )
        )
        OR EXISTS (
          SELECT 1 FROM enrichment_ai ea_q
          WHERE ea_q.cve_id = c.cve_id
            AND (
              lower(COALESCE(ea_q.output_text, '')) ${likeSuffix}
              OR lower(ea_q.output_json::text) ${likeSuffix}
            )
        )
      )`;
      const whereFiltered = [contextMatch, ...filters].join(" AND ");

      // Search ordering: exact CVE hit first, then similarity to CVE id, then fallback order.
      const searchOrderBy =
        `ORDER BY exact_match DESC,\n` +
        `         cve_sim DESC NULLS LAST,\n` +
        `         (exploit_known) DESC,\n` +
        `         ${rankExpr} DESC,\n` +
        `         published_at DESC NULLS LAST,\n` +
        `         cve_id ASC`;

      params.push(limit);
      const limitIdx = params.length;

      const baseSelect = `SELECT c.cve_id, c.published_at, c.modified_at,
                rs.score AS risk_score,
                es.score AS epss,
                c.cvss_base AS cvss_base,
                vp1.vendor AS vp_vendor,
                vp1.product AS vp_product,
                NULLIF(substring(regexp_replace(COALESCE(
                  c.raw->'descriptions'->0->>'value',
                  c.raw->'cve'->'descriptions'->0->>'value',
                  c.raw->'cve'->'description'->'description_data'->0->>'value',
                  c.raw->'description'->'description_data'->0->>'value',
                  ''
                ), E'\\s+', ' ', 'g') for 220), '') AS short_description,
                NULLIF(substring(regexp_replace(COALESCE(
                  ea1.output_json->>'title',
                  ea1.output_json->>'summary',
                  ea1.output_text,
                  ''
                ), E'\\s+', ' ', 'g') for 220), '') AS short_ru,
                COALESCE((
                  SELECT count(*)::int FROM vuln_task_cve l
                  JOIN vuln_task t ON t.id = l.task_id
                  WHERE l.cve_id = c.cve_id AND t.status NOT IN ('closed','not_applicable')
                ), 0) AS task_open_count,
                (COALESCE(
                  c.raw->'metrics'->'cvssMetricV31'->0->'cvssData'->>'attackVector',
                  c.raw->'metrics'->'cvssMetricV30'->0->'cvssData'->>'attackVector',
                  c.raw->'impact'->'baseMetricV3'->'cvssV3'->>'attackVector'
                ) = 'NETWORK') AS cvss_av_network,
                (COALESCE(
                  c.raw->'metrics'->'cvssMetricV31'->0->'cvssData'->>'privilegesRequired',
                  c.raw->'metrics'->'cvssMetricV30'->0->'cvssData'->>'privilegesRequired',
                  c.raw->'impact'->'baseMetricV3'->'cvssV3'->>'privilegesRequired'
                ) = 'NONE') AS cvss_pr_none,
                (COALESCE(
                  c.raw->'metrics'->'cvssMetricV31'->0->'cvssData'->>'userInteraction',
                  c.raw->'metrics'->'cvssMetricV30'->0->'cvssData'->>'userInteraction',
                  c.raw->'impact'->'baseMetricV3'->'cvssV3'->>'userInteraction'
                ) = 'NONE') AS cvss_ui_none,
                (COALESCE(
                  c.raw->'metrics'->'cvssMetricV31'->0->'cvssData'->>'attackComplexity',
                  c.raw->'metrics'->'cvssMetricV30'->0->'cvssData'->>'attackComplexity',
                  c.raw->'impact'->'baseMetricV3'->'cvssV3'->>'attackComplexity'
                ) = 'LOW') AS cvss_ac_low,
                EXISTS (
                  SELECT 1 FROM cve_vendor_product vp_p
                  WHERE vp_p.cve_id = c.cve_id
                    AND (
                      vp_p.vendor_key IN (
                        'microsoft','apache','nginx','openssl','openbsd','openssh','citrix','f5','paloaltonetworks',
                        'fortinet','checkpoint','juniper','cisco','vmware','okta','redhat','oracle','ibm','sap'
                      )
                      OR vp_p.product_key_norm IN (
                        'iis','http_server','nginx','openssl','openssh','netscaler','adc','big-ip','pan-os','fortios',
                        'fortigate','pulse_connect_secure','globalprotect','vpn','sslvpn','gateway','reverse_proxy',
                        'load_balancer','waf','firewall','identity','sso','keycloak','tomcat','jetty','spring'
                      )
                      OR lower(vp_p.product_key_norm) LIKE '%vpn%'
                      OR lower(vp_p.product_key_norm) LIKE '%proxy%'
                      OR lower(vp_p.product_key_norm) LIKE '%gateway%'
                    )
                ) AS perimeter_product,
                (k.cve_id IS NOT NULL) AS exploit_known,
                EXISTS (
                  SELECT 1 FROM enrichment_ai ea
                  WHERE ea.cve_id = c.cve_id
                    AND (ea.output_json->>'_enrich_error') IS DISTINCT FROM 'true'
                    AND NOT (
                      COALESCE(ea.output_text, '') = 'LLM not configured.'
                      OR COALESCE(ea.output_json->>'summary', '') LIKE 'LLM not configured%'
                    )
                ) AS ai_ready,
                ARRAY_REMOVE(ARRAY[
                  CASE WHEN k.cve_id IS NOT NULL THEN 'KEV' ELSE NULL END,
                  CASE WHEN es.score IS NOT NULL AND es.score >= 0.5 THEN 'EPSS>=0.50' ELSE NULL END,
                  CASE WHEN es.score IS NOT NULL AND es.score >= 0.2 AND es.score < 0.5 THEN 'EPSS>=0.20' ELSE NULL END,
                  CASE WHEN c.cvss_base IS NOT NULL AND c.cvss_base >= 9.0 THEN 'CVSS>=9.0' ELSE NULL END,
                  CASE WHEN c.cvss_base IS NOT NULL AND c.cvss_base >= 8.0 AND c.cvss_base < 9.0 THEN 'CVSS>=8.0' ELSE NULL END
                ], NULL) AS critical_reasons,
                (${exactCond}) AS exact_match,
                similarity(lower(c.cve_id), $${needleIdx}::text) AS cve_sim
           FROM cve c
      ${vendorJoin}
      LEFT JOIN LATERAL (
        SELECT vp.vendor, vp.product
          FROM cve_vendor_product vp
         WHERE vp.cve_id = c.cve_id
      ORDER BY vp.vendor_key ASC, vp.product_key_norm ASC
         LIMIT 1
      ) vp1 ON TRUE
      LEFT JOIN LATERAL (
        SELECT ea.output_json, ea.output_text
          FROM enrichment_ai ea
         WHERE ea.cve_id = c.cve_id
           AND (ea.output_json->>'_enrich_error') IS DISTINCT FROM 'true'
           AND NOT (
             COALESCE(ea.output_text, '') = 'LLM not configured.'
             OR COALESCE(ea.output_json->>'summary', '') LIKE 'LLM not configured%'
           )
      ORDER BY ea.created_at DESC
         LIMIT 1
      ) ea1 ON TRUE
      LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
      LEFT JOIN epss_score es ON es.cve_id = c.cve_id
      LEFT JOIN kev k ON k.cve_id = c.cve_id`;

      const useUnionExact =
        isExactCveQuery &&
        // only needed when view filters could hide old records; harmless even without filters, but keeps query simpler
        (filters.length > 0 || view === "last24h" || view === "last_24h" || view === "last-24h");

      const sql = useUnionExact
        ? `WITH hits AS (
            ${baseSelect}
            WHERE ${exactCond}
            UNION ALL
            ${baseSelect}
            WHERE NOT (${exactCond}) AND ${whereFiltered}
          )
          SELECT cve_id, published_at, modified_at, risk_score, epss, cvss_base,
                 vp_vendor, vp_product, short_description, short_ru,
                 cvss_av_network, cvss_pr_none, cvss_ui_none, cvss_ac_low, perimeter_product,
                 exploit_known, ai_ready, critical_reasons
            FROM hits
           ${searchOrderBy}
           LIMIT $${limitIdx}`
        : `${baseSelect}
           WHERE ${whereFiltered}
           ${searchOrderBy}
           LIMIT $${limitIdx}`;

      const r = await this.db.query(sql, params);
      return { items: r.rows };
    }

    const where = filters.length > 0 ? `WHERE ${filters.join(" AND ")}` : `WHERE TRUE`;
    params.push(limit);
    const limitIdx = params.length;

    const r = await this.db.query(
      `SELECT c.cve_id, c.published_at, c.modified_at,
              rs.score AS risk_score,
              es.score AS epss,
              c.cvss_base AS cvss_base,
              vp1.vendor AS vp_vendor,
              vp1.product AS vp_product,
              NULLIF(substring(regexp_replace(COALESCE(
                c.raw->'descriptions'->0->>'value',
                c.raw->'cve'->'descriptions'->0->>'value',
                c.raw->'cve'->'description'->'description_data'->0->>'value',
                c.raw->'description'->'description_data'->0->>'value',
                ''
              ), E'\\s+', ' ', 'g') for 220), '') AS short_description,
              NULLIF(substring(regexp_replace(COALESCE(
                ea1.output_json->>'title',
                ea1.output_json->>'summary',
                ea1.output_text,
                ''
              ), E'\\s+', ' ', 'g') for 220), '') AS short_ru,
              COALESCE((
                SELECT count(*)::int FROM vuln_task_cve l
                JOIN vuln_task t ON t.id = l.task_id
                WHERE l.cve_id = c.cve_id AND t.status NOT IN ('closed','not_applicable')
              ), 0) AS task_open_count,
              (COALESCE(
                c.raw->'metrics'->'cvssMetricV31'->0->'cvssData'->>'attackVector',
                c.raw->'metrics'->'cvssMetricV30'->0->'cvssData'->>'attackVector',
                c.raw->'impact'->'baseMetricV3'->'cvssV3'->>'attackVector'
              ) = 'NETWORK') AS cvss_av_network,
              (COALESCE(
                c.raw->'metrics'->'cvssMetricV31'->0->'cvssData'->>'privilegesRequired',
                c.raw->'metrics'->'cvssMetricV30'->0->'cvssData'->>'privilegesRequired',
                c.raw->'impact'->'baseMetricV3'->'cvssV3'->>'privilegesRequired'
              ) = 'NONE') AS cvss_pr_none,
              (COALESCE(
                c.raw->'metrics'->'cvssMetricV31'->0->'cvssData'->>'userInteraction',
                c.raw->'metrics'->'cvssMetricV30'->0->'cvssData'->>'userInteraction',
                c.raw->'impact'->'baseMetricV3'->'cvssV3'->>'userInteraction'
              ) = 'NONE') AS cvss_ui_none,
              (COALESCE(
                c.raw->'metrics'->'cvssMetricV31'->0->'cvssData'->>'attackComplexity',
                c.raw->'metrics'->'cvssMetricV30'->0->'cvssData'->>'attackComplexity',
                c.raw->'impact'->'baseMetricV3'->'cvssV3'->>'attackComplexity'
              ) = 'LOW') AS cvss_ac_low,
              EXISTS (
                SELECT 1 FROM cve_vendor_product vp_p
                WHERE vp_p.cve_id = c.cve_id
                  AND (
                    vp_p.vendor_key IN (
                      'microsoft','apache','nginx','openssl','openbsd','openssh','citrix','f5','paloaltonetworks',
                      'fortinet','checkpoint','juniper','cisco','vmware','okta','redhat','oracle','ibm','sap'
                    )
                    OR vp_p.product_key_norm IN (
                      'iis','http_server','nginx','openssl','openssh','netscaler','adc','big-ip','pan-os','fortios',
                      'fortigate','pulse_connect_secure','globalprotect','vpn','sslvpn','gateway','reverse_proxy',
                      'load_balancer','waf','firewall','identity','sso','keycloak','tomcat','jetty','spring'
                    )
                    OR lower(vp_p.product_key_norm) LIKE '%vpn%'
                    OR lower(vp_p.product_key_norm) LIKE '%proxy%'
                    OR lower(vp_p.product_key_norm) LIKE '%gateway%'
                  )
              ) AS perimeter_product,
              (k.cve_id IS NOT NULL) AS exploit_known,
              EXISTS (
                SELECT 1 FROM enrichment_ai ea
                WHERE ea.cve_id = c.cve_id
                  AND (ea.output_json->>'_enrich_error') IS DISTINCT FROM 'true'
                  AND NOT (
                    COALESCE(ea.output_text, '') = 'LLM not configured.'
                    OR COALESCE(ea.output_json->>'summary', '') LIKE 'LLM not configured%'
                  )
              ) AS ai_ready,
              ARRAY_REMOVE(ARRAY[
                CASE WHEN k.cve_id IS NOT NULL THEN 'KEV' ELSE NULL END,
                CASE WHEN es.score IS NOT NULL AND es.score >= 0.5 THEN 'EPSS>=0.50' ELSE NULL END,
                CASE WHEN es.score IS NOT NULL AND es.score >= 0.2 AND es.score < 0.5 THEN 'EPSS>=0.20' ELSE NULL END,
                CASE WHEN c.cvss_base IS NOT NULL AND c.cvss_base >= 9.0 THEN 'CVSS>=9.0' ELSE NULL END,
                CASE WHEN c.cvss_base IS NOT NULL AND c.cvss_base >= 8.0 AND c.cvss_base < 9.0 THEN 'CVSS>=8.0' ELSE NULL END
              ], NULL) AS critical_reasons
         FROM cve c
   ${vendorJoin}
    LEFT JOIN LATERAL (
      SELECT vp.vendor, vp.product
        FROM cve_vendor_product vp
       WHERE vp.cve_id = c.cve_id
    ORDER BY vp.vendor_key ASC, vp.product_key_norm ASC
       LIMIT 1
    ) vp1 ON TRUE
    LEFT JOIN LATERAL (
      SELECT ea.output_json, ea.output_text
        FROM enrichment_ai ea
       WHERE ea.cve_id = c.cve_id
         AND (ea.output_json->>'_enrich_error') IS DISTINCT FROM 'true'
         AND NOT (
           COALESCE(ea.output_text, '') = 'LLM not configured.'
           OR COALESCE(ea.output_json->>'summary', '') LIKE 'LLM not configured%'
         )
    ORDER BY ea.created_at DESC
       LIMIT 1
    ) ea1 ON TRUE
    LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
    LEFT JOIN epss_score es ON es.cve_id = c.cve_id
    LEFT JOIN kev k ON k.cve_id = c.cve_id
     ${where}
     ${(view === "critical_v2" || view === "critical-v2" || view === "criticalv2") ? criticalV2OrderBy : orderBy}
        LIMIT $${limitIdx}`,
      params
    );
    return { items: r.rows };
  }

  /** Пакетная проверка: какие CVE из списка уже есть в `cve` (для ленты ФСТЭК и др.). */
  @Post("lookup")
  @HttpCode(200)
  async lookupCves(@Body() body: { cveIds?: unknown }) {
    const raw = body?.cveIds;
    const ids = Array.isArray(raw) ? raw : [];
    const normalized = [
      ...new Set(
        ids
          .map((id) => String(id).trim().toUpperCase())
          .filter((id) => /^CVE-\d{4}-\d+$/.test(id))
      )
    ];
    if (normalized.length > 400) normalized.length = 400;
    if (normalized.length === 0) return { present: [] as string[] };

    const r = await this.db.query<{ cve_id: string }>(
      `SELECT cve_id FROM cve WHERE cve_id = ANY($1::text[])`,
      [normalized]
    );
    return { present: r.rows.map((row) => row.cve_id) };
  }

  /** Queue AI enrichment for a CVE (intended when user opens the detail modal). Idempotent per CVE revision unless force=1. */
  @Post(":cveId/enrich")
  async requestEnrich(@Param("cveId") cveId: string, @Query("force") force?: string) {
    if (process.env.ALLOW_MANUAL_ENRICH === "false") {
      throw new ForbiddenException(
        "On-demand AI enrichment is disabled. Set ALLOW_MANUAL_ENRICH=true (or unset) to enable POST /cves/:id/enrich."
      );
    }
    const r = await this.db.query(`SELECT 1 FROM cve WHERE cve_id = $1 LIMIT 1`, [cveId]);
    if ((r.rowCount ?? 0) === 0) throw new NotFoundException("CVE not found");

    const forceOn = force === "true" || force === "1";

    const latestAi = await this.db.query<EnrichmentAiQueryRow>(
      `SELECT output_text, output_json, model, prompt_version, created_at
         FROM enrichment_ai
        WHERE cve_id = $1
     ORDER BY created_at DESC
        LIMIT ${ENRICHMENT_AI_RECENT_LIMIT}`,
      [cveId]
    );
    const enrichRow = pickRowForEnrichCacheHit(latestAi.rows);

    if (!forceOn && enrichRow != null) {
      return { ok: true, status: "cached" as const, cveId };
    }

    this.enrichRunner.scheduleEnrich(cveId, { force: forceOn });

    return { ok: true, status: "queued" as const, cveId };
  }

  @Get(":cveId")
  async get(@Param("cveId") cveId: string) {
    const cve = await this.db.query(
      `SELECT c.cve_id, c.source, c.published_at, c.modified_at, c.raw,
              rs.score AS risk_score, rs.factors AS risk_factors, rs.model_version,
              es.score AS epss,
              c.cvss_base AS cvss_base,
              (k.cve_id IS NOT NULL) AS exploit_known
         FROM cve c
    LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
    LEFT JOIN epss_score es ON es.cve_id = c.cve_id
    LEFT JOIN kev k ON k.cve_id = c.cve_id
        WHERE c.cve_id = $1
        LIMIT 1`,
      [cveId]
    );
    if (cve.rowCount === 0) return { found: false };

    const advisories = await this.db.query<{
      id: string;
      vendor_slug: string;
      title: string;
      link: string;
      summary: string | null;
      published_at: Date | null;
      fetched_at: Date;
    }>(
      `SELECT id, vendor_slug, title, link, summary, published_at, fetched_at
         FROM vendor_advisory
        WHERE $1 = ANY(cve_ids)
     ORDER BY published_at DESC NULLS LAST, fetched_at DESC
        LIMIT 50`,
      [cveId]
    );

    const vendorProducts = await this.db.query<{
      vendor: string | null;
      product: string | null;
      source: string | null;
      cve_updated_at: Date | null;
    }>(
      `SELECT vendor, product, source, cve_updated_at
         FROM cve_vendor_product
        WHERE cve_id = $1
     ORDER BY vendor NULLS LAST, product NULLS LAST
        LIMIT 250`,
      [cveId]
    );

    const advisoryMeta = await this.db.query<{
      total: number;
      with_cves: number;
      last_fetched_at: Date | null;
    }>(
      `SELECT
          count(*)::int AS total,
          count(*) FILTER (WHERE COALESCE(array_length(cve_ids, 1), 0) > 0)::int AS with_cves,
          max(fetched_at) AS last_fetched_at
         FROM vendor_advisory`
    );

    const ai = await this.db.query<EnrichmentAiQueryRow>(
      `SELECT model, prompt_version, output_json, output_text, created_at
         FROM enrichment_ai
        WHERE cve_id = $1
     ORDER BY created_at DESC
        LIMIT ${ENRICHMENT_AI_RECENT_LIMIT}`,
      [cveId]
    );

    const aiPayload = pickAiPayloadForGet(ai.rows);

    return {
      found: true,
      cve: cve.rows[0],
      links: this.buildCveLinks(cveId),
      vendorAdvisories: advisories.rows.map((r) => ({
        id: r.id,
        vendorSlug: r.vendor_slug,
        title: r.title,
        link: r.link,
        summary: r.summary,
        publishedAt: r.published_at ? new Date(r.published_at).toISOString() : null,
        fetchedAt: new Date(r.fetched_at).toISOString()
      })),
      vendorProducts: vendorProducts.rows.map((r) => ({
        vendor: r.vendor,
        product: r.product,
        source: r.source,
        cveUpdatedAt: r.cve_updated_at ? new Date(r.cve_updated_at).toISOString() : null
      })),
      vendorAdvisoriesMeta: {
        total: advisoryMeta.rows[0]?.total ?? 0,
        withCves: advisoryMeta.rows[0]?.with_cves ?? 0,
        lastFetchedAt: advisoryMeta.rows[0]?.last_fetched_at
          ? new Date(advisoryMeta.rows[0].last_fetched_at).toISOString()
          : null
      },
      ai: aiPayload
    };
  }
}


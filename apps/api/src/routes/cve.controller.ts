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
import {
  CVE_HOT_WINDOW_HOURS,
  SQL_EFFECTIVE_PUBLISHED_AT,
  extractNvdPublishedIso,
  isLlmEnrichFailureRow,
  isLlmNotConfiguredEnrichment,
  isPublishedWithinHours,
  parseNvdTimestampIso,
  parseVulnClassFilter,
  resolveCveCardEnrichment,
  sqlVulnClassGuessExpr
} from "@vuln-intel/shared";
import { escapePgLikePattern } from "../pg-like.util.js";
import { CveEnrichRunnerService } from "../services/cve-enrich-runner.service.js";
import { CveNvdImportService } from "../services/cve-nvd-import.service.js";
import { DbService } from "../services/db.service.js";
import { IntegrationSettingsService } from "../services/integration-settings.service.js";

type EnrichmentAiQueryRow = {
  model?: string;
  prompt_version?: string;
  output_json: unknown;
  output_text: string | null;
  created_at?: Date;
};

const ENRICHMENT_AI_RECENT_LIMIT = 20;

/**
 * Для GET: не показывать свежую строку ошибки (_enrich_error), если среди последних строк
 * уже есть успешное обогащение (ручной API мог записать фейл после парсинга, воркер — успех с 200).
 */
function pickAiPayloadForGet(rows: EnrichmentAiQueryRow[]): EnrichmentAiQueryRow | null {
  if (!rows.length) return null;
  const normalized = rows.map((r) => {
    let oj = r.output_json;
    if (typeof oj === "string") {
      try {
        oj = JSON.parse(oj) as unknown;
      } catch {
        return r;
      }
    }
    return { ...r, output_json: oj };
  });
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
  const normalized = rows.map((r) => {
    let oj = r.output_json;
    if (typeof oj === "string") {
      try {
        oj = JSON.parse(oj) as unknown;
      } catch {
        return r;
      }
    }
    return { ...r, output_json: oj };
  });
  return (
    normalized.find(
      (r) => !isLlmNotConfiguredEnrichment(r) && !isLlmEnrichFailureRow(r)
    ) ?? null
  );
}

/**
 * Разбор строки поиска: подстрока для ILIKE-подобного поиска, явные CVE и номера БДУ (для `ANY` по индексам).
 */
function parseVulnListSearch(qRaw: string): { qLowerForNeedle: string; bduIds: string[]; cveIds: string[] } {
  const qTrim = qRaw.trim();
  const qLower = qTrim.toLowerCase();
  const norm = qLower.replace(/бду/g, "bdu");

  const bduIds = new Set<string>();
  for (const m of norm.matchAll(/bdu\s*:\s*(\d{4}-\d+)/gi)) {
    const id = m[1];
    if (id) bduIds.add(id);
  }
  const bare = norm.match(/^\s*(\d{4}-\d+)\s*$/);
  if (bare?.[1] && !/^\s*cve-/i.test(qTrim)) bduIds.add(bare[1]);

  const cveIds = [
    ...new Set(
      [...qRaw.matchAll(/\bCVE-\d{4}-\d+\b/gi)].map((m) => String(m[0]).trim().toUpperCase())
    )
  ];

  return { qLowerForNeedle: norm, bduIds: [...bduIds], cveIds };
}

/** Агрегат номеров БДУ (без префикса «BDU:») для списка CVE. */
const SQL_BDU_IDS_FOR_CVE_LIST = `(SELECT array_agg(l.bdu_id ORDER BY l.bdu_id) FROM cve_bdu_link l WHERE l.cve_id = c.cve_id) AS bdu_ids`;

const SQL_EXPLOIT_INTEL_JOIN = `LEFT JOIN cve_exploit_intel ei ON ei.cve_id = c.cve_id`;

const SQL_EXPLOIT_INTEL_SELECT = `
                COALESCE(ei.epss_percentile, es.percentile) AS epss_percentile,
                ei.epss_delta_7d,
                COALESCE(ei.epss_spike, false) AS epss_spike,
                COALESCE(ei.vulncheck_kev, false) AS vulncheck_kev,
                COALESCE(ei.vckev_only, false) AS vckev_only,
                COALESCE(ei.has_poc, false) AS has_poc,
                COALESCE(ei.has_public_exploit, false) AS has_public_exploit,
                COALESCE(ei.exploit_ref_count, 0) AS exploit_ref_count`;

@Controller("cves")
export class CveController {
  constructor(
    private readonly db: DbService,
    private readonly enrichRunner: CveEnrichRunnerService,
    private readonly nvdImport: CveNvdImportService,
    private readonly integration: IntegrationSettingsService
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
    @Query("product") productRaw?: string,
    @Query("vulnClass") vulnClassRaw?: string | string[],
    @Query("vckevOnly") vckevOnlyRaw?: string,
    @Query("epssSpike") epssSpikeRaw?: string,
    @Query("hasPoc") hasPocRaw?: string,
    @Query("hasPublicExploit") hasPublicExploitRaw?: string,
    @Query("newVckev7d") newVckev7dRaw?: string
  ) {
    const limit = Math.max(1, Math.min(200, Number(limitRaw ?? 50)));
    const view = (viewRaw ?? "latest").toLowerCase();
    const sort = (sortRaw ?? (view === "critical" ? "rank" : "fresh")).toLowerCase();
    const minCvss = minCvssRaw != null ? Number(minCvssRaw) : undefined;
    const minEpss = minEpssRaw != null ? Number(minEpssRaw) : undefined;
    const kevOnly = kevOnlyRaw === "1" || kevOnlyRaw === "true";
    const vendor = vendorRaw?.trim() ? vendorRaw.trim().toLowerCase() : null;
    const product = productRaw?.trim() ? productRaw.trim().toLowerCase() : null;
    const vulnClasses = parseVulnClassFilter(vulnClassRaw);
    const vckevOnlyFilter = vckevOnlyRaw === "1" || vckevOnlyRaw === "true";
    const epssSpikeFilter = epssSpikeRaw === "1" || epssSpikeRaw === "true";
    const hasPocFilter = hasPocRaw === "1" || hasPocRaw === "true";
    const hasPublicExploitFilter = hasPublicExploitRaw === "1" || hasPublicExploitRaw === "true";
    const newVckev7dFilter = newVckev7dRaw === "1" || newVckev7dRaw === "true";
    const vulnClassGuessSql = sqlVulnClassGuessExpr();
    /** Полнотекстовый поиск: не сужать выборку пресетом вкладки (иначе по BDU/CVE не находятся «тихие» записи). */
    const qPresent = Boolean(q?.trim());

    const rankExpr = `(COALESCE(c.cvss_base, 0) * 0.7 + COALESCE(es.score, 0) * 10 * 0.3)`;
    // Critical v2: deterministic ordering, no "empty" records.
    // - KEV always included and always ranked first
    // - EPSS >= 0.2 or CVSS >= 8.0 included (configurable via query thresholds)
    // - Deterministic tiebreakers: published_at desc, cve_id asc
    const criticalV2OrderBy = `ORDER BY (k.cve_id IS NOT NULL) DESC,
                                      GREATEST(COALESCE(es.score, 0) * 100, COALESCE(c.cvss_base, 0) * 10) DESC,
                                      c.published_at DESC NULLS LAST,
                                      c.cve_id ASC`;
    const isLast24hView =
      view === "last24h" || view === "last_24h" || view === "last-24h";
    const orderBy = (() => {
      if (isLast24hView) {
        return `ORDER BY ${SQL_EFFECTIVE_PUBLISHED_AT} DESC NULLS LAST, c.cve_id ASC`;
      }
      if (sort === "risk") return `ORDER BY rs.score DESC NULLS LAST, c.published_at DESC NULLS LAST`;
      if (sort === "epss") return `ORDER BY es.score DESC NULLS LAST, c.published_at DESC NULLS LAST`;
      if (sort === "cvss") return `ORDER BY c.cvss_base DESC NULLS LAST, c.published_at DESC NULLS LAST`;
      if (sort === "exploit") {
        return `ORDER BY COALESCE(ei.epss_spike, false) DESC,
                         COALESCE(ei.vckev_only, false) DESC,
                         COALESCE(ei.has_public_exploit, false) DESC,
                         COALESCE(ei.epss_delta_7d, 0) DESC NULLS LAST,
                         COALESCE(es.score, 0) DESC,
                         c.published_at DESC NULLS LAST`;
      }
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
    if (vckevOnlyFilter) filters.push(`COALESCE(ei.vckev_only, false) = true`);
    if (epssSpikeFilter) filters.push(`COALESCE(ei.epss_spike, false) = true`);
    if (hasPocFilter) filters.push(`COALESCE(ei.has_poc, false) = true`);
    if (hasPublicExploitFilter) filters.push(`COALESCE(ei.has_public_exploit, false) = true`);
    if (newVckev7dFilter) {
      filters.push(
        `EXISTS (SELECT 1 FROM vulncheck_kev vk7 WHERE vk7.cve_id = c.cve_id AND vk7.date_added >= now() - interval '7 days')`
      );
    }
    if (!qPresent) {
      if (Number.isFinite(minCvss)) add(`c.cvss_base >= $1`, minCvss);
      if (Number.isFinite(minEpss)) add(`es.score >= $1`, minEpss);
    }

    if (!qPresent) {
      if (view === "kev") filters.push(`k.cve_id IS NOT NULL`);
      if (view === "exploit") {
        filters.push(
          `(COALESCE(ei.vckev_only, false) OR COALESCE(ei.epss_spike, false) OR COALESCE(ei.has_poc, false) OR COALESCE(ei.has_public_exploit, false))`
        );
      }
      if (isLast24hView) {
        // Только реальная дата публикации в NVD (колонка + паспорт raw), не lastModified и не время ingest.
        filters.push(`${SQL_EFFECTIVE_PUBLISHED_AT} IS NOT NULL`);
        filters.push(
          `${SQL_EFFECTIVE_PUBLISHED_AT} >= now() - interval '${CVE_HOT_WINDOW_HOURS} hours'`
        );
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

    if (vulnClasses.length > 0) {
      params.push(vulnClasses);
      const clsIdx = params.length;
      filters.push(`${vulnClassGuessSql} = ANY($${clsIdx}::text[])`);
    }

    if (q && q.trim().length > 0) {
      const qTrim = q.trim();
      const { qLowerForNeedle, bduIds, cveIds } = parseVulnListSearch(qTrim);
      const isExactCveQuery = /^cve-\d{4}-\d{4,}$/i.test(qTrim);
      const needleLiteral = qLowerForNeedle;
      const needleLike = escapePgLikePattern(qLowerForNeedle);
      params.push(needleLiteral);
      const literalIdx = params.length;
      params.push(needleLike);
      const needleIdx = params.length;
      const exactCond = `lower(c.cve_id) = $${literalIdx}::text`;
      const likeSuffix = `LIKE '%' || $${needleIdx}::text || '%' ESCAPE E'\\\\'`;

      let cveAnyIdx = 0;
      let bduAnyIdx = 0;
      if (cveIds.length > 0) {
        params.push(cveIds);
        cveAnyIdx = params.length;
      }
      if (bduIds.length > 0) {
        params.push(bduIds);
        bduAnyIdx = params.length;
      }

      const exactParts: string[] = [`(${exactCond})`];
      if (cveAnyIdx > 0) exactParts.push(`c.cve_id = ANY($${cveAnyIdx}::text[])`);
      if (bduAnyIdx > 0) {
        exactParts.push(
          `EXISTS (SELECT 1 FROM cve_bdu_link cb_em WHERE cb_em.cve_id = c.cve_id AND cb_em.bdu_id = ANY($${bduAnyIdx}::text[]))`
        );
      }
      const exactMatchExpr = `(${exactParts.join(" OR ")})`;

      const idTokenSql =
        (cveAnyIdx > 0 ? ` OR c.cve_id = ANY($${cveAnyIdx}::text[])` : "") +
        (bduAnyIdx > 0
          ? ` OR EXISTS (SELECT 1 FROM cve_bdu_link cb_any WHERE cb_any.cve_id = c.cve_id AND cb_any.bdu_id = ANY($${bduAnyIdx}::text[]))`
          : "");

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
        OR EXISTS (
          SELECT 1 FROM cve_bdu_link cb_q
          WHERE cb_q.cve_id = c.cve_id
            AND (
              lower(cb_q.bdu_id) ${likeSuffix}
              OR lower(('bdu:' || cb_q.bdu_id)::text) ${likeSuffix}
            )
        )
        OR EXISTS (
          SELECT 1 FROM risk_score rs_q
          WHERE rs_q.cve_id = c.cve_id
            AND (
              lower(rs_q.factors::text) ${likeSuffix}
              OR lower(rs_q.model_version) ${likeSuffix}
            )
        )
        ${idTokenSql}
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
                  CASE
                    WHEN ea1.output_json->>'summary' IS NOT NULL
                      AND ea1.output_json->>'summary' NOT LIKE '{%'
                      AND length(ea1.output_json->>'summary') < 1800
                      THEN ea1.output_json->>'summary'
                  END,
                  ea1.output_json->'raw_model_json'->>'summary',
                  CASE
                    WHEN ea1.output_json->>'title' IS NOT NULL
                      AND ea1.output_json->>'title' <> 'Комплексный анализ уязвимости'
                      THEN ea1.output_json->>'title'
                  END,
                  ea1.output_json->'raw_model_json'->>'title',
                  substring(regexp_replace(COALESCE(
                    c.raw->'descriptions'->0->>'value',
                    c.raw->'cve'->'descriptions'->0->>'value',
                    c.raw->'cve'->'description'->'description_data'->0->>'value',
                    c.raw->'description'->'description_data'->0->>'value',
                    ''
                  ), E'\\s+', ' ', 'g') for 220),
                  ''
                ), E'\\s+', ' ', 'g') for 220), '') AS short_ru,
                COALESCE((
                  SELECT count(*)::int FROM vuln_task_cve l
                  JOIN vuln_task t ON t.id = l.task_id
                  WHERE l.cve_id = c.cve_id AND t.status <> 'closed'
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
                ${vulnClassGuessSql} AS vuln_class,
                ARRAY_REMOVE(ARRAY[
                  CASE WHEN k.cve_id IS NOT NULL THEN 'KEV' ELSE NULL END,
                  CASE WHEN es.score IS NOT NULL AND es.score >= 0.5 THEN 'EPSS>=0.50' ELSE NULL END,
                  CASE WHEN es.score IS NOT NULL AND es.score >= 0.2 AND es.score < 0.5 THEN 'EPSS>=0.20' ELSE NULL END,
                  CASE WHEN c.cvss_base IS NOT NULL AND c.cvss_base >= 9.0 THEN 'CVSS>=9.0' ELSE NULL END,
                  CASE WHEN c.cvss_base IS NOT NULL AND c.cvss_base >= 8.0 AND c.cvss_base < 9.0 THEN 'CVSS>=8.0' ELSE NULL END
                ], NULL) AS critical_reasons,
                ${SQL_EXPLOIT_INTEL_SELECT},
                ${SQL_BDU_IDS_FOR_CVE_LIST},
                ${exactMatchExpr} AS exact_match,
                similarity(lower(c.cve_id), $${literalIdx}::text) AS cve_sim
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
      ${SQL_EXPLOIT_INTEL_JOIN}`;

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
                 exploit_known, ai_ready, vuln_class, critical_reasons,
                 epss_percentile, epss_delta_7d, epss_spike, vulncheck_kev, vckev_only,
                 has_poc, has_public_exploit, exploit_ref_count,
                 bdu_ids
            FROM hits
           ${searchOrderBy}
           LIMIT $${limitIdx}`
        : `${baseSelect}
           WHERE ${whereFiltered}
           ${searchOrderBy}
           LIMIT $${limitIdx}`;

      let r = await this.db.query(sql, params);
      if (r.rows.length === 0 && isExactCveQuery) {
        const imported = await this.nvdImport.importByCveId(qTrim);
        if (imported) r = await this.db.query(sql, params);
      }
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
                  CASE
                    WHEN ea1.output_json->>'summary' IS NOT NULL
                      AND ea1.output_json->>'summary' NOT LIKE '{%'
                      AND length(ea1.output_json->>'summary') < 1800
                      THEN ea1.output_json->>'summary'
                  END,
                  ea1.output_json->'raw_model_json'->>'summary',
                  CASE
                    WHEN ea1.output_json->>'title' IS NOT NULL
                      AND ea1.output_json->>'title' <> 'Комплексный анализ уязвимости'
                      THEN ea1.output_json->>'title'
                  END,
                  ea1.output_json->'raw_model_json'->>'title',
                  substring(regexp_replace(COALESCE(
                    c.raw->'descriptions'->0->>'value',
                    c.raw->'cve'->'descriptions'->0->>'value',
                    c.raw->'cve'->'description'->'description_data'->0->>'value',
                    c.raw->'description'->'description_data'->0->>'value',
                    ''
                  ), E'\\s+', ' ', 'g') for 220),
                  ''
              ), E'\\s+', ' ', 'g') for 220), '') AS short_ru,
              COALESCE((
                SELECT count(*)::int FROM vuln_task_cve l
                JOIN vuln_task t ON t.id = l.task_id
                WHERE l.cve_id = c.cve_id AND t.status <> 'closed'
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
              ${vulnClassGuessSql} AS vuln_class,
              ARRAY_REMOVE(ARRAY[
                CASE WHEN k.cve_id IS NOT NULL THEN 'KEV' ELSE NULL END,
                CASE WHEN es.score IS NOT NULL AND es.score >= 0.5 THEN 'EPSS>=0.50' ELSE NULL END,
                CASE WHEN es.score IS NOT NULL AND es.score >= 0.2 AND es.score < 0.5 THEN 'EPSS>=0.20' ELSE NULL END,
                CASE WHEN c.cvss_base IS NOT NULL AND c.cvss_base >= 9.0 THEN 'CVSS>=9.0' ELSE NULL END,
                CASE WHEN c.cvss_base IS NOT NULL AND c.cvss_base >= 8.0 AND c.cvss_base < 9.0 THEN 'CVSS>=8.0' ELSE NULL END
              ], NULL) AS critical_reasons,
              ${SQL_EXPLOIT_INTEL_SELECT},
              ${SQL_BDU_IDS_FOR_CVE_LIST}
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
    ${SQL_EXPLOIT_INTEL_JOIN}
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
    if (normalized.length > 2500) normalized.length = 2500;
    if (normalized.length === 0) return { present: [] as string[] };

    const r = await this.db.query<{ cve_id: string }>(
      `SELECT cve_id FROM cve WHERE cve_id = ANY($1::text[])`,
      [normalized]
    );
    return { present: r.rows.map((row) => row.cve_id) };
  }

  /**
   * Сохраняет пары БДУ↔CVE из ленты ФСТЭК (только если `cve_id` уже есть в `cve`).
   * Идемпотентно: повторные пары игнорируются.
   */
  @Post("bdu-links")
  @HttpCode(200)
  async upsertBduLinks(@Body() body: { pairs?: unknown }) {
    const raw = body?.pairs;
    const arr = Array.isArray(raw) ? raw : [];
    const cveRe = /^CVE-\d{4}-\d+$/i;
    const bduRe = /^\d{4}-\d+$/;
    const seen = new Set<string>();
    const pairs: { cveId: string; bduId: string }[] = [];
    for (const row of arr) {
      if (pairs.length >= 500) break;
      if (row == null || typeof row !== "object") continue;
      const o = row as { cveId?: unknown; bduId?: unknown };
      const cveId = String(o.cveId ?? "").trim().toUpperCase();
      const bduId = String(o.bduId ?? "").trim();
      if (!cveRe.test(cveId) || !bduRe.test(bduId)) continue;
      const k = `${cveId}|${bduId}`;
      if (seen.has(k)) continue;
      seen.add(k);
      pairs.push({ cveId, bduId: bduId });
    }
    if (pairs.length === 0) return { ok: true, inserted: 0 };

    const valuesSql = pairs.map((_, i) => `($${i * 2 + 1}, $${i * 2 + 2})`).join(", ");
    const flatParams: string[] = [];
    for (const p of pairs) {
      flatParams.push(p.cveId, p.bduId);
    }

    const ins = await this.db.query(
      `INSERT INTO cve_bdu_link (cve_id, bdu_id)
       SELECT v.cve_id, v.bdu_id
         FROM (VALUES ${valuesSql}) AS v(cve_id, bdu_id)
         JOIN cve c ON c.cve_id = v.cve_id
    ON CONFLICT (cve_id, bdu_id) DO NOTHING`,
      flatParams
    );
    return { ok: true, inserted: ins.rowCount ?? 0 };
  }

  /** Queue AI enrichment for a CVE (intended when user opens the detail modal). Idempotent per CVE revision unless force=1. */
  @Post(":cveId/enrich")
  async requestEnrich(@Param("cveId") cveId: string, @Query("force") force?: string) {
    if (process.env.ALLOW_MANUAL_ENRICH === "false") {
      throw new ForbiddenException(
        "On-demand AI enrichment is disabled. Set ALLOW_MANUAL_ENRICH=true (or unset) to enable POST /cves/:id/enrich."
      );
    }
    const r = await this.db.query<{ published_at: Date | null; raw: unknown }>(
      `SELECT published_at, raw FROM cve WHERE cve_id = $1 LIMIT 1`,
      [cveId]
    );
    if ((r.rowCount ?? 0) === 0) throw new NotFoundException("CVE not found");

    const forceOn = force === "true" || force === "1";
    const textEngine = await this.integration.getTextEngineSettings();
    const cveRow = r.rows[0]!;
    const publishedIso =
      (cveRow.published_at ? parseNvdTimestampIso(cveRow.published_at.toISOString()) : undefined) ??
      extractNvdPublishedIso(cveRow.raw);
    const inHotWindow = isPublishedWithinHours(publishedIso, CVE_HOT_WINDOW_HOURS);

    if (textEngine.textEngine !== "llm") {
      const res = await this.enrichRunner.enrichNow(cveId, {
        force: forceOn,
        allowOutsideHotWindow: true
      });
      return {
        ok: Boolean(res) || !forceOn,
        status: res ? ("ready" as const) : forceOn ? ("failed" as const) : ("cached" as const),
        cveId,
        textEngine: textEngine.textEngine,
        output_json: res?.outputJson ?? null,
        output_text: res?.outputText ?? null
      };
    }

    if (!forceOn && !inHotWindow) {
      return {
        ok: true,
        status: "skipped_outside_hot_window" as const,
        cveId,
        publishedAt: publishedIso ?? null,
        hotWindowHours: CVE_HOT_WINDOW_HOURS
      };
    }

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
    const cveSql = `SELECT c.cve_id, c.source, c.published_at, c.modified_at, c.raw,
              rs.score AS risk_score, rs.factors AS risk_factors, rs.model_version,
              es.score AS epss,
              COALESCE(ei.epss_percentile, es.percentile) AS epss_percentile,
              ei.epss_delta_7d,
              COALESCE(ei.epss_spike, false) AS epss_spike,
              COALESCE(ei.vulncheck_kev, false) AS vulncheck_kev,
              COALESCE(ei.vckev_only, false) AS vckev_only,
              COALESCE(ei.has_poc, false) AS has_poc,
              COALESCE(ei.has_nuclei, false) AS has_nuclei,
              COALESCE(ei.has_public_exploit, false) AS has_public_exploit,
              COALESCE(ei.exploit_ref_count, 0) AS exploit_ref_count,
              c.cvss_base AS cvss_base,
              (k.cve_id IS NOT NULL) AS exploit_known,
              (SELECT array_agg(l.bdu_id ORDER BY l.bdu_id) FROM cve_bdu_link l WHERE l.cve_id = c.cve_id) AS bdu_ids
         FROM cve c
    LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
    LEFT JOIN epss_score es ON es.cve_id = c.cve_id
    LEFT JOIN kev k ON k.cve_id = c.cve_id
    LEFT JOIN cve_exploit_intel ei ON ei.cve_id = c.cve_id
        WHERE c.cve_id = $1
        LIMIT 1`;

    let cve = await this.db.query(cveSql, [cveId]);
    if ((cve.rowCount ?? 0) === 0 && this.nvdImport.isExactCveId(cveId)) {
      const imported = await this.nvdImport.importByCveId(cveId);
      if (imported) cve = await this.db.query(cveSql, [cveId]);
    }
    if ((cve.rowCount ?? 0) === 0) return { found: false };

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

    const aiPayloadRaw = pickAiPayloadForGet(ai.rows);
    const cveRaw = cve.rows[0]?.raw;
    const resolvedJson = resolveCveCardEnrichment(aiPayloadRaw?.output_json ?? null, cveId, cveRaw);
    const aiPayload = {
      model: aiPayloadRaw?.model ?? "nvd-baseline",
      prompt_version: aiPayloadRaw?.prompt_version ?? "v1",
      output_json: resolvedJson,
      output_text:
        aiPayloadRaw?.output_text ??
        (typeof resolvedJson.summary === "string" ? resolvedJson.summary : null),
      created_at: aiPayloadRaw?.created_at ?? null
    };

    const exploitSignals = await this.db.query<{
      signal_type: string;
      source: string;
      url: string | null;
      title: string | null;
      confidence: string;
      first_seen_at: Date | null;
      last_seen_at: Date | null;
    }>(
      `SELECT signal_type, source, url, title, confidence, first_seen_at, last_seen_at
         FROM cve_exploit_signal
        WHERE cve_id = $1
        ORDER BY last_seen_at DESC NULLS LAST
        LIMIT 50`,
      [cveId]
    );

    const vulncheckKev = await this.db.query<{
      date_added: Date | null;
      cisa_date_added: Date | null;
      vckev_only: boolean;
      ransomware_use: string | null;
      evidence_count: number;
      xdb_url: string | null;
    }>(
      `SELECT date_added, cisa_date_added, vckev_only, ransomware_use, evidence_count, xdb_url
         FROM vulncheck_kev WHERE cve_id = $1 LIMIT 1`,
      [cveId]
    );

    return {
      found: true,
      cve: cve.rows[0],
      links: this.buildCveLinks(cveId),
      textEngine: (await this.integration.getTextEngineSettings()).textEngine,
      exploitIntel: {
        signals: exploitSignals.rows.map((r) => ({
          signal_type: r.signal_type,
          source: r.source,
          url: r.url,
          title: r.title,
          confidence: r.confidence,
          first_seen_at: r.first_seen_at ? new Date(r.first_seen_at).toISOString() : null,
          last_seen_at: r.last_seen_at ? new Date(r.last_seen_at).toISOString() : null
        })),
        vulncheckKev: vulncheckKev.rows[0]
          ? {
              dateAdded: vulncheckKev.rows[0].date_added
                ? new Date(vulncheckKev.rows[0].date_added).toISOString()
                : null,
              cisaDateAdded: vulncheckKev.rows[0].cisa_date_added
                ? new Date(vulncheckKev.rows[0].cisa_date_added).toISOString()
                : null,
              vckevOnly: vulncheckKev.rows[0].vckev_only,
              ransomwareUse: vulncheckKev.rows[0].ransomware_use,
              evidenceCount: vulncheckKev.rows[0].evidence_count,
              xdbUrl: vulncheckKev.rows[0].xdb_url
            }
          : null
      },
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


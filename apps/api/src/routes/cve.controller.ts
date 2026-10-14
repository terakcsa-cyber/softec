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
import { PointCveAiService } from "../services/point-cve-ai.service.js";
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

function clipText(value: string | null | undefined, max: number) {
  const clean = (value ?? "")
    .replace(/&#13;|&#10;/g, "\n")
    .replace(/&quot;/g, "\"")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .trim();
  if (!clean) return null;
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

function dayStamp(value: Date | string | null | undefined) {
  if (!value) return null;
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value.toISOString().slice(0, 10);
  const text = String(value);
  const match = /^(\d{4}-\d{2}-\d{2})/.exec(text);
  return match ? match[1] : null;
}

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
  // Bare YYYY-N… is ambiguous (CVE serial vs BDU). Prefer CVE prefix path; only treat as BDU when
  // the query explicitly says bdu:… (handled above) or starts with bdu.
  const bareBdu = norm.match(/^\s*bdu[:\s-]*(\d{4}-\d+)\s*$/i);
  if (bareBdu?.[1]) bduIds.add(bareBdu[1]);

  const cveIds = [
    ...new Set(
      [...qRaw.matchAll(/\bCVE-\d{4}-\d+\b/gi)].map((m) => String(m[0]).trim().toUpperCase())
    )
  ];

  return { qLowerForNeedle: norm, bduIds: [...bduIds], cveIds };
}

/** CVE-2025-353 / 2025-353 / cve_2025_353 → CVE-2025-353 (partial or full). */
function cveIdShape(qRaw: string): string | null {
  const compact = qRaw.trim().replace(/\s+/g, "");
  const m = /^(?:cve[_-]?)?(\d{4})[_-](\d{1,})$/i.exec(compact);
  if (!m?.[1] || !m[2]) return null;
  return `CVE-${m[1]}-${m[2]}`.toUpperCase();
}

/** Токены свободного поиска (вендор/продукт/фраза). */
function searchTokens(qLower: string): string[] {
  const parts = qLower
    .split(/[^a-z0-9а-яё._+-]+/i)
    .map((t) => t.trim())
    .filter((t) => t.length >= 2);
  return [...new Set(parts)].slice(0, 5);
}

/** Поля каталога CPE/вендор↔продукт для `LIKE '%'||$n||'%'` (alias `vp`). */
function vpFieldsLikeSql(paramIdx: number): string {
  const like = `LIKE '%' || $${paramIdx}::text || '%' ESCAPE E'\\\\'`;
  return `(
              lower(vp.vendor) ${like}
              OR lower(COALESCE(vp.product, '')) ${like}
              OR lower(vp.vendor_key) ${like}
              OR lower(vp.product_key_norm) ${like}
            )`;
}

function clampWindowDays(raw: string | undefined): number | null {
  const n = Number(raw);
  if (!Number.isFinite(n)) return null;
  const days = Math.trunc(n);
  if (days < 1 || days > 90) return null;
  return days;
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

/** Heavy list columns: hydrate only after LIMIT on ranked ids. Expects aliases c, vp1, ea1, rs, es, k, ei. */
const SQL_CVE_LIST_SELECT = `c.cve_id, c.published_at, c.modified_at,
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
                (
                  SELECT left(COALESCE(
                    NULLIF(elem->>'versionEndExcluding', ''),
                    NULLIF(elem->>'versionEndIncluding', ''),
                    NULLIF(elem->>'versionStartIncluding', '')
                  ), 48)
                    FROM jsonb_array_elements(
                      CASE
                        WHEN jsonb_typeof(c.raw->'configurations') = 'array' THEN c.raw->'configurations'
                        WHEN jsonb_typeof(c.raw->'cve'->'configurations') = 'array' THEN c.raw->'cve'->'configurations'
                        ELSE '[]'::jsonb
                      END
                    ) cfg
                    CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(cfg->'nodes') = 'array' THEN cfg->'nodes' ELSE '[]'::jsonb END) node
                    CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(node->'cpeMatch') = 'array' THEN node->'cpeMatch' ELSE '[]'::jsonb END) elem
                   WHERE COALESCE(elem->>'vulnerable', 'true') <> 'false'
                     AND COALESCE(elem->>'versionEndExcluding', elem->>'versionEndIncluding', elem->>'versionStartIncluding', '') <> ''
                   LIMIT 1
                ) AS affected_version,
                EXISTS (
                  SELECT 1 FROM enrichment_ai ea
                  WHERE ea.cve_id = c.cve_id
                    AND (ea.output_json->>'_enrich_error') IS DISTINCT FROM 'true'
                    AND NOT (
                      COALESCE(ea.output_text, '') = 'LLM not configured.'
                      OR COALESCE(ea.output_json->>'summary', '') LIKE 'LLM not configured%'
                    )
                ) AS ai_ready`;

const SQL_CVE_LIST_VP_LATERAL = `LEFT JOIN LATERAL (
        SELECT vp.vendor, vp.product
          FROM cve_vendor_product vp
         WHERE vp.cve_id = c.cve_id
      ORDER BY vp.vendor_key ASC, vp.product_key_norm ASC
         LIMIT 1
      ) vp1 ON TRUE`;

const SQL_CVE_LIST_EA_LATERAL = `LEFT JOIN LATERAL (
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
      ) ea1 ON TRUE`;

const SQL_CVE_LIST_SCORE_JOINS =
  `LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
      LEFT JOIN epss_score es ON es.cve_id = c.cve_id
      LEFT JOIN kev k ON k.cve_id = c.cve_id
      ` + SQL_EXPLOIT_INTEL_JOIN;


@Controller("cves")
export class CveController {
  constructor(
    private readonly db: DbService,
    private readonly enrichRunner: CveEnrichRunnerService,
    private readonly nvdImport: CveNvdImportService,
    private readonly integration: IntegrationSettingsService,
    private readonly pointAi: PointCveAiService
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
    @Query("maxCvss") maxCvssRaw?: string,
    @Query("minEpss") minEpssRaw?: string,
    @Query("kevOnly") kevOnlyRaw?: string,
    @Query("vendor") vendorRaw?: string,
    @Query("product") productRaw?: string,
    @Query("vulnClass") vulnClassRaw?: string | string[],
    @Query("vckevOnly") vckevOnlyRaw?: string,
    @Query("epssSpike") epssSpikeRaw?: string,
    @Query("hasPoc") hasPocRaw?: string,
    @Query("hasPublicExploit") hasPublicExploitRaw?: string,
    @Query("newVckev7d") newVckev7dRaw?: string,
    @Query("kevAddedDays") kevAddedDaysRaw?: string,
    @Query("publishedDays") publishedDaysRaw?: string,
    @Query("offset") offsetRaw?: string,
    @Query("includeTotal") includeTotalRaw?: string,
    @Query("hasTask") hasTaskRaw?: string
  ) {
    return this.listFromDb(
      q,
      limitRaw,
      viewRaw,
      sortRaw,
      minCvssRaw,
      maxCvssRaw,
      minEpssRaw,
      kevOnlyRaw,
      vendorRaw,
      productRaw,
      vulnClassRaw,
      vckevOnlyRaw,
      epssSpikeRaw,
      hasPocRaw,
      hasPublicExploitRaw,
      newVckev7dRaw,
      kevAddedDaysRaw,
      publishedDaysRaw,
      offsetRaw,
      includeTotalRaw,
      hasTaskRaw
    );
  }

  private async listFromDb(
    q?: string,
    limitRaw?: string,
    viewRaw?: string,
    sortRaw?: string,
    minCvssRaw?: string,
    maxCvssRaw?: string,
    minEpssRaw?: string,
    kevOnlyRaw?: string,
    vendorRaw?: string,
    productRaw?: string,
    vulnClassRaw?: string | string[],
    vckevOnlyRaw?: string,
    epssSpikeRaw?: string,
    hasPocRaw?: string,
    hasPublicExploitRaw?: string,
    newVckev7dRaw?: string,
    kevAddedDaysRaw?: string,
    publishedDaysRaw?: string,
    offsetRaw?: string,
    includeTotalRaw?: string,
    hasTaskRaw?: string
  ) {
    const limit = Math.max(1, Math.min(200, Number(limitRaw ?? 50)));
    const offset = Math.max(0, Math.min(1_000_000, Number(offsetRaw ?? 0) || 0));
    const includeTotal = includeTotalRaw === "1" || includeTotalRaw === "true";
    const view = (viewRaw ?? "latest").toLowerCase();
    const sort = (sortRaw ?? (view === "critical" ? "rank" : "fresh")).toLowerCase();
    const minCvss = minCvssRaw != null ? Number(minCvssRaw) : undefined;
    const maxCvss = maxCvssRaw != null ? Number(maxCvssRaw) : undefined;
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
    const kevAddedDays = clampWindowDays(kevAddedDaysRaw);
    const publishedDays = clampWindowDays(publishedDaysRaw);
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

    if (hasTaskRaw === "1" || hasTaskRaw === "true") {
      filters.push(
        `EXISTS (SELECT 1 FROM vuln_task_cve l JOIN vuln_task t ON t.id = l.task_id WHERE l.cve_id = c.cve_id AND t.status <> 'closed')`
      );
    } else if (hasTaskRaw === "0" || hasTaskRaw === "false") {
      filters.push(
        `NOT EXISTS (SELECT 1 FROM vuln_task_cve l JOIN vuln_task t ON t.id = l.task_id WHERE l.cve_id = c.cve_id AND t.status <> 'closed')`
      );
    }
    if (kevOnly || kevAddedDays != null) filters.push(`k.cve_id IS NOT NULL`);
    if (vckevOnlyFilter) filters.push(`COALESCE(ei.vckev_only, false) = true`);
    if (epssSpikeFilter) filters.push(`COALESCE(ei.epss_spike, false) = true`);
    if (hasPocFilter) filters.push(`COALESCE(ei.has_poc, false) = true`);
    if (hasPublicExploitFilter) filters.push(`COALESCE(ei.has_public_exploit, false) = true`);
    if (newVckev7dFilter) {
      filters.push(
        `EXISTS (SELECT 1 FROM vulncheck_kev vk7 WHERE vk7.cve_id = c.cve_id AND vk7.date_added >= now() - interval '7 days')`
      );
    }
    if (kevAddedDays != null) {
      params.push(kevAddedDays - 1);
      filters.push(
        `EXISTS (
           SELECT 1 FROM kev k_new
            WHERE k_new.cve_id = c.cve_id
              AND k_new.date_added IS NOT NULL
              AND k_new.date_added >= (timezone('UTC', now()))::date - $${params.length}::int
         )`
      );
    }
    if (publishedDays != null) {
      params.push(publishedDays);
      filters.push(`c.published_at IS NOT NULL AND c.published_at >= now() - ($${params.length}::text || ' days')::interval`);
    }
    if (!qPresent) {
      if (Number.isFinite(minCvss)) add(`c.cvss_base >= $1`, minCvss);
      if (Number.isFinite(maxCvss)) add(`c.cvss_base < $1`, maxCvss);
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

    if (vendor || product) {
      const match: string[] = [];
      if (vendor) {
        params.push(vendor);
        const vIdx = params.length;
        match.push(`(vp.vendor_key = $${vIdx} OR lower(vp.vendor) = $${vIdx})`);
      }
      if (product) {
        params.push(product);
        const pIdx = params.length;
        match.push(`(vp.product_key_norm = $${pIdx} OR lower(vp.product) = $${pIdx})`);
      }
      filters.push(`EXISTS (SELECT 1 FROM cve_vendor_product vp WHERE vp.cve_id = c.cve_id AND ${match.join(" AND ")})`);
    }

    if (vulnClasses.length > 0) {
      params.push(vulnClasses);
      const clsIdx = params.length;
      filters.push(`${vulnClassGuessSql} = ANY($${clsIdx}::text[])`);
    }

    if (q && q.trim().length > 0) {
      const qTrim = q.trim();
      const { qLowerForNeedle, bduIds, cveIds } = parseVulnListSearch(qTrim);
      const shapedCve = cveIdShape(qTrim);
      const isExactCveQuery = Boolean(shapedCve && /^CVE-\d{4}-\d{4,}$/.test(shapedCve));

      // Fast path: CVE-shaped queries (full or partial) → PK / prefix on cve_id only.
      // Avoids multi-second scans of raw::text / enrichment for "CVE-2025-353".
      if (shapedCve && filters.length === 0 && bduIds.length === 0) {
        const exactId = shapedCve;
        const prefix = exactId;
        const hydrateSql = (whereSql: string, limitSql: string) => `SELECT ${SQL_CVE_LIST_SELECT},
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
      ${SQL_CVE_LIST_VP_LATERAL}
      ${SQL_CVE_LIST_EA_LATERAL}
      ${SQL_CVE_LIST_SCORE_JOINS}
          WHERE ${whereSql}
          ${limitSql}`;

        if (isExactCveQuery) {
          const exactParams = [...params, exactId];
          let r = await this.db.query(
            hydrateSql(`c.cve_id = $${exactParams.length}`, "LIMIT 1"),
            exactParams
          );
          if (r.rows.length === 0) {
            const imported = await this.nvdImport.importByCveId(exactId);
            if (imported) {
              r = await this.db.query(
                hydrateSql(`c.cve_id = $${exactParams.length}`, "LIMIT 1"),
                exactParams
              );
            }
          }
          if (r.rows.length > 0) return { items: r.rows };
        }

        const prefixParams = [...params, prefix, limit, offset];
        const prefixIdx = params.length + 1;
        const limIdx = params.length + 2;
        const offIdx = params.length + 3;
        const rPrefix = await this.db.query(
          `WITH ranked AS (
             SELECT c.cve_id,
                    (c.cve_id = $${prefixIdx}::text) AS exact_match,
                    length(c.cve_id) AS id_len,
                    ${rankExpr} AS rank_score,
                    c.published_at
               FROM cve c
          LEFT JOIN epss_score es ON es.cve_id = c.cve_id
          LEFT JOIN kev k ON k.cve_id = c.cve_id
              WHERE c.cve_id LIKE $${prefixIdx}::text || '%'
           ORDER BY exact_match DESC, id_len ASC, rank_score DESC NULLS LAST, published_at DESC NULLS LAST, cve_id ASC
              LIMIT $${limIdx} OFFSET $${offIdx}
           )
           SELECT ${SQL_CVE_LIST_SELECT},
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
           FROM ranked r
           JOIN cve c ON c.cve_id = r.cve_id
      ${SQL_CVE_LIST_VP_LATERAL}
      ${SQL_CVE_LIST_EA_LATERAL}
      ${SQL_CVE_LIST_SCORE_JOINS}
       ORDER BY r.exact_match DESC, r.id_len ASC, r.rank_score DESC NULLS LAST, r.published_at DESC NULLS LAST, r.cve_id ASC`,
          prefixParams
        );
        return { items: rPrefix.rows };
      }

      // Free-text: collect candidate ids from indexed tables (vendor/product, cve_id, …),
      // then rank — never `FROM cve WHERE EXISTS (vp/enrichment)` (multi-second on large catalogs).
      const needleLiteral = qLowerForNeedle;
      const tokens = searchTokens(qLowerForNeedle);
      if (!shapedCve && tokens.length === 0 && needleLiteral.replace(/\s+/g, "").length < 2) {
        return { items: [], total: 0 };
      }

      params.push(needleLiteral);
      const literalIdx = params.length;
      const exactCond = `lower(c.cve_id) = $${literalIdx}::text`;

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

      const candidateParts: string[] = [];
      const tokenIdxs: number[] = [];
      const tokenSource = tokens.length > 0 ? tokens : [needleLiteral];
      for (const token of tokenSource) {
        params.push(escapePgLikePattern(token));
        tokenIdxs.push(params.length);
      }
      const phraseIdx =
        tokenSource.length > 1 || tokenSource[0] !== needleLiteral
          ? (() => {
              params.push(escapePgLikePattern(needleLiteral));
              return params.length;
            })()
          : tokenIdxs[0]!;

      // Vendor/product: AND across tokens (same CPE row), OR full phrase.
      const vpTokenAnd = tokenIdxs.map((idx) => vpFieldsLikeSql(idx)).join(" AND ");
      const vpPhrase = vpFieldsLikeSql(phraseIdx);
      candidateParts.push(
        `SELECT vp.cve_id FROM cve_vendor_product vp WHERE (${vpTokenAnd}) OR (${vpPhrase})`
      );

      // cve_id substring for each token (OR) + full phrase.
      const cveIdTokenOr = tokenIdxs
        .map((idx) => `lower(c.cve_id) LIKE '%' || $${idx}::text || '%' ESCAPE E'\\\\'`)
        .join(" OR ");
      candidateParts.push(
        `SELECT c.cve_id FROM cve c WHERE (${cveIdTokenOr}) OR lower(c.cve_id) LIKE '%' || $${phraseIdx}::text || '%' ESCAPE E'\\\\'`
      );

      if (cveAnyIdx > 0) {
        candidateParts.push(`SELECT unnest($${cveAnyIdx}::text[]) AS cve_id`);
      }
      if (bduAnyIdx > 0) {
        candidateParts.push(
          `SELECT cb.cve_id FROM cve_bdu_link cb WHERE cb.bdu_id = ANY($${bduAnyIdx}::text[])`
        );
      } else if (/\d{4}-\d/.test(needleLiteral) || /\bbdu\b/.test(needleLiteral)) {
        candidateParts.push(
          `SELECT cb.cve_id FROM cve_bdu_link cb
            WHERE lower(cb.bdu_id) LIKE '%' || $${phraseIdx}::text || '%' ESCAPE E'\\\\'
               OR lower(('bdu:' || cb.bdu_id)::text) LIKE '%' || $${phraseIdx}::text || '%' ESCAPE E'\\\\'`
        );
      }

      // Enrichment / raw: only longer phrases (avoid scanning huge text for "cisco"/"windows").
      const compactNeedle = qLowerForNeedle.replace(/\s+/g, "");
      const allowEnrichmentSearch =
        !shapedCve && (compactNeedle.length >= 10 || (/\s/.test(qLowerForNeedle) && compactNeedle.length >= 8));
      if (allowEnrichmentSearch) {
        candidateParts.push(
          `SELECT ea.cve_id FROM enrichment_ai ea
            WHERE lower(COALESCE(ea.output_text, '')) LIKE '%' || $${phraseIdx}::text || '%' ESCAPE E'\\\\'
               OR lower(COALESCE(ea.output_json->>'summary', '')) LIKE '%' || $${phraseIdx}::text || '%' ESCAPE E'\\\\'
               OR lower(COALESCE(ea.output_json->>'title', '')) LIKE '%' || $${phraseIdx}::text || '%' ESCAPE E'\\\\'`
        );
      }
      const allowRawTextSearch =
        compactNeedle.length >= 12 && !shapedCve && /\s/.test(qLowerForNeedle);
      if (allowRawTextSearch) {
        candidateParts.push(
          `SELECT c.cve_id FROM cve c WHERE lower(c.raw::text) LIKE '%' || $${phraseIdx}::text || '%' ESCAPE E'\\\\'`
        );
      }

      const filterSql = filters.length > 0 ? `AND ${filters.join(" AND ")}` : "";

      const searchOrderByRanked =
        `ORDER BY exact_match DESC,\n` +
        `         exploit_known DESC,\n` +
        `         rank_score DESC,\n` +
        `         published_at DESC NULLS LAST,\n` +
        `         cve_id ASC`;

      const hydrateOrderBy =
        `ORDER BY r.exact_match DESC,\n` +
        `         r.exploit_known DESC,\n` +
        `         r.rank_score DESC,\n` +
        `         r.published_at DESC NULLS LAST,\n` +
        `         r.cve_id ASC`;

      params.push(limit);
      const limitIdx = params.length;
      params.push(offset);
      const offsetIdx = params.length;

      const rankEaJoin =
        vulnClasses.length > 0
          ? `
      ${SQL_CVE_LIST_EA_LATERAL}`
          : "";

      const rankedSelect = `SELECT c.cve_id,
                ${exactMatchExpr} AS exact_match,
                (k.cve_id IS NOT NULL) AS exploit_known,
                ${rankExpr} AS rank_score,
                c.published_at
           FROM candidates cand
           JOIN cve c ON c.cve_id = cand.cve_id
      ${rankEaJoin}
      LEFT JOIN epss_score es ON es.cve_id = c.cve_id
      LEFT JOIN kev k ON k.cve_id = c.cve_id
      ${SQL_EXPLOIT_INTEL_JOIN}`;

      const useUnionExact =
        isExactCveQuery &&
        (filters.length > 0 || view === "last24h" || view === "last_24h" || view === "last-24h");

      const candidatesCte = `candidates AS (
            ${candidateParts.join("\n            UNION\n            ")}
          )`;

      const rankedCte = useUnionExact
        ? `ranked AS (
            SELECT * FROM (
              SELECT c.cve_id,
                     TRUE AS exact_match,
                     (k.cve_id IS NOT NULL) AS exploit_known,
                     ${rankExpr} AS rank_score,
                     c.published_at
                FROM cve c
           LEFT JOIN epss_score es ON es.cve_id = c.cve_id
           LEFT JOIN kev k ON k.cve_id = c.cve_id
           ${SQL_EXPLOIT_INTEL_JOIN}
               WHERE ${exactCond} ${filterSql}
              UNION ALL
              ${rankedSelect}
               WHERE NOT (${exactCond}) ${filterSql}
            ) u
            ${searchOrderByRanked}
            LIMIT $${limitIdx} OFFSET $${offsetIdx}
          )`
        : `ranked AS (
            ${rankedSelect}
            WHERE TRUE ${filterSql}
            ${searchOrderByRanked}
            LIMIT $${limitIdx} OFFSET $${offsetIdx}
          )`;

      const sql = `WITH ${candidatesCte},
          ${rankedCte}
          SELECT ${SQL_CVE_LIST_SELECT},
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
           FROM ranked r
           JOIN cve c ON c.cve_id = r.cve_id
      ${SQL_CVE_LIST_VP_LATERAL}
      ${SQL_CVE_LIST_EA_LATERAL}
      ${SQL_CVE_LIST_SCORE_JOINS}
          ${hydrateOrderBy}`;

      let r = await this.db.query(sql, params);
      if (r.rows.length === 0 && isExactCveQuery) {
        const imported = await this.nvdImport.importByCveId(qTrim);
        if (imported) r = await this.db.query(sql, params);
      }
      return { items: r.rows, total: null };
    }

    const where = filters.length > 0 ? `WHERE ${filters.join(" AND ")}` : `WHERE TRUE`;
    const listOrderBy =
      view === "critical_v2" || view === "critical-v2" || view === "criticalv2"
        ? criticalV2OrderBy
        : orderBy;
    const rankEaJoin =
      vulnClasses.length > 0
        ? `
      ${SQL_CVE_LIST_EA_LATERAL}`
        : "";
    const fromRanked = `FROM cve c
       ${rankEaJoin}
      LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
      LEFT JOIN epss_score es ON es.cve_id = c.cve_id
      LEFT JOIN kev k ON k.cve_id = c.cve_id
      ${SQL_EXPLOIT_INTEL_JOIN}
         ${where}`;
    let total: number | null = null;
    if (includeTotal) {
      const counted = await this.db.query<{ n: number }>(`SELECT count(DISTINCT c.cve_id)::int AS n ${fromRanked}`, params);
      total = counted.rows[0]?.n ?? 0;
    }
    params.push(limit);
    const limitIdx = params.length;
    params.push(offset);
    const offsetIdx = params.length;

    const r = await this.db.query(
      `WITH ranked AS (
          SELECT c.cve_id
            FROM cve c
       ${rankEaJoin}
      LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
      LEFT JOIN epss_score es ON es.cve_id = c.cve_id
      LEFT JOIN kev k ON k.cve_id = c.cve_id
      ${SQL_EXPLOIT_INTEL_JOIN}
         ${where}
         ${listOrderBy}
            LIMIT $${limitIdx} OFFSET $${offsetIdx}
        )
        SELECT ${SQL_CVE_LIST_SELECT},
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
         FROM ranked r
         JOIN cve c ON c.cve_id = r.cve_id
    ${SQL_CVE_LIST_VP_LATERAL}
    ${SQL_CVE_LIST_EA_LATERAL}
    ${SQL_CVE_LIST_SCORE_JOINS}
         ${listOrderBy}`,
      params
    );
    return { items: r.rows, total };
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

  /** Одна карточка: DeepSeek по открытым материалам этой CVE. Очередь каталога не стартует. */
  @Post(":cveId/ai")
  @HttpCode(200)
  aiOne(@Param("cveId") cveId: string) {
    return this.pointAi.enrichOne(cveId);
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

    const kevRow = await this.db.query<{
      date_added: Date | string | null;
      due_date: Date | string | null;
      required_action: string | null;
      ransomware_use: string | null;
      vulnerability_name: string | null;
    }>(
      `SELECT date_added, due_date, required_action, ransomware_use, vulnerability_name
         FROM kev WHERE cve_id = $1 LIMIT 1`,
      [cveId]
    );

    const bduRows = await this.db.query<{
      bdu_id: string;
      name: string | null;
      solution: string | null;
      exploit_status: string | null;
      fix_status: string | null;
      has_exploit: boolean;
      has_fix: boolean;
    }>(
      `SELECT b.bdu_id, b.name, b.solution, b.exploit_status, b.fix_status, b.has_exploit, b.has_fix
         FROM cve_bdu_link l
         JOIN bdu_vuln b ON b.bdu_id = l.bdu_id
        WHERE l.cve_id = $1
        ORDER BY b.bdu_id
        LIMIT 8`,
      [cveId]
    );

    const contextFacts = await this.db.query<{
      source: string;
      fact_type: string;
      title: string | null;
      detail: string | null;
      url: string | null;
      updated_at: Date | null;
    }>(
      `SELECT source, fact_type, title, detail, url, updated_at
         FROM cve_context_fact
        WHERE cve_id = $1
        ORDER BY source, fact_type`,
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
      kev: kevRow.rows[0]
        ? {
            dateAdded: dayStamp(kevRow.rows[0].date_added),
            dueDate: dayStamp(kevRow.rows[0].due_date),
            requiredAction: kevRow.rows[0].required_action,
            ransomwareUse: kevRow.rows[0].ransomware_use,
            name: kevRow.rows[0].vulnerability_name
          }
        : null,
      bdu: bduRows.rows.map((row) => ({
        id: row.bdu_id,
        name: row.name,
        solution: clipText(row.solution, 500),
        exploitStatus: row.exploit_status,
        fixStatus: row.fix_status,
        hasExploit: row.has_exploit,
        hasFix: row.has_fix
      })),
      contextFacts: contextFacts.rows.map((row) => ({
        source: row.source,
        factType: row.fact_type,
        title: row.title,
        detail: clipText(row.detail, 800),
        url: row.url,
        updatedAt: row.updated_at ? new Date(row.updated_at).toISOString() : null
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


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
  bduFstecUrl,
  isMatureEnrichmentForTextEngine,
  normalizeBduId,
  resolveBduCardEnrichment,
  sqlBduFstecAttentionWithinHours,
  type TextEngineMode
} from "@vuln-intel/shared";
import { BduEnrichRunnerService } from "../services/bdu-enrich-runner.service.js";
import { DbService } from "../services/db.service.js";
import { IntegrationSettingsService } from "../services/integration-settings.service.js";
import { escapePgLikePattern } from "../pg-like.util.js";

type EnrichmentBduQueryRow = {
  model?: string;
  prompt_version?: string;
  output_json: unknown;
  output_text: string | null;
  created_at?: Date;
};

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

const ENRICHMENT_BDU_RECENT_LIMIT = 20;

function pickAiPayloadForGet(rows: EnrichmentBduQueryRow[]): EnrichmentBduQueryRow | null {
  if (!rows.length) return null;
  const normalized = rows.map(normalizeEnrichmentOutputJson);
  const successes = normalized.filter((r) =>
    isMatureEnrichmentForTextEngine(r, "baseline")
  );
  if (successes.length > 0) return successes[0] ?? null;
  return null;
}

function pickRowForEnrichCacheHit(
  rows: EnrichmentBduQueryRow[],
  textEngine: TextEngineMode = "baseline"
): EnrichmentBduQueryRow | null {
  if (!rows.length) return null;
  const normalized = rows.map(normalizeEnrichmentOutputJson);
  return normalized.find((r) => isMatureEnrichmentForTextEngine(r, textEngine)) ?? null;
}

type BduRow = {
  bdu_id: string;
  name: string;
  description: string | null;
  software_names: string | null;
  vendors: string | null;
  cve_ids: string[];
  severity: string | null;
  severity_level: number;
  cvss_score: number | null;
  cvss_vector: string | null;
  identify_date: string | null;
  publication_date: string | null;
  last_upd_date: string | null;
  identify_year: number | null;
  solution: string | null;
  status: string | null;
  exploit_status: string | null;
  fix_status: string | null;
  has_exploit: boolean;
  has_fix: boolean;
  sources: string | null;
  fstec_url: string;
  updated_at: Date;
};

function mapBduRow(row: BduRow, linkedCveIds?: string[]) {
  const cveIds = row.cve_ids ?? [];
  const linked = linkedCveIds ?? [];
  return {
    bduId: row.bdu_id,
    name: row.name,
    description: row.description,
    softwareNames: row.software_names,
    vendors: row.vendors,
    cveIds,
    linkedCveIds: linked,
    severity: row.severity,
    severityLevel: row.severity_level,
    cvssScore: row.cvss_score,
    cvssVector: row.cvss_vector,
    identifyDate: row.identify_date,
    publicationDate: row.publication_date,
    lastUpdDate: row.last_upd_date,
    identifyYear: row.identify_year,
    solution: row.solution,
    status: row.status,
    exploitStatus: row.exploit_status,
    fixStatus: row.fix_status,
    hasExploit: row.has_exploit,
    hasFix: row.has_fix,
    sources: row.sources,
    fstecUrl: row.fstec_url || bduFstecUrl(row.bdu_id),
    updatedAt: new Date(row.updated_at).toISOString()
  };
}

function parseBduSearch(qRaw: string): { bduIds: string[]; needle: string } {
  const qTrim = qRaw.trim();
  const norm = qTrim.toLowerCase().replace(/бду/g, "bdu");
  const bduIds = new Set<string>();
  for (const m of norm.matchAll(/bdu\s*:\s*(\d{4}-\d+)/gi)) {
    const id = m[1];
    if (id) bduIds.add(id);
  }
  const bare = norm.match(/^\s*(\d{4}-\d+)\s*$/);
  if (bare?.[1] && !/^\s*cve-/i.test(qTrim)) bduIds.add(bare[1]);
  const fromNorm = normalizeBduId(qTrim);
  if (fromNorm) bduIds.add(fromNorm);
  return { bduIds: [...bduIds], needle: norm };
}

@Controller("bdu")
export class BduController {
  constructor(
    private readonly db: DbService,
    private readonly enrichRunner: BduEnrichRunnerService,
    private readonly integration: IntegrationSettingsService
  ) {}

  @Post("lookup")
  @HttpCode(200)
  async lookup(@Body() body: { bduIds?: unknown }) {
    const raw = body?.bduIds;
    const arr = Array.isArray(raw) ? raw : [];
    const ids = [
      ...new Set(
        arr
          .map((x) => normalizeBduId(String(x ?? "")))
          .filter((x): x is string => Boolean(x))
      )
    ].slice(0, 500);
    if (ids.length === 0) return { items: [] };

    const r = await this.db.query<BduRow>(
      `SELECT bdu_id, name, description, software_names, vendors, cve_ids,
              severity, severity_level, cvss_score, cvss_vector,
              identify_date, publication_date, last_upd_date, identify_year,
              solution, status, exploit_status, fix_status, has_exploit, has_fix, sources, fstec_url, updated_at
         FROM bdu_vuln
        WHERE bdu_id = ANY($1::text[])`,
      [ids]
    );

    const linkedByBdu = await this.linkedCvesForBdu(ids);
    return {
      items: r.rows.map((row) => mapBduRow(row, linkedByBdu.get(row.bdu_id) ?? []))
    };
  }

  @Get()
  async list(
    @Query("limit") limitRaw?: string,
    @Query("offset") offsetRaw?: string,
    @Query("q") qRaw?: string,
    @Query("recentDays") recentDaysRaw?: string,
    @Query("publishedLast24h") publishedLast24hRaw?: string,
    @Query("unlinkedOnly") unlinkedOnlyRaw?: string,
    @Query("urgentOnly") urgentOnlyRaw?: string,
    @Query("minLinkedEpss") minLinkedEpssRaw?: string,
    @Query("minCvss") minCvssRaw?: string
  ) {
    const limit = Math.max(1, Math.min(100, Number(limitRaw ?? 30)));
    const offset = Math.max(0, Number(offsetRaw ?? 0));
    const q = qRaw?.trim() || null;
    const recentDays = Math.max(0, Math.min(365, Number(recentDaysRaw ?? 0)));
    const publishedLast24h =
      publishedLast24hRaw === "true" || publishedLast24hRaw === "1" || publishedLast24hRaw === "yes";
    const unlinkedOnly = unlinkedOnlyRaw === "true" || unlinkedOnlyRaw === "1";
    const urgentOnly = urgentOnlyRaw === "true" || urgentOnlyRaw === "1" || urgentOnlyRaw === "yes";
    const minLinkedEpss = Number.isFinite(Number(minLinkedEpssRaw)) ? Number(minLinkedEpssRaw) : 0.5;
    const minCvss = Number.isFinite(Number(minCvssRaw)) ? Number(minCvssRaw) : 9.0;

    const params: unknown[] = [];
    const where: string[] = [];
    let urgentEpssParamIdx = 0;
    let urgentCvssParamIdx = 0;

    if (publishedLast24h) {
      const windowHours = Math.max(
        1,
        Math.min(168, Number(process.env.BDU_ATTENTION_WINDOW_HOURS ?? 24))
      );
      where.push(sqlBduFstecAttentionWithinHours("b", windowHours));
    }

    if (urgentOnly) {
      params.push(minLinkedEpss);
      urgentEpssParamIdx = params.length;
      params.push(minCvss);
      urgentCvssParamIdx = params.length;
      where.push(`(
        b.has_exploit = true
        OR (b.cvss_score IS NOT NULL AND b.cvss_score >= $${urgentCvssParamIdx})
        OR EXISTS (
          SELECT 1
            FROM cve c_u
       LEFT JOIN epss_score es_u ON es_u.cve_id = c_u.cve_id
       LEFT JOIN kev k_u ON k_u.cve_id = c_u.cve_id
           WHERE (k_u.cve_id IS NOT NULL OR es_u.score >= $${urgentEpssParamIdx} OR c_u.cvss_base >= $${urgentCvssParamIdx})
             AND (
               c_u.cve_id = ANY(b.cve_ids)
               OR EXISTS (
                 SELECT 1 FROM cve_bdu_link l_u
                  WHERE l_u.bdu_id = b.bdu_id
                    AND l_u.cve_id = c_u.cve_id
               )
             )
        )
      )`);
    }

    if (recentDays > 0) {
      params.push(recentDays);
      where.push(
        `(b.identify_year >= EXTRACT(YEAR FROM now())::int - 1 OR b.updated_at >= now() - ($${params.length}::int || ' days')::interval)`
      );
    }

    if (unlinkedOnly) {
      where.push(`NOT EXISTS (
        SELECT 1 FROM cve_bdu_link l WHERE l.bdu_id = b.bdu_id
      )`);
    }

    if (q) {
      const { bduIds, needle } = parseBduSearch(q);
      if (bduIds.length > 0) {
        params.push(bduIds);
        where.push(`b.bdu_id = ANY($${params.length}::text[])`);
      } else if (needle.length > 0) {
        params.push(`%${escapePgLikePattern(needle)}%`);
        const idx = params.length;
        where.push(`(
          lower(b.bdu_id) LIKE $${idx}
          OR lower(b.name) LIKE $${idx}
          OR lower(COALESCE(b.description, '')) LIKE $${idx}
          OR lower(COALESCE(b.vendors, '')) LIKE $${idx}
          OR lower(COALESCE(b.software_names, '')) LIKE $${idx}
          OR EXISTS (
            SELECT 1 FROM unnest(b.cve_ids) c WHERE lower(c) LIKE $${idx}
          )
        )`);
      }
    }

    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    params.push(limit, offset);
    const limitIdx = params.length - 1;
    const offsetIdx = params.length;

    const r = await this.db.query<BduRow>(
      `SELECT b.bdu_id, b.name, b.description, b.software_names, b.vendors, b.cve_ids,
              b.severity, b.severity_level, b.cvss_score, b.cvss_vector,
              b.identify_date, b.publication_date, b.last_upd_date, b.identify_year,
              b.solution, b.status, b.exploit_status, b.fix_status, b.has_exploit, b.has_fix, b.sources, b.fstec_url, b.updated_at
         FROM bdu_vuln b
         ${whereSql}
         ORDER BY
           ${
             urgentOnly
               ? `(
             SELECT max(
               (CASE WHEN k_o.cve_id IS NOT NULL THEN 1.0 ELSE 0.0 END)
               + COALESCE(es_o.score, 0)
               + (COALESCE(c_o.cvss_base, 0) / 10.0)
             )
               FROM cve c_o
          LEFT JOIN epss_score es_o ON es_o.cve_id = c_o.cve_id
          LEFT JOIN kev k_o ON k_o.cve_id = c_o.cve_id
              WHERE (k_o.cve_id IS NOT NULL OR es_o.score >= $${urgentEpssParamIdx} OR c_o.cvss_base >= $${urgentCvssParamIdx})
                AND (
                  c_o.cve_id = ANY(b.cve_ids)
                  OR EXISTS (
                    SELECT 1 FROM cve_bdu_link l_o
                     WHERE l_o.bdu_id = b.bdu_id
                       AND l_o.cve_id = c_o.cve_id
                  )
                )
           ) DESC NULLS LAST,`
               : ""
           }
           CASE
             WHEN b.publication_date ~ '^\\d{2}\\.\\d{2}\\.\\d{4}$'
               THEN to_timestamp(b.publication_date, 'DD.MM.YYYY')
             ELSE NULL
           END DESC NULLS LAST,
           b.cvss_score DESC NULLS LAST,
           b.bdu_id DESC
         LIMIT $${limitIdx} OFFSET $${offsetIdx}`,
      params
    );

    const ids = r.rows.map((x) => x.bdu_id);
    const linkedByBdu = await this.linkedCvesForBdu(ids);

    return {
      items: r.rows.map((row) => mapBduRow(row, linkedByBdu.get(row.bdu_id) ?? [])),
      limit,
      offset
    };
  }

  @Post(":bduId/enrich")
  async requestEnrich(@Param("bduId") bduIdRaw: string, @Query("force") force?: string) {
    if (process.env.ALLOW_MANUAL_ENRICH === "false") {
      throw new ForbiddenException(
        "On-demand AI enrichment is disabled. Set ALLOW_MANUAL_ENRICH=true (or unset) to enable POST /bdu/:id/enrich."
      );
    }
    const bduId = normalizeBduId(bduIdRaw);
    if (!bduId) throw new NotFoundException();
    const exists = await this.db.query(`SELECT 1 FROM bdu_vuln WHERE bdu_id = $1`, [bduId]);
    if ((exists.rowCount ?? 0) === 0) throw new NotFoundException();

    const forceOn = force === "1" || force === "true" || force === "yes";
    const textEngine = await this.integration.getTextEngineSettings();
    if (textEngine.textEngine !== "llm") {
      const res = await this.enrichRunner.enrichNow(bduId, {
        force: forceOn,
        allowOutsideHotWindow: true
      });
      return {
        ok: Boolean(res) || !forceOn,
        queued: false,
        cached: !res && !forceOn,
        status: res ? ("ready" as const) : forceOn ? ("failed" as const) : ("cached" as const),
        textEngine: textEngine.textEngine,
        output_json: res?.outputJson ?? null,
        output_text: res?.outputText ?? null
      };
    }
    const latestAi = await this.db.query<EnrichmentBduQueryRow>(
      `SELECT model, prompt_version, output_json, output_text, created_at
         FROM enrichment_bdu
        WHERE bdu_id = $1
     ORDER BY created_at DESC
        LIMIT ${ENRICHMENT_BDU_RECENT_LIMIT}`,
      [bduId]
    );
    if (!forceOn && pickRowForEnrichCacheHit(latestAi.rows, textEngine.textEngine) != null) {
      return { ok: true, queued: false, cached: true };
    }
    this.enrichRunner.scheduleEnrich(bduId, { force: forceOn, allowOutsideHotWindow: true });
    return { ok: true, queued: true, cached: false };
  }

  @Get(":bduId")
  async detail(@Param("bduId") bduIdRaw: string) {
    const bduId = normalizeBduId(bduIdRaw);
    if (!bduId) throw new NotFoundException();
    const r = await this.db.query<BduRow>(
      `SELECT bdu_id, name, description, software_names, vendors, cve_ids,
              severity, severity_level, cvss_score, cvss_vector,
              identify_date, publication_date, last_upd_date, identify_year,
              solution, status, exploit_status, fix_status, has_exploit, has_fix, sources, fstec_url, updated_at
         FROM bdu_vuln WHERE bdu_id = $1`,
      [bduId]
    );
    const row = r.rows[0];
    if (!row) return { found: false };
    const linked = await this.linkedCvesForBdu([bduId]);
    const linkedIds = linked.get(bduId) ?? [];

    const ai = await this.db.query<EnrichmentBduQueryRow>(
      `SELECT model, prompt_version, output_json, output_text, created_at
         FROM enrichment_bdu
        WHERE bdu_id = $1
     ORDER BY created_at DESC
        LIMIT ${ENRICHMENT_BDU_RECENT_LIMIT}`,
      [bduId]
    );
    const aiPayloadRaw = pickAiPayloadForGet(ai.rows);
    const fstecUrl = row.fstec_url || bduFstecUrl(row.bdu_id);

    let linkedCveRaw: unknown = null;
    const primaryLinked = linkedIds[0] ?? null;
    if (primaryLinked) {
      const rawR = await this.db.query<{ raw: unknown }>(
        `SELECT raw FROM cve WHERE cve_id = $1 LIMIT 1`,
        [primaryLinked]
      );
      linkedCveRaw = rawR.rows[0]?.raw ?? null;
    }

    const resolvedJson = resolveBduCardEnrichment(
      aiPayloadRaw?.output_json ?? null,
      bduId,
      {
        name: row.name,
        description: row.description,
        solution: row.solution,
        software_names: row.software_names,
        severity: row.severity,
        exploit_status: row.exploit_status,
        has_exploit: row.has_exploit
      },
      linkedCveRaw
    );

    const textEngine = await this.integration.getTextEngineSettings();
    return {
      found: true,
      bdu: mapBduRow(row, linkedIds),
      textEngine: textEngine.textEngine,
      linkedCveRaw,
      links: {
        fstec: fstecUrl,
        cves: linkedIds.map((cveId) => ({
          cveId,
          nvd: `https://nvd.nist.gov/vuln/detail/${cveId}`
        }))
      },
      ai: {
        model: aiPayloadRaw?.model ?? "bdu-baseline",
        prompt_version: aiPayloadRaw?.prompt_version ?? "v1",
        output_json: resolvedJson,
        output_text:
          aiPayloadRaw?.output_text ??
          (typeof resolvedJson.summary === "string" ? resolvedJson.summary : null),
        created_at: aiPayloadRaw?.created_at
          ? new Date(aiPayloadRaw.created_at).toISOString()
          : null
      }
    };
  }

  private async linkedCvesForBdu(bduIds: string[]): Promise<Map<string, string[]>> {
    const out = new Map<string, string[]>();
    if (bduIds.length === 0) return out;
    const r = await this.db.query<{ bdu_id: string; cve_id: string }>(
      `SELECT l.bdu_id, l.cve_id
         FROM cve_bdu_link l
        WHERE l.bdu_id = ANY($1::text[])
        ORDER BY l.cve_id`,
      [bduIds]
    );
    for (const row of r.rows) {
      const prev = out.get(row.bdu_id) ?? [];
      prev.push(row.cve_id);
      out.set(row.bdu_id, prev);
    }
    return out;
  }
}

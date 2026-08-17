import { computeUnifiedRiskScoreV2, type RiskScoreFactors } from "./scoring.js";
import {
  isAiScoreEnabled,
  shouldScoreViaQueue,
  type ScoreRequestedEnvelope
} from "../queue/score-request.js";
import { SQL_EFFECTIVE_PUBLISHED_AT } from "../cve/published-window.js";

export type RiskScoreDbQueryable = {
  query(
    sql: string,
    params?: unknown[]
  ): Promise<{ rows: unknown[]; rowCount?: number | null }>;
};

export type RiskScoreInputHints = {
  cvss?: number;
  epss?: number;
  exploitKnown?: boolean;
  publishedAt?: string;
  mentions?: number;
};

export type RiskScoreLoadedInputs = {
  cvss?: number;
  epss?: number;
  exploitKnown?: boolean;
  vckevOnly?: boolean;
  vulncheckKev?: boolean;
  epssSpike?: boolean;
  hasPoc?: boolean;
  hasPublicExploit?: boolean;
  tgMentions24h?: number;
  publishedAt?: string;
  mentions?: number;
};

export type UpsertRiskScoreResult = {
  cveId: string;
  score: number;
  modelVersion: string;
  factors: RiskScoreFactors;
};

/**
 * Rabbit `ai.score` is legacy/opt-in. Default path writes `risk_score` inline in ingest/API.
 * Gate: `shouldScoreViaQueue` in `queue/score-request.ts`.
 */

export function extractCvssBaseScoreFromNvdRaw(raw: unknown): number | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const metrics = (raw as Record<string, unknown>).metrics;
  if (!metrics || typeof metrics !== "object" || Array.isArray(metrics)) return undefined;
  const candidates: unknown[] = [];
  for (const k of Object.keys(metrics as Record<string, unknown>)) {
    const v = (metrics as Record<string, unknown>)[k];
    if (Array.isArray(v)) candidates.push(...v);
  }
  for (const c of candidates) {
    const score = (c as { cvssData?: { baseScore?: unknown } })?.cvssData?.baseScore;
    if (typeof score === "number" && score >= 0 && score <= 10) return score;
  }
  return undefined;
}

export async function loadRiskScoreInputs(
  db: RiskScoreDbQueryable,
  cveId: string,
  hints: RiskScoreInputHints = {}
): Promise<RiskScoreLoadedInputs> {
  const out: RiskScoreLoadedInputs = { ...hints };

  if (out.publishedAt == null || out.cvss == null) {
    const cve = await db.query(
      `SELECT raw, published_at FROM cve WHERE cve_id = $1 LIMIT 1`,
      [cveId]
    );
    const row = cve.rows[0] as { raw: unknown; published_at: Date | null } | undefined;
    if (row) {
      if (out.publishedAt == null && row.published_at) {
        out.publishedAt =
          row.published_at instanceof Date
            ? row.published_at.toISOString()
            : new Date(row.published_at).toISOString();
      }
      if (out.cvss == null) out.cvss = extractCvssBaseScoreFromNvdRaw(row.raw);
    }
  }

  if (out.epss == null) {
    const epss = await db.query(`SELECT score FROM epss_score WHERE cve_id = $1 LIMIT 1`, [cveId]);
    const row = epss.rows[0] as { score: number } | undefined;
    if (row) out.epss = Number(row.score);
  }

  if (out.exploitKnown == null) {
    const kev = await db.query(`SELECT cve_id FROM kev WHERE cve_id = $1 LIMIT 1`, [cveId]);
    if ((kev.rowCount ?? 0) > 0) out.exploitKnown = true;
  }

  const intel = await db.query(
    `SELECT COALESCE(vckev_only, false) AS vckev_only,
            COALESCE(vulncheck_kev, false) AS vulncheck_kev,
            COALESCE(epss_spike, false) AS epss_spike,
            COALESCE(has_poc, false) AS has_poc,
            COALESCE(has_public_exploit, false) AS has_public_exploit,
            COALESCE(tg_mentions_24h, 0)::int AS tg_mentions_24h
       FROM cve_exploit_intel WHERE cve_id = $1 LIMIT 1`,
    [cveId]
  );
  const intelRow = intel.rows[0] as
    | {
        vckev_only: boolean;
        vulncheck_kev: boolean;
        epss_spike: boolean;
        has_poc: boolean;
        has_public_exploit: boolean;
        tg_mentions_24h: number;
      }
    | undefined;
  if (intelRow) {
    out.vckevOnly = intelRow.vckev_only;
    out.vulncheckKev = intelRow.vulncheck_kev;
    out.epssSpike = intelRow.epss_spike;
    out.hasPoc = intelRow.has_poc;
    out.hasPublicExploit = intelRow.has_public_exploit;
    out.tgMentions24h = intelRow.tg_mentions_24h;
    if (out.exploitKnown == null && intelRow.vckev_only) out.exploitKnown = false;
  }

  return out;
}

export async function upsertRiskScoreForCve(
  db: RiskScoreDbQueryable,
  cveId: string,
  hints: RiskScoreInputHints = {}
): Promise<UpsertRiskScoreResult> {
  const loaded = await loadRiskScoreInputs(db, cveId, hints);
  const publishedAt = loaded.publishedAt ? new Date(loaded.publishedAt) : undefined;
  const computed = computeUnifiedRiskScoreV2({
    cvss: loaded.cvss,
    epss: loaded.epss,
    exploitKnown: loaded.exploitKnown,
    vckevOnly: loaded.vckevOnly,
    vulncheckKev: loaded.vulncheckKev,
    epssSpike: loaded.epssSpike,
    hasPoc: loaded.hasPoc,
    hasPublicExploit: loaded.hasPublicExploit,
    mentions: loaded.mentions,
    tgMentions24h: loaded.tgMentions24h,
    publishedAt: publishedAt && !Number.isNaN(publishedAt.getTime()) ? publishedAt : undefined
  });

  await db.query(
    `INSERT INTO risk_score(cve_id, score, factors, model_version, computed_at)
     VALUES ($1,$2,$3,$4,now())
     ON CONFLICT (cve_id)
     DO UPDATE SET score = EXCLUDED.score,
                   factors = EXCLUDED.factors,
                   model_version = EXCLUDED.model_version,
                   computed_at = now()`,
    [cveId, computed.score, JSON.stringify(computed.factors), computed.modelVersion]
  );

  return {
    cveId,
    score: computed.score,
    modelVersion: computed.modelVersion,
    factors: computed.factors
  };
}

/**
 * Batch upsert with bounded concurrency. Skips empty ids. Continues on per-CVE errors
 * (logs via optional onError); returns successful count.
 */
export async function upsertRiskScoresForCveIds(
  db: RiskScoreDbQueryable,
  cveIds: string[],
  opts?: {
    concurrency?: number;
    hintsFor?: (cveId: string) => RiskScoreInputHints | undefined;
    onError?: (cveId: string, err: unknown) => void;
  }
): Promise<number> {
  const ids = [...new Set(cveIds.map((id) => id.trim()).filter(Boolean))];
  if (!ids.length) return 0;
    const concurrency = Math.max(1, Math.min(64, opts?.concurrency ?? 48));
  let ok = 0;
  let idx = 0;

  async function worker() {
    while (idx < ids.length) {
      const i = idx++;
      const cveId = ids[i]!;
      try {
        await upsertRiskScoreForCve(db, cveId, opts?.hintsFor?.(cveId) ?? {});
        ok++;
      } catch (err) {
        opts?.onError?.(cveId, err);
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, ids.length) }, () => worker()));
  return ok;
}

/** Inline by default; Rabbit only when AI_SCORE_VIA_QUEUE=true and publish is provided. */
export async function applyRiskScoresForCveIds(
  db: RiskScoreDbQueryable,
  cveIds: string[],
  opts?: {
    concurrency?: number;
    hintsFor?: (cveId: string) => RiskScoreInputHints | undefined;
    onError?: (cveId: string, err: unknown) => void;
    /** Legacy queue path — required when shouldScoreViaQueue(). */
    publishViaQueue?: (events: ScoreRequestedEnvelope[]) => number;
    buildQueueEvents?: () => Promise<ScoreRequestedEnvelope[]>;
  }
): Promise<number> {
  if (!isAiScoreEnabled() || !cveIds.length) return 0;
  if (shouldScoreViaQueue()) {
    if (!opts?.buildQueueEvents || !opts.publishViaQueue) return 0;
    const events = await opts.buildQueueEvents();
    return opts.publishViaQueue(events);
  }
  return upsertRiskScoresForCveIds(db, cveIds, {
    concurrency: opts?.concurrency,
    hintsFor: opts?.hintsFor,
    onError: opts?.onError
  });
}

/** True when any catalog CVE is missing rule_v2 or scored before the EPSS feed date. */
export async function catalogRiskScoresLagFeedDate(
  db: RiskScoreDbQueryable,
  scoreDate: string
): Promise<boolean> {
  const r = await db.query(
    `SELECT EXISTS (
       SELECT 1
         FROM cve c
         LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
        WHERE rs.cve_id IS NULL
           OR rs.computed_at::date < $1::date
           OR rs.model_version IS DISTINCT FROM 'rule_v2'
     ) AS stale`,
    [scoreDate]
  );
  const row = r.rows[0] as { stale?: boolean } | undefined;
  return Boolean(row?.stale);
}

/**
 * After daily EPSS (and for freshness decay): rewrite `risk_score` for the whole CVE catalog
 * with the same rule_v2 weights as computeUnifiedRiskScoreV2. One SQL pass, no per-CVE cap.
 */
export async function rescoreCatalogRiskScores(db: RiskScoreDbQueryable): Promise<number> {
  if (!isAiScoreEnabled()) return 0;
  const r = await db.query(
    `INSERT INTO risk_score (cve_id, score, factors, model_version, computed_at)
     SELECT s.cve_id, s.score, s.factors, 'rule_v2', now()
       FROM (
         SELECT
           c.cve_id,
           ROUND(
             LEAST(100, GREATEST(0,
               (
                 0.36 * cvss_n
                 + 0.22 * epss_n
                 + 0.18 * exploit_n
                 + 0.06 * CASE WHEN epss_spike THEN 1.0 ELSE 0.0 END
                 + 0.08 * freshness_n
                 + 0.10 * mentions_n
                 + CASE
                     WHEN (exploit_known OR vckev_only) AND cvss_base IS NOT NULL AND cvss_base >= 9 THEN 0.08
                     WHEN epss_spike AND exploit_n >= 0.55 THEN 0.05
                     ELSE 0
                   END
               ) * 100
             ))
           )::int AS score,
           jsonb_strip_nulls(jsonb_build_object(
             'cvss', cvss_base,
             'epss', epss,
             'exploitKnown', exploit_known,
             'vckevOnly', vckev_only,
             'vulncheckKev', vulncheck_kev,
             'epssSpike', epss_spike,
             'hasPoc', has_poc,
             'hasPublicExploit', has_public_exploit,
             'mentions', tg_mentions,
             'tgMentions24h', tg_mentions,
             'freshnessDays', freshness_days
           )) AS factors
         FROM (
           SELECT
             c.cve_id,
             c.cvss_base,
             (k.cve_id IS NOT NULL) AS exploit_known,
             COALESCE(ei.vckev_only, false) AS vckev_only,
             COALESCE(ei.vulncheck_kev, vk.cve_id IS NOT NULL) AS vulncheck_kev,
             COALESCE(ei.has_poc, false) AS has_poc,
             COALESCE(ei.has_public_exploit, false) AS has_public_exploit,
             COALESCE(ei.tg_mentions_24h, 0) AS tg_mentions,
             CASE
               WHEN e.score IS NOT NULL AND (
                 (hist.score IS NULL AND e.score >= 0.15)
                 OR (hist.score IS NOT NULL AND hist.score > 0 AND e.score / hist.score >= 3)
                 OR (hist.score IS NOT NULL AND e.score - hist.score >= 0.15)
               ) THEN true
               ELSE COALESCE(ei.epss_spike, false)
             END AS epss_spike,
             LEAST(1::double precision, GREATEST(0::double precision,
               CASE WHEN c.cvss_base IS NULL THEN 0.35 ELSE c.cvss_base / 10.0 END
             )) AS cvss_n,
             LEAST(1::double precision, GREATEST(0::double precision,
               CASE WHEN e.score IS NULL THEN 0.15 ELSE e.score END
             )) AS epss_n,
             CASE
               WHEN k.cve_id IS NOT NULL THEN 1.0
               WHEN COALESCE(ei.vckev_only, false) THEN 0.92
               WHEN COALESCE(ei.has_public_exploit, false) THEN 0.88
               WHEN COALESCE(ei.vulncheck_kev, vk.cve_id IS NOT NULL) THEN 0.8
               WHEN COALESCE(ei.has_poc, false) THEN 0.55
               ELSE 0.0
             END AS exploit_n,
             CASE
               WHEN ${SQL_EFFECTIVE_PUBLISHED_AT} IS NULL THEN 0.2
               ELSE LEAST(1::double precision, GREATEST(0::double precision,
                 EXP(-((EXTRACT(EPOCH FROM (now() - ${SQL_EFFECTIVE_PUBLISHED_AT})) / 86400.0) / 180.0))
               ))
             END AS freshness_n,
             CASE
               WHEN ${SQL_EFFECTIVE_PUBLISHED_AT} IS NULL THEN NULL
               ELSE ROUND(EXTRACT(EPOCH FROM (now() - ${SQL_EFFECTIVE_PUBLISHED_AT})) / 86400.0)::int
             END AS freshness_days,
             LEAST(1::double precision, GREATEST(0::double precision,
               LN(COALESCE(ei.tg_mentions_24h, 0) + 1) / LN(10) / 4.0
             )) AS mentions_n,
             e.score AS epss
           FROM cve c
           LEFT JOIN epss_score e ON e.cve_id = c.cve_id
           LEFT JOIN kev k ON k.cve_id = c.cve_id
           LEFT JOIN vulncheck_kev vk ON vk.cve_id = c.cve_id
           LEFT JOIN cve_exploit_intel ei ON ei.cve_id = c.cve_id
           LEFT JOIN LATERAL (
             SELECT h.score
               FROM epss_score_history h
              WHERE h.cve_id = c.cve_id
                AND h.scored_at <= (COALESCE(e.scored_at, CURRENT_DATE) - INTERVAL '7 days')
              ORDER BY h.scored_at DESC
              LIMIT 1
           ) hist ON true
         ) c
       ) s
     ON CONFLICT (cve_id) DO UPDATE SET
       score = EXCLUDED.score,
       factors = EXCLUDED.factors,
       model_version = EXCLUDED.model_version,
       computed_at = now()
     WHERE risk_score.score IS DISTINCT FROM EXCLUDED.score
        OR risk_score.factors IS DISTINCT FROM EXCLUDED.factors
        OR risk_score.model_version IS DISTINCT FROM EXCLUDED.model_version`
  );
  return Number(r.rowCount ?? 0);
}

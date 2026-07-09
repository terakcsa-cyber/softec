import { SQL_EFFECTIVE_PUBLISHED_AT } from "../cve/published-window.js";

export type DbQueryable = {
  query(sql: string, params?: unknown[]): Promise<{ rows: unknown[]; rowCount?: number | null }>;
};

export type Hot24ScoreSweepRow = { cve_id: string };

/** Часовой bucket для idempotency (один прогон sweep в час на CVE). */
export function hot24ScoreHourBucket(now: Date = new Date()): string {
  const hourBucket = new Date(now);
  hourBucket.setMinutes(0, 0, 0);
  return hourBucket.toISOString().slice(0, 13);
}

export function hot24ScoreIdempotencyKey(cveId: string, bucket: string): string {
  return `score:hot24h:${cveId}:${bucket}`;
}

/**
 * CVE из окна 24ч без risk_score или со устаревшим computed_at.
 * Исключает CVE, для которых sweep уже ставил задачу в текущем часовом bucket.
 */
export async function listHot24CvesNeedingScore(
  db: DbQueryable,
  opts?: { limit?: number; staleHours?: number; bucket?: string }
): Promise<Hot24ScoreSweepRow[]> {
  const limit = Math.max(1, Math.min(2000, opts?.limit ?? 500));
  const staleHours = Math.max(0, Math.min(168, opts?.staleHours ?? 6));
  const bucket = opts?.bucket ?? hot24ScoreHourBucket();

  const staleClause =
    staleHours <= 0
      ? "r.cve_id IS NULL"
      : `(r.cve_id IS NULL OR r.computed_at < now() - ($3::text || ' hours')::interval)`;

  const params: unknown[] = [limit, bucket];
  if (staleHours > 0) params.push(String(staleHours));

  const r = await db.query(
    `SELECT c.cve_id
       FROM cve c
  LEFT JOIN risk_score r ON r.cve_id = c.cve_id
      WHERE ${SQL_EFFECTIVE_PUBLISHED_AT} >= now() - interval '24 hours'
        AND ${staleClause}
        AND NOT EXISTS (
          SELECT 1
            FROM idempotency_key k
           WHERE k.scope = 'ai.score'
             AND k.key = ('score:hot24h:' || c.cve_id || ':' || $2::text)
        )
   ORDER BY ${SQL_EFFECTIVE_PUBLISHED_AT} DESC NULLS LAST
      LIMIT $1`,
    params
  );
  return r.rows as Hot24ScoreSweepRow[];
}

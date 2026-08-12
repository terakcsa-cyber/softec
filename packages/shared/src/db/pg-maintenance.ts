/**
 * Periodic Postgres housekeeping: prune unbounded growth tables, then VACUUM (ANALYZE).
 * Prefer regular VACUUM over VACUUM FULL (no exclusive lock / no rewrite thrash).
 */

export type PgMaintenanceDb = {
  query(
    sql: string,
    params?: unknown[]
  ): Promise<{ rows: Array<Record<string, unknown>>; rowCount?: number | null }>;
};

export type PgMaintenanceResult = {
  pruned: {
    auditLog: number;
    idempotencyKey: number;
    refreshToken: number;
    enrichmentAi: number;
  };
  vacuumed: string[];
  dryRun: boolean;
  startedAt: string;
  finishedAt: string;
};

export type PgMaintenanceOptions = {
  dryRun?: boolean;
  /** Keep audit_log rows newer than this many days (default 90). */
  auditRetentionDays?: number;
  /** Keep latest N enrichment_ai rows per cve_id (default 2). */
  enrichmentKeepPerCve?: number;
  /** Delete revoked/expired refresh tokens older than this many days (default 14). */
  refreshTokenRetentionDays?: number;
  /** Run VACUUM (ANALYZE) on hot tables (default true). */
  vacuum?: boolean;
  log?: (msg: string) => void;
};

const HOT_TABLES = [
  "audit_log",
  "idempotency_key",
  "refresh_token",
  "enrichment_ai",
  "risk_score",
  "cve",
  "epss_score"
] as const;

function clampInt(n: number, min: number, max: number, fallback: number): number {
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(n)));
}

export async function runPgMaintenance(
  db: PgMaintenanceDb,
  opts: PgMaintenanceOptions = {}
): Promise<PgMaintenanceResult> {
  const dryRun = opts.dryRun === true;
  const auditDays = clampInt(Number(opts.auditRetentionDays ?? 90), 7, 3650, 90);
  const enrichKeep = clampInt(Number(opts.enrichmentKeepPerCve ?? 2), 1, 20, 2);
  const refreshDays = clampInt(Number(opts.refreshTokenRetentionDays ?? 14), 1, 365, 14);
  const doVacuum = opts.vacuum !== false;
  const log = opts.log ?? (() => undefined);
  const startedAt = new Date().toISOString();

  const pruned = {
    auditLog: 0,
    idempotencyKey: 0,
    refreshToken: 0,
    enrichmentAi: 0
  };

  // --- audit_log ---
  {
    const countR = await db.query(
      `SELECT COUNT(*)::text AS n FROM audit_log WHERE ts < now() - ($1::text || ' days')::interval`,
      [String(auditDays)]
    );
    const n = Number(countR.rows[0]?.n ?? 0);
    if (n > 0) {
      log(`[pg-maint] audit_log prune candidates=${n} retentionDays=${auditDays} dryRun=${dryRun}`);
      if (!dryRun) {
        const del = await db.query(
          `DELETE FROM audit_log WHERE ts < now() - ($1::text || ' days')::interval`,
          [String(auditDays)]
        );
        pruned.auditLog = del.rowCount ?? n;
      } else {
        pruned.auditLog = n;
      }
    }
  }

  // --- idempotency_key (expired) ---
  {
    const countR = await db.query(
      `SELECT COUNT(*)::text AS n
         FROM idempotency_key
        WHERE expires_at IS NOT NULL
          AND expires_at < now()`
    );
    const n = Number(countR.rows[0]?.n ?? 0);
    if (n > 0) {
      log(`[pg-maint] idempotency_key expired=${n} dryRun=${dryRun}`);
      if (!dryRun) {
        const del = await db.query(
          `DELETE FROM idempotency_key WHERE expires_at IS NOT NULL AND expires_at < now()`
        );
        pruned.idempotencyKey = del.rowCount ?? n;
      } else {
        pruned.idempotencyKey = n;
      }
    }
  }

  // --- refresh_token (revoked / expired) ---
  {
    const countR = await db.query(
      `SELECT COUNT(*)::text AS n
         FROM refresh_token
        WHERE (
                revoked_at IS NOT NULL
                AND revoked_at < now() - ($1::text || ' days')::interval
              )
           OR expires_at < now() - ($1::text || ' days')::interval`,
      [String(refreshDays)]
    );
    const n = Number(countR.rows[0]?.n ?? 0);
    if (n > 0) {
      log(`[pg-maint] refresh_token stale=${n} retentionDays=${refreshDays} dryRun=${dryRun}`);
      if (!dryRun) {
        const del = await db.query(
          `DELETE FROM refresh_token
            WHERE (
                    revoked_at IS NOT NULL
                    AND revoked_at < now() - ($1::text || ' days')::interval
                  )
               OR expires_at < now() - ($1::text || ' days')::interval`,
          [String(refreshDays)]
        );
        pruned.refreshToken = del.rowCount ?? n;
      } else {
        pruned.refreshToken = n;
      }
    }
  }

  // --- enrichment_ai history (keep latest N per CVE) ---
  {
    const countR = await db.query(
      `SELECT COUNT(*)::text AS n
         FROM (
           SELECT id
             FROM (
               SELECT id,
                      row_number() OVER (PARTITION BY cve_id ORDER BY created_at DESC NULLS LAST) AS rn
                 FROM enrichment_ai
             ) t
            WHERE rn > $1
         ) x`,
      [enrichKeep]
    );
    const n = Number(countR.rows[0]?.n ?? 0);
    if (n > 0) {
      log(`[pg-maint] enrichment_ai old versions=${n} keepPerCve=${enrichKeep} dryRun=${dryRun}`);
      if (!dryRun) {
        const del = await db.query(
          `DELETE FROM enrichment_ai e
            USING (
              SELECT id
                FROM (
                  SELECT id,
                         row_number() OVER (PARTITION BY cve_id ORDER BY created_at DESC NULLS LAST) AS rn
                    FROM enrichment_ai
                ) t
               WHERE rn > $1
            ) d
            WHERE e.id = d.id`,
          [enrichKeep]
        );
        pruned.enrichmentAi = del.rowCount ?? n;
      } else {
        pruned.enrichmentAi = n;
      }
    }
  }

  const vacuumed: string[] = [];
  if (doVacuum && !dryRun) {
    for (const table of HOT_TABLES) {
      try {
        // Regular VACUUM ANALYZE — safe online; reclaims dead tuples for reuse.
        await db.query(`VACUUM (ANALYZE) ${table}`);
        vacuumed.push(table);
        log(`[pg-maint] VACUUM ANALYZE ${table}`);
      } catch (e) {
        log(
          `[pg-maint] VACUUM skipped ${table}: ${e instanceof Error ? e.message : String(e)}`
        );
      }
    }
  }

  const finishedAt = new Date().toISOString();
  return { pruned, vacuumed, dryRun, startedAt, finishedAt };
}

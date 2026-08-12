#!/usr/bin/env node
/**
 * Prune retention + VACUUM (ANALYZE) on hot tables.
 * node --env-file=.env scripts/pg-maintenance.mjs
 */
import pg from "pg";
import { runPgMaintenance } from "../packages/shared/dist/index.js";

async function main() {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) throw new Error("DATABASE_URL is required");

  const pool = new pg.Pool({ connectionString: dbUrl });
  try {
    const result = await runPgMaintenance(pool, {
      auditRetentionDays: Number(process.env.AUDIT_LOG_RETENTION_DAYS ?? 90),
      enrichmentKeepPerCve: Number(process.env.ENRICHMENT_AI_KEEP_PER_CVE ?? 2),
      refreshTokenRetentionDays: Number(process.env.REFRESH_TOKEN_RETENTION_DAYS ?? 14),
      vacuum: process.env.PG_MAINTENANCE_VACUUM !== "false",
      dryRun: process.env.PG_MAINTENANCE_DRY_RUN === "true",
      log: (m) => console.log(m)
    });
    console.log("[pg-maint] done", JSON.stringify(result));
  } finally {
    await pool.end();
  }
}

main().catch((e) => {
  console.error("[pg-maint] failed", e);
  process.exit(1);
});

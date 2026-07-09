#!/usr/bin/env node
/**
 * Однократная загрузка EPSS feed → epss_score + epss_score_history.
 * node --env-file=.env scripts/epss-sync-now.mjs
 */
import pg from "pg";
import { ingestEpssFeed } from "../packages/shared/dist/index.js";

async function main() {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) throw new Error("DATABASE_URL is required");

  const pool = new pg.Pool({ connectionString: dbUrl });
  try {
    const result = await ingestEpssFeed(pool, { auditMeta: { reason: "manual", via: "epss-sync-now" } });
    console.log(
      `[epss-sync] ok source=${result.sourceUrl} rows=${result.rows} upserted=${result.upserted} changed=${result.changedCveIds.length}`
    );
  } finally {
    await pool.end();
  }
}

main().catch((e) => {
  console.error("[epss-sync] failed", e);
  process.exit(1);
});

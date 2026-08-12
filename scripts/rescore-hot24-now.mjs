#!/usr/bin/env node
/**
 * Recalculate risk_score for hot-24h CVEs missing a fresh score.
 * Default: inline upsert (no Rabbit). Queue only if AI_SCORE_VIA_QUEUE=true.
 * node --env-file=.env scripts/rescore-hot24-now.mjs
 */
import amqplib from "amqplib";
import pg from "pg";
import {
  applyRiskScoresForCveIds,
  buildScoreEventsForCveIds,
  hot24ScoreHourBucket,
  hot24ScoreIdempotencyKey,
  isAiScoreEnabled,
  listHot24CvesNeedingScore,
  publishScoreEvents,
  shouldScoreViaQueue
} from "../packages/shared/dist/index.js";

async function main() {
  if (!isAiScoreEnabled()) {
    console.error("[rescore-hot24] scoring disabled — set AI_SCORE_ENABLED=true");
    process.exit(2);
  }

  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) throw new Error("DATABASE_URL is required");

  const limit = Math.max(1, Math.min(5000, Number(process.env.HOT24_SCORE_SWEEP_LIMIT ?? 500)));
  const staleHours = Math.max(0, Math.min(168, Number(process.env.HOT24_SCORE_STALE_HOURS ?? 6)));
  const bucket = hot24ScoreHourBucket();
  const viaQueue = shouldScoreViaQueue();

  const pool = new pg.Pool({ connectionString: dbUrl });
  let conn = null;
  let ch = null;
  try {
    const rows = await listHot24CvesNeedingScore(pool, { limit, staleHours, bucket });
    const cveIds = rows.map((r) => r.cve_id);
    if (!cveIds.length) {
      console.log(`[rescore-hot24] nothing to score limit=${limit} staleHours=${staleHours}`);
      return;
    }

    if (viaQueue) {
      const amqpUrl = process.env.RABBITMQ_URL ?? "amqp://vuln:vuln@localhost:5672/";
      conn = await amqplib.connect(amqpUrl);
      ch = await conn.createChannel();
      await ch.assertExchange("vuln.events", "topic", { durable: true });
    }

    const n = await applyRiskScoresForCveIds(pool, cveIds, {
      concurrency: Number(process.env.AI_SCORE_INLINE_CONCURRENCY ?? 32),
      buildQueueEvents: () =>
        buildScoreEventsForCveIds(cveIds, {
          producer: { service: "script", version: "0.0.1" },
          tag: "hot24-script",
          idempotencyKeyFor: (cveId) => hot24ScoreIdempotencyKey(cveId, bucket)
        }),
      publishViaQueue: viaQueue
        ? (events) =>
            publishScoreEvents(
              (ex, rk, payload) => {
                ch.publish(ex, rk, Buffer.from(JSON.stringify(payload), "utf8"), {
                  contentType: "application/json",
                  persistent: true
                });
              },
              events
            )
        : undefined
    });
    console.log(
      `[rescore-hot24] ${viaQueue ? "enqueued" : "upserted"}=${n} limit=${limit} staleHours=${staleHours} bucket=${bucket}`
    );
  } finally {
    if (ch) await ch.close().catch(() => {});
    if (conn) await conn.close().catch(() => {});
    await pool.end();
  }
}

main().catch((e) => {
  console.error("[rescore-hot24] failed", e);
  process.exit(1);
});

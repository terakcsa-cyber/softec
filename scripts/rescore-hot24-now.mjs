#!/usr/bin/env node
/**
 * Поставить в очередь ai.score все CVE за 24ч без свежего risk_score.
 * node --env-file=.env scripts/rescore-hot24-now.mjs
 */
import amqplib from "amqplib";
import pg from "pg";
import { v4 as uuidv4 } from "uuid";
import {
  hot24ScoreHourBucket,
  hot24ScoreIdempotencyKey,
  listHot24CvesNeedingScore,
  QueueEventType
} from "../packages/shared/dist/index.js";

async function main() {
  const dbUrl = process.env.DATABASE_URL;
  const amqpUrl = process.env.RABBITMQ_URL ?? "amqp://vuln:vuln@localhost:5672/";
  if (!dbUrl) throw new Error("DATABASE_URL is required");

  const limit = Math.max(1, Math.min(5000, Number(process.env.HOT24_SCORE_SWEEP_LIMIT ?? 500)));
  const staleHours = Math.max(0, Math.min(168, Number(process.env.HOT24_SCORE_STALE_HOURS ?? 6)));
  const bucket = hot24ScoreHourBucket();

  const pool = new pg.Pool({ connectionString: dbUrl });
  const conn = await amqplib.connect(amqpUrl);
  const ch = await conn.createChannel();
  await ch.assertExchange("vuln.events", "topic", { durable: true });

  try {
    const rows = await listHot24CvesNeedingScore(pool, { limit, staleHours, bucket });
    const nowIso = new Date().toISOString();
    let n = 0;
    for (const row of rows) {
      const env = {
        id: uuidv4(),
        type: QueueEventType.ScoreCveRequested,
        ts: nowIso,
        producer: { service: "script", version: "0.0.1" },
        idempotencyKey: hot24ScoreIdempotencyKey(row.cve_id, bucket),
        payload: { cveId: row.cve_id }
      };
      ch.publish("vuln.events", "vuln.score.requested.v1", Buffer.from(JSON.stringify(env), "utf8"), {
        contentType: "application/json",
        persistent: true
      });
      n++;
    }
    console.log(`[rescore-hot24] enqueued=${n} limit=${limit} staleHours=${staleHours} bucket=${bucket}`);
  } finally {
    await ch.close();
    await conn.close();
    await pool.end();
  }
}

main().catch((e) => {
  console.error("[rescore-hot24] failed", e);
  process.exit(1);
});

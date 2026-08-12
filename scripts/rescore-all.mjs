#!/usr/bin/env node
/**
 * Recalculate risk_score for the whole CVE corpus.
 * Default: inline upsert. Queue only if AI_SCORE_VIA_QUEUE=true.
 * RESCORE_LIMIT=0 means no limit. RESCORE_BATCH=2000.
 */
import amqplib from "amqplib";
import pg from "pg";
import {
  applyRiskScoresForCveIds,
  buildScoreEventsForCveIds,
  isAiScoreEnabled,
  shouldScoreViaQueue,
  publishScoreEvents
} from "../packages/shared/dist/index.js";

const DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://vuln:vuln@localhost:5432/vuln_intel";
const RABBITMQ_URL = process.env.RABBITMQ_URL ?? "amqp://vuln:vuln@localhost:5672/";

if (!isAiScoreEnabled()) {
  console.error("[rescore-all] scoring disabled — set AI_SCORE_ENABLED=true");
  process.exit(2);
}

const LIMIT = Number(process.env.RESCORE_LIMIT ?? 0); // 0 = no limit
const BATCH = Number(process.env.RESCORE_BATCH ?? 2000);
const RUN_ID = process.env.RESCORE_RUN_ID ?? new Date().toISOString();
const viaQueue = shouldScoreViaQueue();

const db = new pg.Pool({ connectionString: DATABASE_URL });
let conn = null;
let ch = null;

let done = 0;
let lastCveId = "";

try {
  if (viaQueue) {
    conn = await amqplib.connect(RABBITMQ_URL);
    ch = await conn.createChannel();
    await ch.assertExchange("vuln.events", "topic", { durable: true });
  }

  // eslint-disable-next-line no-constant-condition
  while (true) {
    // eslint-disable-next-line no-await-in-loop
    const r = await db.query(
      `SELECT cve_id
         FROM cve
        WHERE cve_id > $1
        ORDER BY cve_id ASC
        LIMIT $2`,
      [lastCveId, BATCH]
    );
    if (r.rowCount === 0) break;

    let cveIds = r.rows.map((row) => row.cve_id);
    if (LIMIT > 0) {
      const remain = LIMIT - done;
      if (remain <= 0) break;
      cveIds = cveIds.slice(0, remain);
    }

    // eslint-disable-next-line no-await-in-loop
    const n = await applyRiskScoresForCveIds(db, cveIds, {
      concurrency: Number(process.env.AI_SCORE_INLINE_CONCURRENCY ?? 32),
      buildQueueEvents: () =>
        buildScoreEventsForCveIds(cveIds, {
          producer: { service: "scripts", version: "0.0.1" },
          tag: "rescore-all",
          idempotencyKeyFor: (cveId) => `score:rescore-all:${RUN_ID}:${cveId}`
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

    done += n;
    const tail = r.rows[r.rows.length - 1];
    lastCveId = tail ? tail.cve_id : lastCveId;
    // eslint-disable-next-line no-console
    console.log(`[rescore-all] ${viaQueue ? "enqueued" : "upserted"}=${done} last=${lastCveId}`);

    if (LIMIT > 0 && done >= LIMIT) break;
  }
} finally {
  if (ch) await ch.close().catch(() => {});
  if (conn) await conn.close().catch(() => {});
  await db.end().catch(() => {});
}

// eslint-disable-next-line no-console
console.log(`[rescore-all] done total=${done} mode=${viaQueue ? "queue" : "inline"}`);

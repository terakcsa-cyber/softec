import amqplib from "amqplib";
import pg from "pg";
import { v4 as uuidv4 } from "uuid";

const DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://vuln:vuln@localhost:5432/vuln_intel";
const RABBITMQ_URL = process.env.RABBITMQ_URL ?? "amqp://vuln:vuln@localhost:5672/";

const EXCHANGE = "vuln.events";
const ROUTING_KEY = "vuln.score.requested.v1";
const EVENT_TYPE = "vuln.score.requested.v1";

const { isAiScoreEnabled } = await import("../packages/shared/dist/index.js");
if (!isAiScoreEnabled()) {
  console.error("[rescore-all] ai.score disabled — set TEXT_ENGINE=llm or AI_SCORE_ENABLED=true");
  process.exit(2);
}

const LIMIT = Number(process.env.RESCORE_LIMIT ?? 0); // 0 = no limit
const BATCH = Number(process.env.RESCORE_BATCH ?? 2000);
const RUN_ID = process.env.RESCORE_RUN_ID ?? new Date().toISOString();

const db = new pg.Pool({ connectionString: DATABASE_URL });
const conn = await amqplib.connect(RABBITMQ_URL);
const ch = await conn.createChannel();
await ch.assertExchange(EXCHANGE, "topic", { durable: true });

let published = 0;
let lastCveId = "";

try {
  // keyset pagination to avoid OFFSET on large tables
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

    const nowIso = new Date().toISOString();
    for (const row of r.rows) {
      const cveId = row.cve_id;
      const env = {
        id: uuidv4(),
        type: EVENT_TYPE,
        ts: nowIso,
        producer: { service: "scripts", version: "0.0.1" },
        // Must be unique per run to bypass idempotency in scoring worker.
        idempotencyKey: `score:rescore-all:${RUN_ID}:${cveId}`,
        payload: { cveId }
      };
      const ok = ch.publish(EXCHANGE, ROUTING_KEY, Buffer.from(JSON.stringify(env), "utf8"), {
        contentType: "application/json",
        persistent: true
      });
      if (!ok) {
        // eslint-disable-next-line no-await-in-loop
        await new Promise((res) => setTimeout(res, 5));
      }
      published++;
      if (LIMIT > 0 && published >= LIMIT) break;
    }

    const tail = r.rows[r.rows.length - 1];
    lastCveId = tail ? tail.cve_id : lastCveId;
    // eslint-disable-next-line no-console
    console.log(`[rescore-all] published=${published} last=${lastCveId}`);

    if (LIMIT > 0 && published >= LIMIT) break;
  }
} finally {
  await ch.close().catch(() => {});
  await conn.close().catch(() => {});
  await db.end().catch(() => {});
}

// eslint-disable-next-line no-console
console.log(`[rescore-all] done published=${published} run=${RUN_ID}`);


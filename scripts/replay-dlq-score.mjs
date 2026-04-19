import amqplib from "amqplib";

const RABBITMQ_URL = process.env.RABBITMQ_URL ?? "amqp://vuln:vuln@localhost:5672/";
const EXCHANGE = "vuln.events";
const DLQ = process.env.DLQ_NAME ?? "dlq.ai.score";
const ROUTING_KEY = process.env.REPLAY_ROUTING_KEY ?? "vuln.score.requested.v1";
const LIMIT = Number(process.env.REPLAY_LIMIT ?? 500);

const conn = await amqplib.connect(RABBITMQ_URL);
const ch = await conn.createChannel();

await ch.assertExchange(EXCHANGE, "topic", { durable: true });
await ch.assertQueue(DLQ, { durable: true });

let replayed = 0;
for (let i = 0; i < LIMIT; i++) {
  // eslint-disable-next-line no-await-in-loop
  const msg = await ch.get(DLQ, { noAck: false });
  if (!msg) break;
  try {
    const ok = ch.publish(EXCHANGE, ROUTING_KEY, msg.content, {
      contentType: msg.properties.contentType ?? "application/json",
      persistent: true
    });
    if (!ok) {
      // backpressure: wait a tick
      // eslint-disable-next-line no-await-in-loop
      await new Promise((r) => setTimeout(r, 10));
    }
    ch.ack(msg);
    replayed++;
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error("Replay failed, leaving message in DLQ", e);
    ch.nack(msg, false, true);
    break;
  }
}

// eslint-disable-next-line no-console
console.log(`Replayed ${replayed} messages from ${DLQ} -> ${EXCHANGE}:${ROUTING_KEY}`);

await ch.close();
await conn.close();


import { randomUUID } from "node:crypto";
import {
  EnrichCveRequestedEventSchema,
  QueueEventEnvelopeSchema,
  QueueEventType,
  ScoreCveRequestedEventSchema
} from "./events.js";
import { isAiScoreEnabled, shouldScoreViaQueue } from "./score-request.js";

export type AmqpGetChannel = {
  get(
    queue: string,
    opts: { noAck: boolean }
  ): Promise<
    | {
        content: Buffer;
        fields?: { routingKey?: string; redelivered?: boolean };
        properties?: { headers?: Record<string, unknown> };
      }
    | false
  >;
  ack(msg: unknown): void;
  nack(msg: unknown, allUpTo: boolean, requeue: boolean): void;
  publish(
    exchange: string,
    routingKey: string,
    content: Buffer,
    options?: { contentType?: string; persistent?: boolean; priority?: number }
  ): boolean;
  assertExchange(exchange: string, type: string, opts: { durable: boolean }): Promise<unknown>;
};

const DLQ_QUEUES = ["dlq.ai.enrich", "dlq.ai.score"] as const;

function withDlqReplayKey(env: { idempotencyKey?: string; [k: string]: unknown }) {
  let base =
    typeof env.idempotencyKey === "string" && env.idempotencyKey.length > 0 ? env.idempotencyKey : "unknown";
  const maxBase = 512;
  if (base.length > maxBase) base = base.slice(0, maxBase);
  return { ...env, idempotencyKey: `${base}:dlq:${randomUUID()}` };
}

function replayParsedMessage(
  channel: AmqpGetChannel,
  env: unknown
): boolean {
  const parsed = QueueEventEnvelopeSchema.safeParse(env);
  if (!parsed.success) return false;
  const base = parsed.data;
  if (base.type === QueueEventType.EnrichCveRequested) {
    const p = EnrichCveRequestedEventSchema.safeParse(base.payload);
    if (!p.success) return false;
    const replayedEnv = withDlqReplayKey(base);
    const buf = Buffer.from(JSON.stringify(replayedEnv), "utf8");
    channel.publish("vuln.events", "vuln.enrich.requested.v1", buf, {
      contentType: "application/json",
      persistent: true,
      priority: 9
    });
    return true;
  }
  if (base.type === QueueEventType.ScoreCveRequested) {
    // Inline scoring is default — replaying into ai.score only piles up with no consumer.
    if (!isAiScoreEnabled() || !shouldScoreViaQueue()) return false;
    const p = ScoreCveRequestedEventSchema.safeParse(base.payload);
    if (!p.success) return false;
    const replayedEnv = withDlqReplayKey(base);
    const buf = Buffer.from(JSON.stringify(replayedEnv), "utf8");
    channel.publish("vuln.events", "vuln.score.requested.v1", buf, {
      contentType: "application/json",
      persistent: true
    });
    return true;
  }
  return false;
}

/** Переотправляет сообщения из DLQ в vuln.events с новым idempotencyKey. */
export async function replayDlqMessages(
  channel: AmqpGetChannel,
  opts?: { queues?: readonly string[]; limitPerQueue?: number }
): Promise<{ replayed: number; skipped: number; byQueue: Record<string, number> }> {
  const scoreQueueOn = isAiScoreEnabled() && shouldScoreViaQueue();
  const queues =
    opts?.queues ??
    (scoreQueueOn ? DLQ_QUEUES : (["dlq.ai.enrich"] as const));
  const limitPerQueue = Math.max(1, Math.min(10_000, opts?.limitPerQueue ?? 200));
  await channel.assertExchange("vuln.events", "topic", { durable: true });

  const byQueue: Record<string, number> = {};
  let replayed = 0;
  let skipped = 0;

  for (const queue of queues) {
    let n = 0;
    for (let i = 0; i < limitPerQueue; i++) {
      // eslint-disable-next-line no-await-in-loop
      const msg = await channel.get(queue, { noAck: false });
      if (!msg) break;

      const body = msg.content.toString("utf8");
      let published = false;
      try {
        published = replayParsedMessage(channel, JSON.parse(body));
      } catch {
        published = false;
      }

      if (published) {
        channel.ack(msg);
        n++;
        replayed++;
      } else {
        channel.nack(msg, false, true);
        skipped++;
      }
    }
    byQueue[queue] = n;
  }

  return { replayed, skipped, byQueue };
}

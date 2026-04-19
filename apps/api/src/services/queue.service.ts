import { Injectable, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import amqplib, { Channel, ChannelModel, Options } from "amqplib";

function msgToStringSafe(msg: any): string {
  try {
    return msg?.content?.toString?.("utf8") ?? "";
  } catch {
    return "";
  }
}

@Injectable()
export class QueueService implements OnModuleInit, OnModuleDestroy {
  private conn?: ChannelModel;
  private channel?: Channel;

  async onModuleInit() {
    const url = process.env.RABBITMQ_URL ?? "amqp://vuln:vuln@localhost:5672/";
    this.conn = await amqplib.connect(url);
    this.channel = await this.conn.createChannel();
    /** Must run before any publish: unrouted messages are dropped if no queue is bound yet. */
    await this.ensureTopology();
  }

  /**
   * Mirrors `apps/ai` queue bindings so `publish()` does not lose messages when the worker
   * starts after the API (otherwise the exchange exists but no queue is bound yet).
   */
  async ensureTopology() {
    if (!this.channel) throw new Error("Queue channel not initialized");
    const ch = this.channel;
    await ch.assertExchange("vuln.events", "topic", { durable: true });
    await ch.assertExchange("vuln.dlx", "topic", { durable: true });

    await ch.assertQueue("ai.enrich", {
      durable: true,
      arguments: {
        "x-max-priority": 10,
        "x-dead-letter-exchange": "vuln.dlx",
        "x-dead-letter-routing-key": "dlq.ai.enrich"
      }
    });
    await ch.bindQueue("ai.enrich", "vuln.events", "vuln.enrich.requested.*");

    await ch.assertQueue("ai.score", {
      durable: true,
      arguments: {
        "x-dead-letter-exchange": "vuln.dlx",
        "x-dead-letter-routing-key": "dlq.ai.score"
      }
    });
    await ch.bindQueue("ai.score", "vuln.events", "vuln.score.requested.*");

    await ch.assertQueue("dlq.ai.enrich", { durable: true });
    await ch.assertQueue("dlq.ai.score", { durable: true });
    await ch.bindQueue("dlq.ai.enrich", "vuln.dlx", "dlq.ai.enrich");
    await ch.bindQueue("dlq.ai.score", "vuln.dlx", "dlq.ai.score");
  }

  async publish(exchange: string, routingKey: string, payload: unknown, options?: Options.Publish) {
    if (!this.channel) throw new Error("Queue channel not initialized");
    await this.channel.assertExchange(exchange, "topic", { durable: true });
    const buf = Buffer.from(JSON.stringify(payload), "utf8");
    this.channel.publish(exchange, routingKey, buf, {
      contentType: "application/json",
      persistent: true,
      ...options
    });
  }

  async getQueueDepth(queueName: string): Promise<{ queue: string; messages: number; consumers: number }> {
    if (!this.channel) throw new Error("Queue channel not initialized");
    const r = await this.channel.checkQueue(queueName);
    return { queue: queueName, messages: r.messageCount, consumers: r.consumerCount };
  }

  async sampleQueueRequeue(queueName: string, limit: number) {
    if (!this.channel) throw new Error("Queue channel not initialized");
    const out: Array<{
      body: string;
      headers: Record<string, unknown>;
      redelivered: boolean;
      routingKey?: string;
    }> = [];

    for (let i = 0; i < limit; i++) {
      // eslint-disable-next-line no-await-in-loop
      const msg = await this.channel.get(queueName, { noAck: false });
      if (!msg) break;
      out.push({
        body: msgToStringSafe(msg),
        headers: (msg.properties?.headers ?? {}) as Record<string, unknown>,
        redelivered: Boolean(msg.fields?.redelivered),
        routingKey: typeof msg.fields?.routingKey === "string" ? msg.fields.routingKey : undefined
      });
      // Put message back (requeue) so sampling is non-destructive.
      this.channel.nack(msg, false, true);
    }
    return out;
  }

  async drainQueue(queueName: string, limit: number, onMessage?: (body: string) => Promise<void> | void) {
    if (!this.channel) throw new Error("Queue channel not initialized");
    let drained = 0;
    for (let i = 0; i < limit; i++) {
      // eslint-disable-next-line no-await-in-loop
      const msg = await this.channel.get(queueName, { noAck: false });
      if (!msg) break;
      const body = msgToStringSafe(msg);
      if (onMessage) {
        // eslint-disable-next-line no-await-in-loop
        await onMessage(body);
      }
      this.channel.ack(msg);
      drained++;
    }
    return { drained };
  }

  async onModuleDestroy() {
    try {
      await this.channel?.close();
    } finally {
      await this.conn?.close();
    }
  }
}


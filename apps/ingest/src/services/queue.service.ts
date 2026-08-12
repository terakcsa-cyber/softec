import { Injectable, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import amqplib, { Channel, ChannelModel, Options } from "amqplib";

function redactAmqpUrl(url: string): string {
  try {
    const u = new URL(url);
    if (u.password) u.password = "****";
    return u.toString();
  } catch {
    return url.replace(/:\/\/([^:]+):([^@]+)@/, "://$1:****@");
  }
}

async function connectAmqpWithRetry(url: string): Promise<ChannelModel> {
  const maxAttempts = Math.max(1, Math.min(200, Number(process.env.RABBITMQ_CONNECT_RETRIES ?? 60)));
  const delayMs = Math.max(100, Math.min(30_000, Number(process.env.RABBITMQ_CONNECT_RETRY_MS ?? 2000)));
  let last: unknown;
  for (let i = 1; i <= maxAttempts; i++) {
    try {
      return await amqplib.connect(url);
    } catch (e) {
      last = e;
      // eslint-disable-next-line no-console
      console.error(
        `[ingest:amqp] connect failed ${i}/${maxAttempts} ${redactAmqpUrl(url)}`,
        e instanceof Error ? e.message : e
      );
      if (i < maxAttempts) await new Promise((r) => setTimeout(r, delayMs));
    }
  }
  throw last;
}

@Injectable()
export class QueueService implements OnModuleInit, OnModuleDestroy {
  private conn?: ChannelModel;
  channel?: Channel;

  async onModuleInit() {
    const url = process.env.RABBITMQ_URL ?? "amqp://vuln:vuln@localhost:5672/";
    this.conn = await connectAmqpWithRetry(url);
    this.channel = await this.conn.createChannel();
    await this.ensureTopology();
  }

  /**
   * Assert enrich/score queues so checkQueue / publish backpressure work even if ai starts later.
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

  publish(exchange: string, routingKey: string, payload: unknown, options?: Options.Publish) {
    if (!this.channel) throw new Error("Queue channel not initialized");
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

  async onModuleDestroy() {
    try {
      await this.channel?.close();
    } finally {
      await this.conn?.close();
    }
  }
}

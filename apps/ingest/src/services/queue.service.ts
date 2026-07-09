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
    await this.channel.assertExchange("vuln.events", "topic", { durable: true });
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

  async onModuleDestroy() {
    try {
      await this.channel?.close();
    } finally {
      await this.conn?.close();
    }
  }
}


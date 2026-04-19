import { Injectable, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import amqplib, { Channel, ChannelModel, ConsumeMessage, Options } from "amqplib";

@Injectable()
export class QueueService implements OnModuleInit, OnModuleDestroy {
  private conn?: ChannelModel;
  channel?: Channel;

  async onModuleInit() {
    const url = process.env.RABBITMQ_URL ?? "amqp://vuln:vuln@localhost:5672/";
    this.conn = await amqplib.connect(url);
    this.channel = await this.conn.createChannel();
  }

  async ensureTopology() {
    if (!this.channel) throw new Error("Queue channel not initialized");
    await this.channel.assertExchange("vuln.events", "topic", { durable: true });

    // Worker queues (durable) with DLQ.
    await this.channel.assertExchange("vuln.dlx", "topic", { durable: true });

    await this.channel.assertQueue("ai.enrich", {
      durable: true,
      arguments: {
        "x-max-priority": 10,
        "x-dead-letter-exchange": "vuln.dlx",
        "x-dead-letter-routing-key": "dlq.ai.enrich"
      }
    });
    await this.channel.bindQueue("ai.enrich", "vuln.events", "vuln.enrich.requested.*");

    await this.channel.assertQueue("ai.score", {
      durable: true,
      arguments: {
        "x-dead-letter-exchange": "vuln.dlx",
        "x-dead-letter-routing-key": "dlq.ai.score"
      }
    });
    await this.channel.bindQueue("ai.score", "vuln.events", "vuln.score.requested.*");

    // DLQs
    await this.channel.assertQueue("dlq.ai.enrich", { durable: true });
    await this.channel.assertQueue("dlq.ai.score", { durable: true });
    await this.channel.bindQueue("dlq.ai.enrich", "vuln.dlx", "dlq.ai.enrich");
    await this.channel.bindQueue("dlq.ai.score", "vuln.dlx", "dlq.ai.score");
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

  ack(msg: ConsumeMessage) {
    if (!this.channel) throw new Error("Queue channel not initialized");
    this.channel.ack(msg);
  }

  nack(msg: ConsumeMessage, requeue = false) {
    if (!this.channel) throw new Error("Queue channel not initialized");
    this.channel.nack(msg, false, requeue);
  }

  async onModuleDestroy() {
    try {
      await this.channel?.close();
    } finally {
      await this.conn?.close();
    }
  }
}


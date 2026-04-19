import { Injectable, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import amqplib, { Channel, ChannelModel, Options } from "amqplib";

@Injectable()
export class QueueService implements OnModuleInit, OnModuleDestroy {
  private conn?: ChannelModel;
  private channel?: Channel;

  async onModuleInit() {
    const url = process.env.RABBITMQ_URL ?? "amqp://vuln:vuln@localhost:5672/";
    this.conn = await amqplib.connect(url);
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


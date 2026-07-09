import assert from "node:assert/strict";
import { accessSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, before, after } from "node:test";
import pg from "pg";
import amqplib from "amqplib";
import { PostgreSqlContainer } from "@testcontainers/postgresql";
import { RabbitMQContainer } from "@testcontainers/rabbitmq";

function dockerAvailable() {
  try {
    accessSync("/var/run/docker.sock");
    return true;
  } catch {
    return false;
  }
}

const skip = process.env.SKIP_INTEGRATION === "1" || process.env.SKIP_INTEGRATION === "true" || !dockerAvailable();

describe("chaos: postgres restart", { skip }, () => {
  /** @type {import('@testcontainers/postgresql').StartedPostgreSqlContainer} */
  let container;
  /** @type {pg.Client} */
  let client;

  before(async () => {
    container = await new PostgreSqlContainer("postgres:16-alpine").start();
    client = new pg.Client({ connectionString: container.getConnectionUri() });
    await client.connect();
    await client.query(`
      CREATE TABLE chaos_probe (id SERIAL PRIMARY KEY, note TEXT NOT NULL)
    `);
    await client.query(`INSERT INTO chaos_probe (note) VALUES ('before-restart')`);
    await client.end();
  });

  after(async () => {
    await container?.stop().catch(() => {});
  });

  it("keeps data after container restart", async () => {
    await container.restart();

    const uri = container.getConnectionUri();
    const c = new pg.Client({ connectionString: uri });
    await c.connect();
    const row = await c.query(`SELECT note FROM chaos_probe ORDER BY id DESC LIMIT 1`);
    assert.equal(row.rows[0]?.note, "before-restart");
    await c.query(`INSERT INTO chaos_probe (note) VALUES ('after-restart')`);
    const count = await c.query(`SELECT COUNT(*)::int AS n FROM chaos_probe`);
    assert.equal(count.rows[0]?.n, 2);
    await c.end();
  });
});

describe("chaos: rabbitmq restart", { skip }, () => {
  /** @type {import('@testcontainers/rabbitmq').StartedRabbitMQContainer} */
  let container;

  before(async () => {
    container = await new RabbitMQContainer("rabbitmq:3-management-alpine").start();
  });

  after(async () => {
    await container?.stop().catch(() => {});
  });

  it("accepts connections after restart", async () => {
    const url = container.getAmqpUrl();
    const conn1 = await amqplib.connect(url);
    await conn1.close();

    await container.restart();

    const conn2 = await amqplib.connect(container.getAmqpUrl());
    const ch = await conn2.createChannel();
    const q = await ch.assertQueue("vip.chaos.restart", { durable: false, autoDelete: true });
    assert.ok(q.queue);
    await ch.sendToQueue(q.queue, Buffer.from("ping"));
    const received = await ch.get(q.queue, { noAck: true });
    assert.equal(received?.content?.toString(), "ping");
    await ch.close();
    await conn2.close();
  });
});

import assert from "node:assert/strict";
import { accessSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, before, after } from "node:test";
import pg from "pg";
import amqplib from "amqplib";
import { PostgreSqlContainer } from "@testcontainers/postgresql";
import { RabbitMQContainer } from "@testcontainers/rabbitmq";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../../..");
const migrationsDir = path.join(root, "infra/postgres/migrations");

function dockerAvailable() {
  try {
    accessSync("/var/run/docker.sock");
    return true;
  } catch {
    return false;
  }
}

const skip = process.env.SKIP_INTEGRATION === "1" || process.env.SKIP_INTEGRATION === "true" || !dockerAvailable();

describe("integration: postgres migrations", { skip }, () => {
  /** @type {import('@testcontainers/postgresql').StartedPostgreSqlContainer} */
  let container;
  /** @type {pg.Client} */
  let client;

  before(async () => {
    container = await new PostgreSqlContainer("postgres:16-alpine").start();
    client = new pg.Client({ connectionString: container.getConnectionUri() });
    await client.connect();
    await client.query(`
      CREATE TABLE auth_user (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);
    const migrationSql = await readFile(path.join(migrationsDir, "001_auth_user_role.sql"), "utf8");
    await client.query(migrationSql);
  });

  after(async () => {
    await client?.end().catch(() => {});
    await container?.stop().catch(() => {});
  });

  it("applies auth_user.role migration", async () => {
    const cols = await client.query(
      `SELECT column_name FROM information_schema.columns
       WHERE table_name = 'auth_user' AND column_name = 'role'`
    );
    assert.equal(cols.rows.length, 1);

    await client.query(
      `INSERT INTO auth_user (email, role) VALUES ('int@test.local', 'viewer')
       ON CONFLICT (email) DO NOTHING`
    );
    const row = await client.query(`SELECT role FROM auth_user WHERE email = 'int@test.local'`);
    assert.equal(row.rows[0]?.role, "viewer");
  });
});

describe("integration: rabbitmq", { skip }, () => {
  /** @type {import('@testcontainers/rabbitmq').StartedRabbitMQContainer} */
  let container;

  before(async () => {
    container = await new RabbitMQContainer("rabbitmq:3-management-alpine").start();
  });

  after(async () => {
    await container?.stop().catch(() => {});
  });

  it("connects and declares a queue", async () => {
    const conn = await amqplib.connect(container.getAmqpUrl());
    const ch = await conn.createChannel();
    const q = await ch.assertQueue("vip.integration.test", { durable: false, autoDelete: true });
    assert.ok(q.queue);
    await ch.close();
    await conn.close();
  });
});

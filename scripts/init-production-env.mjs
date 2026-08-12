#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { randomBytes } from "node:crypto";

const args = new Map();
for (const raw of process.argv.slice(2)) {
  if (raw === "--force") {
    args.set("force", "true");
    continue;
  }
  const m = raw.match(/^--([^=]+)=(.*)$/);
  if (m) args.set(m[1], m[2]);
}

const root = resolve(new URL("..", import.meta.url).pathname);
const templatePath = resolve(root, ".env.production.example");
const outFile = String(args.get("out") ?? ".env.production");
const outPath = resolve(root, outFile);
const force = args.get("force") === "true";
const webPort = String(args.get("web-port") ?? process.env.WEB_PUBLISHED_PORT ?? "3000");
const origin = String(args.get("origin") ?? process.env.PUBLIC_WEB_ORIGIN ?? `http://localhost:${webPort}`).replace(/\/+$/, "");

if (existsSync(outPath) && !force) {
  console.error(`[init-production-env] ${outPath} already exists. Use --force to overwrite.`);
  process.exit(1);
}

if (!existsSync(templatePath)) {
  console.error(`[init-production-env] template not found: ${templatePath}`);
  process.exit(1);
}

function secret(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

const postgresUser = "vuln";
const postgresDb = "vuln_intel";
const postgresPassword = secret(32);
const rabbitUser = "vuln";
const rabbitPassword = secret(32);

const replacements = {
  WEB_PUBLISHED_PORT: webPort,
  PUBLIC_WEB_ORIGIN: origin,
  POSTGRES_USER: postgresUser,
  POSTGRES_PASSWORD: postgresPassword,
  POSTGRES_DB: postgresDb,
  RABBITMQ_DEFAULT_USER: rabbitUser,
  RABBITMQ_DEFAULT_PASS: rabbitPassword,
  RABBITMQ_DEFAULT_VHOST: "/",
  DATABASE_URL: `postgres://${postgresUser}:${postgresPassword}@postgres:5432/${postgresDb}`,
  REDIS_URL: "redis://redis:6379",
  RABBITMQ_URL: `amqp://${rabbitUser}:${rabbitPassword}@rabbitmq:5672/%2F`,
  JWT_SECRET: secret(48),
  API_CORS_ORIGIN: origin,
  AUTH_ALLOW_REGISTER: "false",
  AUTH_ALLOW_REGISTER_IN_PRODUCTION: "false",
  ALLOW_INTERNAL_API_BEARER: "false",
  BDU_ALLOW_MIRROR_FALLBACK: "true"
};

function renderLine(line) {
  const m = line.match(/^([A-Z0-9_]+)=.*$/);
  if (!m) return line;
  const key = m[1];
  if (!(key in replacements)) return line;
  return `${key}=${replacements[key]}`;
}

const rendered = readFileSync(templatePath, "utf8")
  .split(/\r?\n/)
  .map(renderLine)
  .join("\n")
  .replace(/CHANGE_ME_[A-Z0-9_]+/g, () => secret(32));

writeFileSync(outPath, rendered.endsWith("\n") ? rendered : `${rendered}\n`, { mode: 0o600 });

console.log(`[init-production-env] wrote ${outPath}`);
console.log(`[init-production-env] PUBLIC_WEB_ORIGIN=${origin}`);
console.log("[init-production-env] Next:");
console.log(`  docker compose --env-file ${outFile} -f infra/docker-compose.prod.yml up -d --build`);

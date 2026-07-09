#!/usr/bin/env node
/**
 * Chaos smoke: restart app services one-by-one and verify health recovers.
 * For staging/prod compose stacks (Docker required).
 *
 * Usage:
 *   ENV_FILE=.env.staging COMPOSE_FILE=infra/docker-compose.staging.yml node scripts/chaos-restart-smoke.mjs
 */
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const envFile = process.env.ENV_FILE?.trim() || ".env.staging";
const composeFile = process.env.COMPOSE_FILE?.trim() || "infra/docker-compose.staging.yml";
const webBase = process.env.SMOKE_WEB_URL?.trim() || "http://127.0.0.1:3080";
const services = (process.env.CHAOS_SERVICES ?? "api,ingest,ai,web").split(",").map((s) => s.trim());

function run(cmd, args) {
  const res = spawnSync(cmd, args, { cwd: root, encoding: "utf8", stdio: "pipe" });
  if (res.status !== 0) {
    throw new Error(`${cmd} ${args.join(" ")} failed: ${res.stderr || res.stdout}`);
  }
  return res.stdout;
}

async function waitWebHealth(maxSec = 120) {
  const url = `${webBase}/health`;
  const deadline = Date.now() + maxSec * 1000;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
      if (res.ok) return;
    } catch {
      // retry
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`web health timeout: ${url}`);
}

async function main() {
  for (const svc of services) {
    if (!svc) continue;
    console.log(`chaos: restart ${svc}...`);
    run("docker", ["compose", "--env-file", envFile, "-f", composeFile, "restart", svc]);
    await waitWebHealth();
    console.log(`ok ${svc} recovered`);
  }
  console.log("chaos restart smoke passed");
}

main().catch((e) => {
  console.error("FAIL:", e.message);
  process.exit(1);
});

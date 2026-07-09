#!/usr/bin/env node
/**
 * Integration smoke against a running API (post-deploy or local).
 * Extends post-deploy-smoke with RBAC/reconciliation checks when SMOKE_BEARER is set.
 */
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const apiBase = process.env.SMOKE_API_URL?.trim() || "http://127.0.0.1:4001/api";
const bearer = process.env.SMOKE_BEARER?.trim();

async function get(url, headers = {}) {
  const res = await fetch(url, { headers, signal: AbortSignal.timeout(15_000) });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }
  return { status: res.status, json };
}

function fail(msg) {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
}

async function runPostDeploy() {
  const script = path.join(path.dirname(fileURLToPath(import.meta.url)), "post-deploy-smoke.mjs");
  await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script], {
      stdio: "inherit",
      env: process.env
    });
    child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`post-deploy exited ${code}`))));
  });
}

async function main() {
  await runPostDeploy();

  const metrics = await get(`${apiBase}/metrics`);
  if (metrics.status !== 200) {
    fail(`GET /metrics ${metrics.status}`);
  }
  const body = String(metrics.json);
  if (!body.includes("vuln_") && !body.includes("# HELP")) {
    fail("metrics body missing prometheus markers");
  }
  console.log("ok api /metrics");

  if (!bearer) {
    console.log("skip authenticated checks (set SMOKE_BEARER)");
    console.log("integration smoke passed");
    return;
  }

  const headers = { Authorization: `Bearer ${bearer}` };

  const queue = await get(`${apiBase}/stats/queue`, headers);
  if (queue.status !== 200) fail(`stats/queue ${queue.status}`);
  console.log("ok stats/queue");

  const recon = await get(`${apiBase}/stats/reconciliation`, headers);
  if (recon.status !== 200) fail(`stats/reconciliation ${recon.status}`);
  if (!Array.isArray(recon.json?.sources)) fail("reconciliation missing sources[]");
  console.log("ok stats/reconciliation", `sources=${recon.json.sources.length}`);

  const dlqRes = await fetch(`${apiBase}/stats/dlq/retry?queue=dlq.ai.enrich&limit=1`, {
    method: "POST",
    headers,
    signal: AbortSignal.timeout(15_000)
  });
  if (dlqRes.status === 404) fail("dlq retry endpoint missing");
  console.log("ok dlq retry endpoint", dlqRes.status);

  console.log("integration smoke passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

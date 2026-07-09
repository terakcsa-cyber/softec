#!/usr/bin/env node
/**
 * Post-deploy smoke: health, queue stats (if token provided), metrics.
 */
const webBase = process.env.SMOKE_WEB_URL?.trim() || "http://127.0.0.1:3000";
const apiBase = process.env.SMOKE_API_URL?.trim() || "http://127.0.0.1:4001/api";
const skipApi = process.env.SMOKE_API_SKIP === "1" || process.env.SMOKE_API_SKIP === "true";
const bearer = process.env.SMOKE_BEARER?.trim();
const metricsUrl = process.env.SMOKE_METRICS_URL?.trim() || "http://127.0.0.1:9090/metrics";

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

async function main() {
  if (!skipApi) {
    const health = await get(`${apiBase}/health`);
    if (health.status !== 200 || health.json?.ok !== true) {
      fail(`api health ${health.status} ${JSON.stringify(health.json)}`);
    }
    console.log("ok api /health");
  } else {
    console.log("skip direct api checks (SMOKE_API_SKIP)");
  }

  const webHealth = await get(`${webBase}/api/health`);
  if (webHealth.status !== 200) {
    fail(`web bff health ${webHealth.status}`);
  }
  console.log("ok web /api/health");

  if (bearer && !skipApi) {
    const queue = await get(`${apiBase}/stats/queue`, {
      Authorization: `Bearer ${bearer}`
    });
    if (queue.status !== 200) {
      fail(`stats/queue ${queue.status}`);
    }
    console.log("ok stats/queue", JSON.stringify(queue.json?.queues ?? queue.json).slice(0, 200));
  } else {
    console.log("skip stats/queue (set SMOKE_BEARER)");
  }

  try {
    const m = await get(metricsUrl);
    if (m.status === 200 && String(m.json).includes("vuln_")) {
      console.log("ok metrics scrape");
    } else {
      console.log("warn metrics", m.status);
    }
  } catch {
    console.log("skip metrics (not running)");
  }

  console.log("smoke passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

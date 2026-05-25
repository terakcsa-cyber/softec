#!/usr/bin/env node
/**
 * Локальный DAST smoke: curl-сценарии + опционально OWASP ZAP baseline (Docker).
 *
 * Usage:
 *   WEB_BASE=http://127.0.0.1:3001 API_BASE=http://127.0.0.1:4001 node scripts/security-dast.mjs
 *   RUN_ZAP=1 WEB_BASE=http://127.0.0.1:3001 node scripts/security-dast.mjs
 */
import { spawnSync } from "node:child_process";

const WEB = process.env.WEB_BASE?.trim() || "http://127.0.0.1:3001";
const API = process.env.API_BASE?.trim() || "http://127.0.0.1:4001";

const cases = [
  ["GET web health or home", ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", `${WEB}/`]],
  ["GET BFF cves (no auth)", ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", `${WEB}/api/cves?limit=1`]],
  [
    "GET API stats without token (expect 401)",
    ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", `${API}/api/stats/summary`]
  ],
  [
    "GET API stats with bogus bearer (expect 401)",
    [
      "curl",
      "-sS",
      "-o",
      "/dev/null",
      "-w",
      "%{http_code}",
      "-H",
      "Authorization: Bearer invalid-token-xxxxxxxx",
      `${API}/api/stats/summary`
    ]
  ],
  [
    "CORS preflight API",
    [
      "curl",
      "-sS",
      "-o",
      "/dev/null",
      "-w",
      "%{http_code}",
      "-X",
      "OPTIONS",
      "-H",
      "Origin: http://127.0.0.1:3001",
      "-H",
      "Access-Control-Request-Method: GET",
      `${API}/api/cves?limit=1`
    ]
  ],
  [
    "Injection probe q param (server should not 5xx)",
    [
      "curl",
      "-sS",
      "-o",
      "/dev/null",
      "-w",
      "%{http_code}",
      `${WEB}/api/cves?q=${encodeURIComponent("1%' OR 1=1--")}&limit=1`
    ]
  ]
];

let failed = false;
for (const [name, argv] of cases) {
  const r = spawnSync(argv[0], argv.slice(1), { encoding: "utf8" });
  const code = (r.stdout || "").trim();
  // eslint-disable-next-line no-console
  console.log(`${name}: exit=${r.status} out=${code}`);
  if (r.status !== 0) failed = true;
}

if (process.env.RUN_ZAP === "1") {
  const target = process.env.ZAP_TARGET?.trim() || WEB;
  // eslint-disable-next-line no-console
  console.log(`\n> ZAP baseline against ${target} (requires Docker + network)`);
  const zap = spawnSync(
    "docker",
    [
      "run",
      "--rm",
      "-t",
      "ghcr.io/zaproxy/zaproxy:stable",
      "zap-baseline.py",
      "-t",
      target,
      "-I"
    ],
    { stdio: "inherit" }
  );
  if (zap.status !== 0) failed = true;
}

process.exit(failed ? 1 : 0);

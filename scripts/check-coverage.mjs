#!/usr/bin/env node
/**
 * Coverage gate for reliability-critical shared modules (auth, queue, risk, security, metrics, epss).
 * Uses Node built-in test coverage on unit tests only.
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const threshold = Number(process.env.COVERAGE_MIN_LINES ?? "40");
const coverageDir = path.join(root, "coverage");
fs.mkdirSync(coverageDir, { recursive: true });

const criticalPrefixes = [
  "auth/",
  "queue/",
  "risk/",
  "security/",
  "metrics/",
  "cve/published-window.js",
  "exploit/epss-ingest.js"
];

const run = spawnSync(
  process.execPath,
  [
    "--test",
    "--experimental-test-coverage",
    "--test-reporter=lcov",
    "--test-reporter-destination=coverage/lcov.info",
    "packages/shared/test/core.test.mjs",
    "packages/shared/test/roles.test.mjs",
    "packages/shared/test/dlq.test.mjs",
    "packages/shared/test/queue.test.mjs",
    "packages/shared/test/security-policy.test.mjs",
    "packages/shared/test/prometheus.test.mjs",
    "packages/shared/test/epss-ingest.test.mjs"
  ],
  { cwd: root, encoding: "utf8" }
);

if (run.status !== 0) {
  process.stderr.write(run.stdout ?? "");
  process.stderr.write(run.stderr ?? "");
  process.exit(run.status ?? 1);
}

const lcovPath = path.join(root, "coverage/lcov.info");
if (!fs.existsSync(lcovPath)) {
  console.error("FAIL: coverage/lcov.info not generated");
  process.exit(1);
}

const records = fs.readFileSync(lcovPath, "utf8").split("end_of_record\n");
let totalLines = 0;
let coveredLines = 0;
const perFile = [];

for (const rec of records) {
  const sf = rec.match(/^SF:(.+)$/m)?.[1];
  if (!sf) continue;
  const rel = sf.includes("packages/shared/dist/")
    ? sf.split("packages/shared/dist/")[1]
    : path.basename(sf);
  if (!criticalPrefixes.some((p) => rel.startsWith(p) || rel === p || rel.endsWith(p))) continue;

  const lm = [...rec.matchAll(/^DA:(\d+),(\d+)$/gm)];
  if (lm.length === 0) continue;
  const fileTotal = lm.length;
  const fileCovered = lm.filter((m) => Number(m[2]) > 0).length;
  totalLines += fileTotal;
  coveredLines += fileCovered;
  perFile.push({ rel, pct: (fileCovered / fileTotal) * 100 });
}

if (totalLines === 0) {
  console.error("FAIL: no critical module lines in coverage report");
  process.exit(1);
}

const pct = (coveredLines / totalLines) * 100;
for (const f of perFile.sort((a, b) => a.rel.localeCompare(b.rel))) {
  console.log(`  ${f.rel}: ${f.pct.toFixed(1)}%`);
}
console.log(`coverage (critical shared modules): ${pct.toFixed(1)}% lines (${coveredLines}/${totalLines})`);

if (pct < threshold) {
  console.error(`FAIL: below ${threshold}% threshold`);
  process.exit(1);
}

console.log(`ok coverage gate >= ${threshold}%`);

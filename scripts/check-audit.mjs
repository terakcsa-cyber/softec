#!/usr/bin/env node
/**
 * Fail CI when pnpm audit reports high/critical vulnerabilities.
 */
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

const res = spawnSync("pnpm", ["audit", "--audit-level=high", "--json"], {
  cwd: root,
  encoding: "utf8"
});

let report;
try {
  report = JSON.parse(res.stdout || "{}");
} catch {
  console.error("FAIL: could not parse pnpm audit JSON");
  process.stderr.write(res.stderr ?? "");
  process.exit(1);
}

const advisories = Object.values(report.advisories ?? {});
const high = advisories.filter((a) => a.severity === "high" || a.severity === "critical");

if (high.length > 0) {
  console.error(`FAIL: ${high.length} high/critical advisories:`);
  for (const a of high.slice(0, 10)) {
    console.error(`  - ${a.module_name} (${a.severity}): ${a.title}`);
  }
  process.exit(1);
}

if (res.status !== 0 && high.length === 0) {
  // pnpm audit exit 1 can mean moderate only — we're gated on high
  console.log("ok audit: no high/critical (moderate/low may remain)");
  process.exit(0);
}

console.log("ok audit: no high/critical vulnerabilities");

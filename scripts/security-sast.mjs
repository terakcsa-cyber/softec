#!/usr/bin/env node
/**
 * SAST: pnpm audit (монорепо) + Semgrep community packs.
 * Сырой вывод Semgrep: `semgrep-out.json` в корне (добавлен в .gitignore при необходимости).
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

function run(cmd, args, opts = {}) {
  // eslint-disable-next-line no-console
  console.log(`\n> ${cmd} ${args.join(" ")}`);
  return spawnSync(cmd, args, { stdio: "inherit", cwd: root, ...opts });
}

// pnpm@10: audit runs at workspace root (recursive audit flag isn't supported)
const audit = run("pnpm", ["audit", "--audit-level=high"]);
// pnpm audit: 0 = ok, 1 = vulnerabilities (продолжаем к Semgrep)
if (audit.status != null && audit.status !== 0 && audit.status !== 1) {
  process.exit(audit.status);
}

const semgrepConfigs = [
  "p/typescript",
  "p/nodejs",
  "p/react",
  "p/jwt",
  "p/ssrf",
  "p/sql-injection",
  "p/secrets"
];

const strict = process.env.SEMGREP_STRICT === "1";

function runSemgrepScan() {
  const args = [
    "scan",
    ...semgrepConfigs.flatMap((c) => ["--config", c]),
    ...(strict ? ["--error"] : []),
    "--skip-unknown-extensions",
    "--quiet",
    "--json",
    "--output=semgrep-out.json"
  ];

  const local = run("semgrep", args, { env: { ...process.env, SEMGREP_ENABLE_VERSION_CHECK: "0" } });
  if (local.status === 0 || local.status === 1) return local;
  if (local.error?.code === "ENOENT" || local.status === 127) {
    // eslint-disable-next-line no-console
    console.warn("\nSemgrep CLI not found (install: pip install semgrep). Skipping Semgrep scan.");
    return { status: 0 };
  }
  return local;
}

const semgrep = runSemgrepScan();

if (semgrep.status !== 0) {
  // eslint-disable-next-line no-console
  console.warn(
    "\nSemgrep exit non-zero or findings in strict mode. See semgrep-out.json and docs/SECURITY_SAST_FINDINGS.md."
  );
  if (strict || !fs.existsSync(path.join(root, "semgrep-out.json"))) {
    process.exit(semgrep.status ?? 1);
  }
}

// eslint-disable-next-line no-console
console.log("\nsecurity-sast: done (see semgrep-out.json if present).");

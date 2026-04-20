import { existsSync, readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

/** Load monorepo root `.env` from this file's path (Turbo cwd-safe). */
function loadRootEnv(): void {
  const here = dirname(fileURLToPath(import.meta.url));
  const envPath = resolve(here, "../../../.env");
  if (!existsSync(envPath)) {
    return;
  }
  const text = readFileSync(envPath, "utf8");
  for (let line of text.split(/\r?\n/)) {
    line = line.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    /** Уже задано оркестратором (`pnpm dev`) или оболочкой — не затираем (PORT, UPSTREAM и т.д.). */
    if (process.env[key] !== undefined) continue;
    let val = line.slice(eq + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"') && val.length >= 2) ||
      (val.startsWith("'") && val.endsWith("'") && val.length >= 2)
    ) {
      val = val.slice(1, -1);
    }
    process.env[key] = val;
  }
  const has = Boolean(
    process.env.DASHSCOPE_API_KEY || process.env.LLM_API_KEY || process.env.XAI_API_KEY
  );
  // eslint-disable-next-line no-console
  console.log(`[api] Loaded ${envPath} | LLM key present: ${has ? "yes" : "no"}`);
}

loadRootEnv();

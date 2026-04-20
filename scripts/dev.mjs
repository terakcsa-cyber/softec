import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { cleanWebNextCache } from "./clean-web-next-cache.mjs";

const API_HOST = process.env.API_HOST ?? "127.0.0.1";
const WEB_HOST = process.env.WEB_HOST ?? "127.0.0.1";

const lockPath = path.join(process.cwd(), ".dev.lock");

function tryReadLock() {
  try {
    const raw = fs.readFileSync(lockPath, "utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function isPidRunning(pid) {
  if (!pid || typeof pid !== "number") return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

const existing = tryReadLock();
if (existing?.pid && isPidRunning(existing.pid)) {
  // eslint-disable-next-line no-console
  console.error(
    `Dev already running (pid=${existing.pid}). Stop it first or delete ${lockPath} if stale.`
  );
  process.exit(1);
}

try {
  fs.writeFileSync(
    lockPath,
    JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }, null, 2),
    "utf8"
  );
} catch {
  // ignore lock write failures
}

const cleanup = () => {
  try {
    const cur = tryReadLock();
    if (cur?.pid === process.pid) fs.unlinkSync(lockPath);
  } catch {
    // ignore
  }
};
process.on("exit", cleanup);
process.on("SIGINT", () => process.exit(130));
process.on("SIGTERM", () => process.exit(143));

function isPortFreeOnHost(port, host) {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.unref();
    srv.on("error", () => resolve(false));
    srv.listen(port, host, () => srv.close(() => resolve(true)));
  });
}

async function findFreePort(start, host, { maxTries = 200 } = {}) {
  for (let p = start; p < start + maxTries; p++) {
    // eslint-disable-next-line no-await-in-loop
    if (await isPortFreeOnHost(p, host)) return p;
  }
  throw new Error(`No free port found in range ${start}..${start + maxTries - 1}`);
}

const apiBasePort = Number(process.env.API_PORT_BASE ?? 4001);
const webBasePort = Number(process.env.WEB_PORT_BASE ?? 3001);

const maxDevRetries = Number(process.env.DEV_RETRIES ?? 25);

cleanWebNextCache();

for (let attempt = 1; attempt <= maxDevRetries; attempt++) {
  const apiPort = await findFreePort(apiBasePort + (attempt - 1) * 2, API_HOST);
  const webPort = await findFreePort(webBasePort + (attempt - 1) * 2, WEB_HOST);

  const apiBase = `http://${API_HOST}:${apiPort}/api`;
  // eslint-disable-next-line no-console
  console.log(
    [
      `Using ports (attempt ${attempt}/${maxDevRetries}):`,
      `- API: ${apiPort} (${apiBase})`,
      `- Web: ${webPort} (http://${WEB_HOST}:${webPort})`,
      ``
    ].join("\n")
  );

  const jwtSecret =
    process.env.JWT_SECRET?.trim() ||
    "dev-only-change-me-min-32-chars-for-jwt-secret!!";

  const env = {
    ...process.env,
    API_HOST,
    WEB_HOST,
    PORT: String(apiPort),
    WEB_PORT: String(webPort),
    UPSTREAM_API_BASE: apiBase,
    JWT_SECRET: jwtSecret,
    /**
     * Всегда как у поднятого API (`apiBase`). Не брать из `.env`: там часто зашит 4001,
     * а `findFreePort` мог выбрать другой порт — иначе BFF и браузер расходятся с Nest.
     */
    NEXT_PUBLIC_API_BASE: apiBase
  };

  // AI/ingest resolve @vuln-intel/shared from dist; build once so Zod/schemas match source.
  const built = spawnSync("pnpm", ["--filter", "@vuln-intel/shared", "build"], {
    stdio: "inherit",
    env,
    cwd: process.cwd()
  });
  if (built.status !== 0) process.exit(built.status ?? 1);

  const child = spawn("pnpm", ["turbo", "dev"], {
    stdio: "inherit",
    env
  });

  const startedAt = Date.now();
  const exit = await new Promise((resolve) => {
    child.on("exit", (code, signal) => resolve({ code, signal }));
  });

  // If dev process stays up, we never get here. If it exits quickly, retry with new ports.
  const ranForMs = Date.now() - startedAt;
  if (exit.signal) process.kill(process.pid, exit.signal);
  if (exit.code === 0) process.exit(0);
  if (ranForMs > 15_000) process.exit(exit.code ?? 1);
  // eslint-disable-next-line no-console
  console.warn(`Dev crashed after ${ranForMs}ms (code=${exit.code ?? "?"}). Retrying with new ports...`);
}

throw new Error(`Dev failed after ${maxDevRetries} attempts`);


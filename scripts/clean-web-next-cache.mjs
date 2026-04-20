/**
 * Удаляет `apps/web/.next` и корневой `node_modules/.cache`, чтобы не ловить
 * Runtime "Cannot find module './NN.js'" после HMR/сбоя сборки Next/Webpack.
 *
 * Отключить: `DEV_SKIP_NEXT_CLEAN=1`
 * CLI: `node scripts/clean-web-next-cache.mjs` из корня репозитория
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");

export function cleanWebNextCache() {
  if (process.env.DEV_SKIP_NEXT_CLEAN === "1") return false;
  const paths = [
    path.join(REPO_ROOT, "apps/web/.next"),
    path.join(REPO_ROOT, "node_modules/.cache")
  ];
  let cleared = false;
  for (const p of paths) {
    try {
      fs.rmSync(p, { recursive: true, force: true });
      cleared = true;
    } catch {
      // ignore
    }
  }
  if (cleared) {
    // eslint-disable-next-line no-console
    console.log(
      "[clean-web-next-cache] Removed apps/web/.next and node_modules/.cache (DEV_SKIP_NEXT_CLEAN=1 to skip)\n"
    );
  }
  return cleared;
}

const thisFile = path.resolve(fileURLToPath(import.meta.url));
const entryFile = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (entryFile === thisFile) {
  cleanWebNextCache();
}

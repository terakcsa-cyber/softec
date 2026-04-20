import path from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
/** Корневой `.env` монорепозитория — иначе BFF в `app/api/*` не видит UPSTREAM_API_BASE / NEXT_PUBLIC_API_BASE. */
dotenv.config({
  path: path.resolve(__dirname, "../../.env"),
  /** Не перетирать переменные, переданные `scripts/dev.mjs` / turbo (динамический порт API). */
  override: false
});

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  typedRoutes: true
};

export default nextConfig;


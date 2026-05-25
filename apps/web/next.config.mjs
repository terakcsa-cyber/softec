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
  typedRoutes: true,
  poweredByHeader: false,
  // Release builds are gated by `pnpm typecheck`; existing ESLint debt is tracked separately.
  eslint: { ignoreDuringBuilds: true },
  serverExternalPackages: ["yauzl", "fd-slicer", "exceljs"],
  webpack: (config, { isServer }) => {
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
        path: false,
        stream: false
      };
    }
    return config;
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" }
        ]
      }
    ];
  }
};

export default nextConfig;


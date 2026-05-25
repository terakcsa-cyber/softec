import fs from "node:fs";
import net from "node:net";
import path from "node:path";

/** Порты из последнего `pnpm dev` (`.dev-ports.json` в корне монорепо). */
function readDevPortsApiBase(): string | null {
  const candidates = [
    path.resolve(process.cwd(), ".dev-ports.json"),
    path.resolve(process.cwd(), "../../.dev-ports.json"),
    path.resolve(process.cwd(), "../../../.dev-ports.json")
  ];
  for (const file of candidates) {
    try {
      if (!fs.existsSync(file)) continue;
      const raw = fs.readFileSync(file, "utf8");
      const j = JSON.parse(raw) as { apiBase?: string };
      const base = typeof j.apiBase === "string" ? j.apiBase.trim() : "";
      if (base.length > 0) return base.replace(/\/+$/, "");
    } catch {
      // ignore
    }
  }
  return null;
}

/**
 * Next.js BFF проксирует на Nest API. В `pnpm dev` родительский `scripts/dev.mjs` выставляет
 * UPSTREAM_API_BASE на фактический порт API — его нужно использовать, иначе POST /enrich уйдёт не туда.
 */
export function getUpstreamApiBase(): string {
  const norm = (s: string) => s.replace(/\/+$/, "");

  /** В dev предпочитаем `.dev-ports.json` — корневой `.env` часто остаётся на 4001, а API на другом порту / не запущен. */
  if (process.env.NODE_ENV === "development") {
    const fromPorts = readDevPortsApiBase();
    if (fromPorts) {
      assertUpstreamApiBaseSafe(fromPorts);
      return fromPorts;
    }
  }

  const explicit = process.env.UPSTREAM_API_BASE?.trim();
  if (explicit) {
    const out = norm(explicit);
    assertUpstreamApiBaseSafe(out);
    return out;
  }
  const pub = process.env.NEXT_PUBLIC_API_BASE?.trim();
  if (pub) {
    const out = norm(pub);
    assertUpstreamApiBaseSafe(out);
    return out;
  }
  if (process.env.NODE_ENV === "development") {
    const out = "http://127.0.0.1:4001/api";
    assertUpstreamApiBaseSafe(out);
    return out;
  }
  throw new Error(
    "Задайте UPSTREAM_API_BASE или NEXT_PUBLIC_API_BASE (например http://127.0.0.1:4001/api)"
  );
}

/** Блокирует очевидные SSRF-цели для base URL из env (metadata / link-local), не мешая LAN/Docker. */
export function assertUpstreamApiBaseSafe(base: string): void {
  let u: URL;
  try {
    u = new URL(base);
  } catch {
    throw new Error("UPSTREAM_API_BASE / NEXT_PUBLIC_API_BASE: invalid URL");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error("Upstream API base must be http(s)");
  }
  const host = u.hostname.toLowerCase();
  if (
    host === "metadata.google.internal" ||
    host === "metadata" ||
    host.endsWith(".metadata.google.internal")
  ) {
    throw new Error("Upstream hostname is not allowed");
  }
  if (host === "169.254.169.254") {
    throw new Error("Upstream IP is not allowed (cloud metadata)");
  }
  if (net.isIPv6(host) && (host === "fe80::1" || host.startsWith("fe80:"))) {
    throw new Error("Upstream link-local IPv6 is not allowed");
  }
}

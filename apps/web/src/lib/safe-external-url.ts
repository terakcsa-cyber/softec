import net from "node:net";

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "0.0.0.0",
  "::1",
  "metadata.google.internal",
  "metadata",
  "kubernetes.default",
  "kubernetes.default.svc"
]);

/** Доп. разрешённые хосты для RSS ФСТЭК (через запятую), помимо встроенного списка. */
function extraAllowedRssHosts(): string[] {
  const raw = process.env.FSTEC_RSS_ALLOWED_HOSTS?.trim();
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

const DEFAULT_RSS_HOSTS = new Set([
  "t.me",
  "www.t.me",
  "rsshub.app",
  "www.rsshub.app",
  "rsshub.rssforever.com",
  "www.rsshub.rssforever.com"
]);

function hostMatchesAllowed(hostname: string, allowed: string): boolean {
  const h = hostname.toLowerCase();
  const a = allowed.toLowerCase();
  return h === a || h.endsWith(`.${a}`);
}

function isPrivateOrReservedIpv4(octets: number[]): boolean {
  if (octets.length !== 4) return false;
  const a = octets[0]!;
  const b = octets[1]!;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  return false;
}

function parseIpv4(hostname: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostname);
  if (!m) return null;
  const parts = [m[1], m[2], m[3], m[4]].map((x) => Number(x));
  if (parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return parts;
}

/**
 * Блокирует очевидные SSRF-цели для URL из env (приватные/loopback/link-local и т.д.).
 * Для доменных имён проверяется только литерал (DNS rebinding — отдельный слой на периметре).
 */
export function assertSafeHttpUrlForServerSideFetch(urlString: string, kind: "rss" | "generic"): URL {
  let u: URL;
  try {
    u = new URL(urlString);
  } catch {
    throw new Error("Invalid URL");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error("Only http(s) URLs are allowed");
  }
  const host = u.hostname;
  const lower = host.toLowerCase();
  if (BLOCKED_HOSTNAMES.has(lower) || lower.endsWith(".local") || lower.endsWith(".localhost")) {
    throw new Error("Host is not allowed for this fetch");
  }
  if (net.isIPv4(host)) {
    const oct = parseIpv4(host);
    if (oct && isPrivateOrReservedIpv4(oct)) throw new Error("Private/reserved IPv4 is not allowed");
  }
  if (net.isIPv6(host)) {
    if (host === "::1" || host.startsWith("fe80:") || host.startsWith("fc") || host.startsWith("fd")) {
      throw new Error("Private/reserved IPv6 is not allowed");
    }
  }

  if (kind === "rss") {
    const extras = extraAllowedRssHosts();
    const allowed =
      DEFAULT_RSS_HOSTS.has(lower) ||
      [...DEFAULT_RSS_HOSTS].some((a) => hostMatchesAllowed(lower, a)) ||
      extras.some((e) => hostMatchesAllowed(lower, e));
    if (!allowed) {
      throw new Error(
        "RSS host is not on the allowlist. Set FSTEC_RSS_ALLOWED_HOSTS (comma-separated) for self-hosted RSSHub."
      );
    }
  }

  return u;
}

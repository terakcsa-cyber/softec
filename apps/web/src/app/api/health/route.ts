import { NextResponse } from "next/server";

type CheckResult = {
  name: string;
  url: string;
  ok: boolean;
  status: number | null;
  ms: number;
  error?: string;
};

function upstreamBase(): string {
  const base = process.env.UPSTREAM_API_BASE?.trim();
  return base && base.length > 0 ? base : "http://127.0.0.1:4001/api";
}

async function timedFetch(url: string, init: RequestInit, timeoutMs: number): Promise<{
  ok: boolean;
  status: number | null;
  ms: number;
  error?: string;
}> {
  const started = Date.now();
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: ac.signal, cache: "no-store" });
    return { ok: res.ok, status: res.status, ms: Date.now() - started };
  } catch (e) {
    const msg = e instanceof Error ? e.message : "fetch failed";
    return { ok: false, status: null, ms: Date.now() - started, error: msg };
  } finally {
    clearTimeout(t);
  }
}

export async function GET(req: Request) {
  const auth = req.headers.get("authorization") ?? undefined;
  const headers = new Headers();
  if (auth) headers.set("authorization", auth);
  headers.set("accept", "application/json");

  const base = upstreamBase();
  const selfBase = new URL(req.url).origin;

  const targets: Array<{ name: string; url: string; timeoutMs?: number }> = [
    { name: "api.summary", url: `${base}/stats/summary`, timeoutMs: 6_000 },
    { name: "api.queue", url: `${base}/stats/queue`, timeoutMs: 6_000 },
    { name: "api.vendors24h", url: `${base}/stats/vendors?windowHours=24&limit=10`, timeoutMs: 8_000 },
    { name: "api.cves.last24h", url: `${base}/cves?view=last24h&sort=fresh&limit=5`, timeoutMs: 10_000 },
    { name: "api.vendorAdvisories.vendors", url: `${base}/vendor-advisories/vendors`, timeoutMs: 8_000 },
    { name: "web.fstec.feed", url: `${selfBase}/api/fstec/feed`, timeoutMs: 10_000 }
  ];

  const checks = await Promise.all(
    targets.map(async (t): Promise<CheckResult> => {
      const r = await timedFetch(
        t.url,
        {
          method: "GET",
          headers
        },
        t.timeoutMs ?? 8_000
      );
      return { name: t.name, url: t.url, ...r };
    })
  );

  const ok = checks.every((c) => c.ok || c.status === 401 || c.status === 403);

  return NextResponse.json(
    {
      ok,
      checkedAt: new Date().toISOString(),
      upstream: base,
      checks
    },
    { status: ok ? 200 : 503 }
  );
}


import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../lib/upstream-api";

const UPSTREAM_PROXY_TIMEOUT_MS = (() => {
  const n = Number(process.env.UPSTREAM_PROXY_TIMEOUT_MS);
  return Number.isFinite(n) && n > 0 ? Math.min(Math.floor(n), 120_000) : 60_000;
})();

export async function proxyToUpstream(req: Request, upstreamPath: string) {
  const url = new URL(req.url);
  const base = getUpstreamApiBase();
  const target = new URL(`${base}${upstreamPath.startsWith("/") ? "" : "/"}${upstreamPath}`);
  url.searchParams.forEach((v, k) => target.searchParams.set(k, v));

  const headers: Record<string, string> = {
    accept: req.headers.get("accept") || "application/json",
    ...forwardAuthHeaders(req)
  };
  const contentType = req.headers.get("content-type");
  if (contentType) headers["content-type"] = contentType;

  const method = req.method.toUpperCase();
  const body = method === "GET" || method === "HEAD" ? undefined : await req.text();

  const res = await fetch(target.toString(), {
    method,
    headers,
    body,
    cache: "no-store",
    signal: AbortSignal.timeout(UPSTREAM_PROXY_TIMEOUT_MS)
  });

  const outBody = await res.text();
  return new NextResponse(outBody, {
    status: res.status,
    headers: {
      "content-type": res.headers.get("content-type") ?? "application/json",
      "cache-control": "no-store"
    }
  });
}


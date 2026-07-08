import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "../../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../../lib/upstream-api";

export async function GET(req: Request) {
  const url = new URL(req.url);
  const target = new URL(`${getUpstreamApiBase()}/stats/threat-feed`);
  for (const key of ["limit", "offset", "windowHours", "signalType", "sort", "newOnly", "since", "vendor", "watchlistOnly"]) {
    const v = url.searchParams.get(key);
    if (v) target.searchParams.set(key, v);
  }
  const res = await fetch(target.toString(), {
    headers: { accept: "application/json", ...forwardAuthHeaders(req) },
    cache: "no-store"
  });
  const body = await res.text();
  return new NextResponse(body, {
    status: res.status,
    headers: {
      "content-type": res.headers.get("content-type") ?? "application/json",
      "cache-control": "no-store"
    }
  });
}

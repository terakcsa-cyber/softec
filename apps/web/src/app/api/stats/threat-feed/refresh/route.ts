import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "../../../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../../../lib/upstream-api";

export async function POST(req: Request) {
  const url = new URL(req.url);
  const target = new URL(`${getUpstreamApiBase()}/stats/threat-feed/refresh`);
  const force = url.searchParams.get("force");
  if (force) target.searchParams.set("force", force);

  const res = await fetch(target.toString(), {
    method: "POST",
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

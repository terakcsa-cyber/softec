import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "../../../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../../../lib/upstream-api";

export async function POST(req: Request, ctx: { params: Promise<{ bduId: string }> }) {
  const { bduId } = await ctx.params;
  const url = new URL(req.url);
  const force = url.searchParams.get("force");
  const qs = force ? `?force=${encodeURIComponent(force)}` : "";
  const target = `${getUpstreamApiBase()}/bdu/${encodeURIComponent(bduId)}/enrich${qs}`;
  const res = await fetch(target, {
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

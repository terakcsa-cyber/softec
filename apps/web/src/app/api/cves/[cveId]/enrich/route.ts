import { NextResponse } from "next/server";
import { getUpstreamApiBase } from "../../../../../lib/upstream-api";

export async function POST(req: Request, ctx: { params: Promise<{ cveId: string }> }) {
  const { cveId } = await ctx.params;
  const url = new URL(req.url);
  const force = url.searchParams.get("force");
  const qs = force ? `?force=${encodeURIComponent(force)}` : "";
  const target = `${getUpstreamApiBase()}/cves/${encodeURIComponent(cveId)}/enrich${qs}`;
  const res = await fetch(target, {
    method: "POST",
    headers: { accept: "application/json" },
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

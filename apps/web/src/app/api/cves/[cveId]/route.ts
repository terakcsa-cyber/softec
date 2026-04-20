import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "../../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../../lib/upstream-api";

export async function GET(req: Request, ctx: { params: Promise<{ cveId: string }> }) {
  const { cveId } = await ctx.params;
  const target = `${getUpstreamApiBase()}/cves/${encodeURIComponent(cveId)}`;
  const res = await fetch(target, {
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


import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "../../../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../../../lib/upstream-api";

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const target = `${getUpstreamApiBase()}/vuln-tasks/${encodeURIComponent(id)}/cves`;
  const res = await fetch(target, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json", ...forwardAuthHeaders(req) },
    body: await req.text(),
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


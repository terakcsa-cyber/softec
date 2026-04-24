import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "../../../../../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../../../../../lib/upstream-api";

export async function POST(req: Request, ctx: { params: Promise<{ id: string; cveId: string }> }) {
  const { id, cveId } = await ctx.params;
  const target = `${getUpstreamApiBase()}/vuln-tasks/${encodeURIComponent(id)}/cves/${encodeURIComponent(cveId)}/remove`;
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


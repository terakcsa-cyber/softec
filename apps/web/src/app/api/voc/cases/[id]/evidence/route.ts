import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "../../../../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../../../../lib/upstream-api";

async function proxy(req: Request, id: string, suffix: string) {
  const target = `${getUpstreamApiBase()}/voc/cases/${encodeURIComponent(id)}${suffix}`;
  const res = await fetch(target, {
    method: req.method,
    headers: { "content-type": "application/json", accept: "application/json", ...forwardAuthHeaders(req) },
    body: req.method === "GET" ? undefined : await req.text(),
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

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  return proxy(req, id, "/evidence");
}

import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "../../../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../../../lib/upstream-api";

export async function PATCH(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const res = await fetch(`${getUpstreamApiBase()}/voc/alert-rules/${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: { "content-type": "application/json", accept: "application/json", ...forwardAuthHeaders(req) },
    body: await req.text(),
    cache: "no-store"
  });
  const body = await res.text();
  return new NextResponse(body, {
    status: res.status,
    headers: { "content-type": res.headers.get("content-type") ?? "application/json", "cache-control": "no-store" }
  });
}

export async function DELETE(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const res = await fetch(`${getUpstreamApiBase()}/voc/alert-rules/${encodeURIComponent(id)}`, {
    method: "DELETE",
    headers: { accept: "application/json", ...forwardAuthHeaders(req) },
    cache: "no-store"
  });
  const body = await res.text();
  return new NextResponse(body, {
    status: res.status,
    headers: { "content-type": res.headers.get("content-type") ?? "application/json", "cache-control": "no-store" }
  });
}

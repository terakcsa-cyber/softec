import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "../../../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../../../lib/upstream-api";

type Ctx = { params: Promise<{ id: string }> };

export async function PATCH(req: Request, ctx: Ctx) {
  const { id } = await ctx.params;
  const target = `${getUpstreamApiBase()}/voc/watchlist/${encodeURIComponent(id)}`;
  const res = await fetch(target, {
    method: "PATCH",
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

export async function DELETE(req: Request, ctx: Ctx) {
  const { id } = await ctx.params;
  const target = `${getUpstreamApiBase()}/voc/watchlist/${encodeURIComponent(id)}`;
  const res = await fetch(target, {
    method: "DELETE",
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

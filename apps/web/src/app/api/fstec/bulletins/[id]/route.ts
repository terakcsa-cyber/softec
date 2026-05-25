import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "@/lib/upstream-proxy";
import { getUpstreamApiBase } from "@/lib/upstream-api";

type Ctx = { params: Promise<{ id: string }> };

export async function GET(req: Request, ctx: Ctx) {
  const { id } = await ctx.params;
  const target = `${getUpstreamApiBase()}/fstec/bulletins/${encodeURIComponent(id)}`;
  const res = await fetch(target, {
    headers: { accept: "application/json", ...forwardAuthHeaders(req) },
    cache: "no-store"
  });
  const body = await res.text();
  return new NextResponse(body, {
    status: res.status,
    headers: { "content-type": res.headers.get("content-type") ?? "application/json" }
  });
}

export async function DELETE(req: Request, ctx: Ctx) {
  const { id } = await ctx.params;
  const target = `${getUpstreamApiBase()}/fstec/bulletins/${encodeURIComponent(id)}`;
  const res = await fetch(target, {
    method: "DELETE",
    headers: { accept: "application/json", ...forwardAuthHeaders(req) },
    cache: "no-store"
  });
  const body = await res.text();
  return new NextResponse(body, {
    status: res.status,
    headers: { "content-type": res.headers.get("content-type") ?? "application/json" }
  });
}

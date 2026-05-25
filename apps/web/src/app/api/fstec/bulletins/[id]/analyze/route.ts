import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "@/lib/upstream-proxy";
import { getUpstreamApiBase } from "@/lib/upstream-api";

type Ctx = { params: Promise<{ id: string }> };

export async function POST(req: Request, ctx: Ctx) {
  const { id } = await ctx.params;
  const target = `${getUpstreamApiBase()}/fstec/bulletins/${encodeURIComponent(id)}/analyze`;
  const raw = await req.text();
  const res = await fetch(target, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": req.headers.get("content-type") ?? "application/json",
      ...forwardAuthHeaders(req)
    },
    body: raw.length > 0 ? raw : "{}",
    cache: "no-store"
  });
  const body = await res.text();
  return new NextResponse(body, {
    status: res.status,
    headers: { "content-type": res.headers.get("content-type") ?? "application/json" }
  });
}

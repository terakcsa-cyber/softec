import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "@/lib/upstream-proxy";
import { getUpstreamApiBase } from "@/lib/upstream-api";

export async function POST(req: Request, ctx: { params: Promise<{ bduId: string }> }) {
  const { bduId } = await ctx.params;
  const target = `${getUpstreamApiBase()}/telegram/post/bdu/${encodeURIComponent(bduId)}`;
  const requestBody = await req.text();
  const res = await fetch(target, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      ...forwardAuthHeaders(req)
    },
    body: requestBody || "{}",
    cache: "no-store"
  });
  const responseBody = await res.text();
  return new NextResponse(responseBody, {
    status: res.status,
    headers: {
      "content-type": res.headers.get("content-type") ?? "application/json",
      "cache-control": "no-store"
    }
  });
}

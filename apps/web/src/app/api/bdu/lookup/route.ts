import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "../../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../../lib/upstream-api";

export async function POST(req: Request) {
  const body = await req.text();
  const target = `${getUpstreamApiBase()}/bdu/lookup`;
  const res = await fetch(target, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      ...forwardAuthHeaders(req)
    },
    body,
    cache: "no-store"
  });
  const text = await res.text();
  return new NextResponse(text, {
    status: res.status,
    headers: {
      "content-type": res.headers.get("content-type") ?? "application/json",
      "cache-control": "no-store"
    }
  });
}

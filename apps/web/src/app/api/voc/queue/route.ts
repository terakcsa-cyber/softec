import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "../../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../../lib/upstream-api";

export async function GET(req: Request) {
  const url = new URL(req.url);
  const target = new URL(`${getUpstreamApiBase()}/voc/queue`);
  url.searchParams.forEach((v, k) => target.searchParams.set(k, v));

  const res = await fetch(target.toString(), {
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

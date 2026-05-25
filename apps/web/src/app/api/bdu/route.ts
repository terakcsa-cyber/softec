import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../lib/upstream-api";

export async function GET(req: Request) {
  const url = new URL(req.url);
  const target = new URL(`${getUpstreamApiBase()}/bdu`);
  url.searchParams.forEach((v, k) => target.searchParams.set(k, v));

  const res = await fetch(target.toString(), {
    headers: { accept: "application/json", ...forwardAuthHeaders(req) },
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

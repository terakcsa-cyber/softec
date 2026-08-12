import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "../../../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../../../lib/upstream-api";

export async function POST(req: Request) {
  const target = `${getUpstreamApiBase()}/settings/updates/apply`;
  const res = await fetch(target, {
    method: "POST",
    headers: {
      accept: "application/json",
      ...forwardAuthHeaders(req)
    },
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

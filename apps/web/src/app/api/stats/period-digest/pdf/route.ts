import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "../../../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../../../lib/upstream-api";

export async function POST(req: Request) {
  const target = `${getUpstreamApiBase()}/stats/period-digest/pdf`;
  const res = await fetch(target, {
    method: "POST",
    headers: {
      accept: "application/pdf",
      "content-type": req.headers.get("content-type") ?? "application/json",
      ...forwardAuthHeaders(req)
    },
    body: await req.arrayBuffer(),
    cache: "no-store"
  });
  const body = await res.arrayBuffer();
  const headers = new Headers();
  headers.set("content-type", res.headers.get("content-type") ?? "application/pdf");
  headers.set("cache-control", "no-store");
  const disposition = res.headers.get("content-disposition");
  if (disposition) headers.set("content-disposition", disposition);
  return new NextResponse(body, { status: res.status, headers });
}

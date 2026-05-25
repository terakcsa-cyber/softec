import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "@/lib/upstream-proxy";
import { getUpstreamApiBase } from "@/lib/upstream-api";

export async function GET(req: Request) {
  const url = new URL(req.url);
  const qs = url.searchParams.toString();
  const target = `${getUpstreamApiBase()}/fstec/bulletins${qs ? `?${qs}` : ""}`;
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

export async function POST(req: Request) {
  const target = `${getUpstreamApiBase()}/fstec/bulletins`;
  const raw = await req.text();
  const res = await fetch(target, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": req.headers.get("content-type") ?? "application/json",
      ...forwardAuthHeaders(req)
    },
    body: raw,
    cache: "no-store"
  });
  const body = await res.text();
  return new NextResponse(body, {
    status: res.status,
    headers: { "content-type": res.headers.get("content-type") ?? "application/json" }
  });
}

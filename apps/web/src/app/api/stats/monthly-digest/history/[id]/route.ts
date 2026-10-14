import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "../../../../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../../../../lib/upstream-api";

const FILE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!FILE_ID.test(id)) {
    return new NextResponse("Not found", { status: 404, headers: { "cache-control": "no-store" } });
  }
  const target = `${getUpstreamApiBase()}/stats/monthly-digest/history/${encodeURIComponent(id)}`;
  const res = await fetch(target, {
    headers: { accept: "application/pdf", ...forwardAuthHeaders(req) },
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

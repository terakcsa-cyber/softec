import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "../../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../../lib/upstream-api";

export const dynamic = "force-dynamic";

const ALLOW = new Set(["GET", "POST", "HEAD"]);

export async function GET(
  req: Request,
  ctx: { params: Promise<{ path: string[] }> }
) {
  const { path } = await ctx.params;
  return proxyAuth(req, path);
}

export async function POST(
  req: Request,
  ctx: { params: Promise<{ path: string[] }> }
) {
  const { path } = await ctx.params;
  return proxyAuth(req, path);
}

export async function HEAD(
  req: Request,
  ctx: { params: Promise<{ path: string[] }> }
) {
  const { path } = await ctx.params;
  return proxyAuth(req, path);
}

async function proxyAuth(req: Request, path: string[]) {
  if (!path?.length) {
    return NextResponse.json({ message: "Not found" }, { status: 404 });
  }
  const subpath = path.map((p) => encodeURIComponent(p)).join("/");
  const upstream = `${getUpstreamApiBase()}/auth/${subpath}`;
  const u = new URL(req.url);
  const target = `${upstream}${u.search}`;

  const method = req.method.toUpperCase();
  if (!ALLOW.has(method)) {
    return NextResponse.json({ message: "Method not allowed" }, { status: 405 });
  }

  const headers: Record<string, string> = {
    accept: req.headers.get("accept") ?? "application/json",
    ...forwardAuthHeaders(req)
  };

  const init: RequestInit = {
    method,
    headers,
    cache: "no-store"
  };

  if (method === "POST") {
    const ct = req.headers.get("content-type");
    if (ct) headers["content-type"] = ct;
    init.body = await req.arrayBuffer();
  }

  try {
    const res = await fetch(target, init);
    const body = await res.arrayBuffer();
    return new NextResponse(body, {
      status: res.status,
      headers: {
        "content-type": res.headers.get("content-type") ?? "application/json",
        "cache-control": "no-store"
      }
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : "fetch failed";
    const base = getUpstreamApiBase();
    return NextResponse.json(
      {
        message: `Upstream API unreachable (${msg}). Проверьте, что API запущен и UPSTREAM_API_BASE / порт верны.`,
        statusCode: 502,
        ...(process.env.NODE_ENV !== "production" ? { upstream: base } : {})
      },
      { status: 502 }
    );
  }
}

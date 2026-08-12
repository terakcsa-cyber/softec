import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "@/lib/upstream-proxy";
import { getUpstreamApiBase } from "@/lib/upstream-api";

export const maxDuration = 300;

export async function POST(req: Request) {
  const target = `${getUpstreamApiBase()}/settings/tls/letsencrypt/renew`;
  try {
    const res = await fetch(target, {
      method: "POST",
      headers: {
        accept: "application/json",
        ...forwardAuthHeaders(req)
      },
      cache: "no-store",
      signal: AbortSignal.timeout(240_000)
    });
    const body = await res.text();
    return new NextResponse(body || JSON.stringify({ message: `Upstream TLS renew HTTP ${res.status}` }), {
      status: res.status,
      headers: {
        "content-type": res.headers.get("content-type") ?? "application/json",
        "cache-control": "no-store"
      }
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const timedOut = /timeout|aborted|AbortError/i.test(msg);
    return NextResponse.json(
      {
        message: timedOut
          ? "Таймаут обновления Let's Encrypt. Смотрите логи api / certbot renew."
          : `BFF не достучался до API для renew: ${msg}`
      },
      { status: 504 }
    );
  }
}

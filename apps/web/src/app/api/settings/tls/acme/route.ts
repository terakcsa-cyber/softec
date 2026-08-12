import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "@/lib/upstream-proxy";
import { getUpstreamApiBase } from "@/lib/upstream-api";

/** Certbot HTTP-01 can take up to ~3 minutes. */
export const maxDuration = 300;

export async function POST(req: Request) {
  const target = `${getUpstreamApiBase()}/settings/tls/letsencrypt`;
  const raw = await req.text();
  try {
    const res = await fetch(target, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": req.headers.get("content-type") ?? "application/json",
        ...forwardAuthHeaders(req)
      },
      body: raw,
      cache: "no-store",
      signal: AbortSignal.timeout(240_000)
    });
    const body = await res.text();
    return new NextResponse(body || JSON.stringify({ message: `Upstream TLS API HTTP ${res.status}` }), {
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
          ? "Таймаут выпуска Let's Encrypt (API/certbot > 4 мин). Проверьте порт 80, логи api и что LE достучится до /.well-known/acme-challenge/."
          : `BFF не достучался до API для Let's Encrypt: ${msg}`
      },
      { status: 504 }
    );
  }
}

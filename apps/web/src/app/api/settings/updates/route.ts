import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "../../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../../lib/upstream-api";

export async function GET(req: Request) {
  const target = `${getUpstreamApiBase()}/settings/updates`;
  try {
    const res = await fetch(target, {
      headers: { accept: "application/json", ...forwardAuthHeaders(req) },
      cache: "no-store",
      signal: AbortSignal.timeout(20_000)
    });
    const body = await res.text();
    return new NextResponse(body, {
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
          ? "Таймаут статуса обновлений. API, скорее всего, завис на git/docker — нажмите «Проверить обновления» после перезагрузки страницы."
          : `BFF не достучался до API обновлений: ${msg}`
      },
      { status: 504 }
    );
  }
}

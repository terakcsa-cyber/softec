import { NextResponse } from "next/server";
import { forwardAuthHeaders } from "../../../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../../../lib/upstream-api";

export async function POST(req: Request) {
  const target = `${getUpstreamApiBase()}/settings/updates/check`;
  try {
    const res = await fetch(target, {
      method: "POST",
      headers: {
        accept: "application/json",
        ...forwardAuthHeaders(req)
      },
      cache: "no-store",
      signal: AbortSignal.timeout(45_000)
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
          ? "Таймаут git fetch (GitHub/SSH из контейнера). Задайте HTTPS PLATFORM_UPDATE_REPO_URL или обновите вручную: git pull && ./deploy.sh --yes --update"
          : `BFF не достучался до API проверки обновлений: ${msg}`
      },
      { status: 504 }
    );
  }
}

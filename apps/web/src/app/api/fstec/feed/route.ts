import { NextResponse } from "next/server";
import { enrichFeedItemsWithLocalBdu } from "@/lib/fstec-feed-enrich";
import { parseRssOrAtom } from "@/lib/fstec-rss";
import { looksLikeTelegramChannelPreview, parseTelegramChannelPreviewHtml } from "@/lib/fstec-telegram-preview";

/** По умолчанию — публичная страница Telegram (стабильнее, чем RSSHub с 403). */
const DEFAULT_TG_CHANNEL = "bdufstecru";

/** RSSHub (только если явно включён режим rss). */
const DEFAULT_FSTEC_RSS_URL = "https://rsshub.app/telegram/channel/bdufstecru";

type FeedSourceMode = "telegram" | "rss";

function resolveFeedMode(): FeedSourceMode {
  const m = process.env.FSTEC_FEED_SOURCE?.trim().toLowerCase();
  if (m === "rss") return "rss";
  return "telegram";
}

function resolveChannel(): string {
  const raw = process.env.FSTEC_TG_CHANNEL?.trim();
  const ch = (raw && raw.length > 0 ? raw : DEFAULT_TG_CHANNEL).replace(/^@/, "");
  if (!/^[a-zA-Z][a-zA-Z0-9_]{3,63}$/.test(ch)) {
    throw new Error("Invalid FSTEC_TG_CHANNEL (ожидается username канала без @)");
  }
  return ch;
}

function resolveFeedUrl(): string {
  const raw = process.env.FSTEC_TG_RSS_URL?.trim();
  return raw && raw.length > 0 ? raw : DEFAULT_FSTEC_RSS_URL;
}

function assertHttpUrl(url: string): URL {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new Error("Invalid URL");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error("Only http(s) URLs are allowed");
  }
  return u;
}

const DEFAULT_BROWSER_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

function browserUserAgent(): string {
  return process.env.FSTEC_RSS_USER_AGENT?.trim() || DEFAULT_BROWSER_UA;
}

function telegramPreviewHeaders(): HeadersInit {
  return {
    accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    "user-agent": browserUserAgent(),
    referer: "https://t.me/",
    origin: "https://t.me"
  };
}

function rssRequestHeaders(targetUrl: string): HeadersInit {
  const ua = browserUserAgent();
  let origin = "";
  try {
    origin = new URL(targetUrl).origin;
  } catch {
    // ignore
  }
  return {
    accept: "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.8",
    "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    "user-agent": ua,
    ...(origin ? { referer: `${origin}/`, origin } : {})
  };
}

function rssUpstreamErrorMessage(status: number): string {
  const base = `RSS upstream returned HTTP ${status}`;
  if (status === 403) {
    return (
      `${base}. Публичный RSSHub часто режет серверные запросы — переключитесь на источник по умолчанию ` +
      `(уберите FSTEC_FEED_SOURCE=rss) или поднимите свой RSSHub в FSTEC_TG_RSS_URL.`
    );
  }
  if (status === 429) {
    return `${base}. Слишком много запросов — увеличьте интервал или используйте свой инстанс RSS.`;
  }
  return base;
}

async function getFeedFromTelegramPreview() {
  const channel = resolveChannel();
  const url = `https://t.me/s/${encodeURIComponent(channel)}`;
  const res = await fetch(url, {
    headers: telegramPreviewHeaders(),
    next: { revalidate: 120 }
  });
  if (!res.ok) {
    return NextResponse.json(
      {
        error: `Telegram вернул HTTP ${res.status}. Проверьте, что канал публичный и имя в FSTEC_TG_CHANNEL верное.`
      },
      { status: 502 }
    );
  }
  const html = await res.text();
  if (!looksLikeTelegramChannelPreview(html)) {
    return NextResponse.json(
      {
        error:
          "Не удалось разобрать страницу Telegram (изменилась вёрстка или пришла не HTML-страница канала). Попробуйте позже или режим FSTEC_FEED_SOURCE=rss со своим RSS."
      },
      { status: 502 }
    );
  }
  const items = parseTelegramChannelPreviewHtml(html);
  const localBduEnrichment = await enrichFeedItemsWithLocalBdu(items);
  return NextResponse.json({
    items,
    source: {
      url,
      fetchedAt: new Date().toISOString(),
      kind: "telegram" as const,
      channel: `@${channel}`,
      localBduEnrichment
    }
  });
}

async function getFeedFromRss() {
  const url = resolveFeedUrl();
  try {
    assertHttpUrl(url);
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Invalid URL";
    return NextResponse.json({ error: msg }, { status: 500 });
  }

  const res = await fetch(url, {
    headers: rssRequestHeaders(url),
    next: { revalidate: 120 }
  });
  if (!res.ok) {
    return NextResponse.json({ error: rssUpstreamErrorMessage(res.status) }, { status: 502 });
  }
  const xml = await res.text();
  const head = xml.slice(0, 800).trimStart().toLowerCase();
  if (head.startsWith("<!doctype html") || head.startsWith("<html")) {
    return NextResponse.json(
      {
        error:
          "RSS URL вернул HTML вместо XML (часто Cloudflare у публичного RSSHub). Используйте режим Telegram по умолчанию или свой инстанс RSS."
      },
      { status: 502 }
    );
  }
  const items = parseRssOrAtom(xml);
  const localBduEnrichment = await enrichFeedItemsWithLocalBdu(items);
  return NextResponse.json({
    items,
    source: {
      url,
      fetchedAt: new Date().toISOString(),
      kind: "rss" as const,
      localBduEnrichment
    }
  });
}

export async function GET() {
  const mode = resolveFeedMode();

  try {
    if (mode === "rss") {
      return await getFeedFromRss();
    }
    return await getFeedFromTelegramPreview();
  } catch (e) {
    if (e instanceof Error && e.message.includes("FSTEC_TG_CHANNEL")) {
      return NextResponse.json({ error: e.message }, { status: 500 });
    }
    const msg = e instanceof Error ? e.message : "Failed to load feed";
    return NextResponse.json({ error: msg }, { status: 502 });
  }
}

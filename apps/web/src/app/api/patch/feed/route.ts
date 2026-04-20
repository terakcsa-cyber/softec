import { NextResponse } from "next/server";
import { looksLikeTelegramChannelPreview, parseTelegramChannelPreviewHtml } from "@/lib/fstec-telegram-preview";

type PatchChannel = { slug: string; title: string };

const CHANNELS: PatchChannel[] = [
  { slug: "avleonovrus", title: "Управление Уязвимостями и прочее" },
  { slug: "true_secator", title: "SecAtor" },
  { slug: "kasperskylab_ru", title: "Kaspersky" },
  { slug: "bizone_channel", title: "BI.ZONE" },
  { slug: "ZerodayAlert", title: "0day Alert" },
  { slug: "SecLabNews", title: "SecurityLab.ru" },
  { slug: "fstecru", title: "Новости информационной безопасности" },
  { slug: "easy_infosec_tg", title: "Easy InfoSec" },
  { slug: "cyberok_news", title: "SyberOK_News" },
  { slug: "security_kz", title: "SecuriXy.kz" }
];

type FeedItem = {
  id: string;
  title: string;
  link: string;
  pubDate: string | null;
  descriptionText: string;
  channel: { slug: string; title: string };
  cveIds: string[];
};

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

function uniq<T>(arr: T[]): T[] {
  return [...new Set(arr)];
}

function extractCveIds(text: string): string[] {
  const hits = text.match(/\bCVE-\d{4}-\d{4,}\b/gi) ?? [];
  return uniq(hits.map((h) => h.toUpperCase())).slice(0, 24);
}

function extractFetchErrorMessage(e: unknown): string {
  const anyErr = e as any;
  const msg = e instanceof Error ? e.message : "Failed to load feed";
  const cause = anyErr?.cause;
  const code: string | undefined = cause?.code || anyErr?.code;
  const hostname: string | undefined = cause?.hostname || anyErr?.hostname;
  if (code === "ENOTFOUND") return `Нет доступа к интернету/DNS: не удалось разрешить домен${hostname ? ` (${hostname})` : ""}.`;
  if (code === "EAI_AGAIN") return `Проблема с DNS (EAI_AGAIN)${hostname ? ` для ${hostname}` : ""} — попробуйте позже.`;
  if (code === "ETIMEDOUT") return "Таймаут соединения (ETIMEDOUT) — проверьте сеть или попробуйте позже.";
  const causeMsg = typeof cause?.message === "string" ? cause.message : "";
  return causeMsg ? `${msg}: ${causeMsg}` : msg;
}

async function fetchChannel(channel: PatchChannel): Promise<{ url: string; items: FeedItem[] } | { url: string; error: string }> {
  const url = `https://t.me/s/${encodeURIComponent(channel.slug)}`;
  const res = await fetch(url, { headers: telegramPreviewHeaders(), next: { revalidate: 30 } });
  if (!res.ok) {
    return { url, error: `Telegram вернул HTTP ${res.status} для @${channel.slug}` };
  }
  const html = await res.text();
  if (!looksLikeTelegramChannelPreview(html)) {
    return { url, error: `Не удалось разобрать HTML Telegram для @${channel.slug}` };
  }
  const base = parseTelegramChannelPreviewHtml(html);
  const items: FeedItem[] = base.map((it) => {
    const text = `${it.title}\n${it.descriptionText ?? ""}`.trim();
    const cveIds = extractCveIds(text);
    return {
      ...it,
      channel,
      cveIds
    };
  });
  return { url, items };
}

export async function GET() {
  try {
    const results = await Promise.all(CHANNELS.map((c) => fetchChannel(c)));
    const errors = results
      .filter((r): r is { url: string; error: string } => "error" in r)
      .map((e) => ({ url: e.url, error: e.error }));
    const items = results
      .filter((r): r is { url: string; items: FeedItem[] } => "items" in r)
      .flatMap((r) => r.items);

    items.sort((a, b) => {
      const ta = a.pubDate ? new Date(a.pubDate).getTime() : 0;
      const tb = b.pubDate ? new Date(b.pubDate).getTime() : 0;
      return tb - ta;
    });

    return NextResponse.json({
      items: items.slice(0, 120),
      source: {
        fetchedAt: new Date().toISOString(),
        kind: "telegram_multi" as const,
        channels: CHANNELS
      },
      errors: errors.length ? errors : undefined
    });
  } catch (e) {
    return NextResponse.json({ error: extractFetchErrorMessage(e) }, { status: 502 });
  }
}


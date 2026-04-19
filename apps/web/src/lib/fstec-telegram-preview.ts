import { parse } from "node-html-parser";
import type { FstecFeedItem } from "./fstec-rss";
import { stripHtmlToText } from "./fstec-rss";

function titleFromDescription(text: string): string {
  const t = text.replace(/\s+/g, " ").trim();
  if (!t) return "Сообщение";
  if (t.length <= 160) return t;
  return `${t.slice(0, 157).trimEnd()}…`;
}

/**
 * Парсит публичную HTML-страницу канала Telegram (`https://t.me/s/username`).
 * Не требует RSSHub и обычно доступна с сервера без 403 (в отличие от публичного RSSHub).
 */
export function parseTelegramChannelPreviewHtml(html: string): FstecFeedItem[] {
  const root = parse(html);
  const wraps = root.querySelectorAll(".tgme_widget_message_wrap");
  const byLink = new Map<string, FstecFeedItem>();

  for (const wrap of wraps) {
    const dateA = wrap.querySelector("a.tgme_widget_message_date");
    if (!dateA) continue;
    const link = (dateA.getAttribute("href") ?? "").trim();
    if (!link || byLink.has(link)) continue;

    const timeEl = dateA.querySelector("time");
    const pubDate = timeEl?.getAttribute("datetime")?.trim() ?? null;

    const textEl = wrap.querySelector(".tgme_widget_message_text");
    const rawHtml = textEl?.innerHTML ?? "";
    const descriptionText = stripHtmlToText(rawHtml);

    const title = titleFromDescription(descriptionText);
    byLink.set(link, {
      id: link,
      title,
      link,
      pubDate,
      descriptionText
    });
  }

  const items = [...byLink.values()];
  /** На странице сообщения идут от старых к новым — показываем сначала свежие. */
  items.reverse();
  return items;
}

export function looksLikeTelegramChannelPreview(html: string): boolean {
  const h = html.slice(0, 50_000).toLowerCase();
  return h.includes("tgme_widget_message_wrap") && h.includes("tgme_widget_message_date");
}

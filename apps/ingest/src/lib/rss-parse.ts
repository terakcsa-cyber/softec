import { XMLParser } from "fast-xml-parser";

export type RssFeedItem = {
  id: string;
  title: string;
  link: string;
  pubDate: string | null;
  descriptionText: string;
};

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  trimValues: true,
  // У внешних RSS/Atom нередко встречаются большие наборы entities, из-за чего fast-xml-parser
  // может падать на лимите расширения. Нам не нужно разворачивать entities на уровне XML —
  // мы нормализуем текст сами в stripHtmlToText/decodeBasicEntities.
  processEntities: false
});

function decodeBasicEntities(s: string): string {
  return s
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

export function stripHtmlToText(html: string): string {
  const noTags = html.replace(/<[^>]*>/g, " ");
  return decodeBasicEntities(noTags).replace(/\s+/g, " ").trim();
}

function pickText(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "string") return v.trim();
  if (typeof v === "object" && v !== null && "#text" in v) {
    return String((v as { "#text": unknown })["#text"]).trim();
  }
  return String(v).trim();
}

function atomLinkHref(link: unknown): string {
  if (link == null) return "";
  const rows = Array.isArray(link) ? link : [link];
  let fallback = "";
  for (const row of rows) {
    if (row && typeof row === "object") {
      const o = row as { "@_href"?: string; href?: string; "@_rel"?: string; rel?: string };
      const href = o["@_href"] ?? o.href ?? "";
      const rel = o["@_rel"] ?? o.rel ?? "";
      if (href && (rel === "alternate" || rel === "")) return href;
      if (href && !fallback) fallback = href;
    } else if (typeof row === "string") {
      return row;
    }
  }
  return fallback;
}

function mapRssItems(raw: unknown): RssFeedItem[] {
  const items = Array.isArray(raw) ? raw : raw ? [raw] : [];
  return items.map((it, i) => {
    const row = it as Record<string, unknown>;
    const title = pickText(row.title);
    let link = pickText(row.link);
    if (!link && row.guid) {
      const g = row.guid;
      if (typeof g === "string") link = g.trim();
      else if (g && typeof g === "object") {
        const go = g as Record<string, unknown>;
        link = pickText(go["#text"]);
      }
    }
    const pubDate = row.pubDate ? String(row.pubDate) : null;
    const descRaw = row.description ?? row["content:encoded"] ?? "";
    const descriptionText = stripHtmlToText(pickText(descRaw) || String(descRaw ?? ""));
    const id = link || `${title}-${i}`;
    return { id, title, link, pubDate, descriptionText };
  });
}

function mapAtomEntries(raw: unknown): RssFeedItem[] {
  const entries = Array.isArray(raw) ? raw : raw ? [raw] : [];
  return entries.map((ent, i) => {
    const row = ent as Record<string, unknown>;
    const title = pickText(row.title);
    const link = atomLinkHref(row.link);
    const pubDate = row.updated ? String(row.updated) : row.published ? String(row.published) : null;
    const summary = row.summary ?? row.content;
    const descriptionText = stripHtmlToText(pickText(summary));
    const id = link || pickText(row.id) || `${title}-${i}`;
    return { id, title, link, pubDate, descriptionText };
  });
}

export function parseRssOrAtom(xml: string): RssFeedItem[] {
  const doc = xmlParser.parse(xml) as Record<string, unknown>;
  const rssChannel = (doc.rss as Record<string, unknown> | undefined)?.channel as
    | Record<string, unknown>
    | undefined;
  if (rssChannel?.item) {
    return mapRssItems(rssChannel.item);
  }
  const feed = doc.feed as Record<string, unknown> | undefined;
  if (feed?.entry) {
    return mapAtomEntries(feed.entry);
  }
  return [];
}

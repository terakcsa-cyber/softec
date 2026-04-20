import { createHash } from "node:crypto";
import { Inject, Injectable, OnModuleInit } from "@nestjs/common";
import { DbService } from "../services/db.service.js";
import { parseRssOrAtom, type RssFeedItem } from "../lib/rss-parse.js";

export type PatchFeedSource = {
  feedUrl: string;
  vendorSlug: string;
};

/**
 * Публичные ленты (без токенов): международные вендоры + русскоязычные (банки/ИБ/СМИ о патчах).
 * Используются, если `PATCH_ADVISORY_SOURCES` не задан или пустой. Переопределение — JSON в env.
 */
function defaultSources(): PatchFeedSource[] {
  return [
    /** Регулятор и банковский контекст (материалы на русском; не только ИБ, но релевантно КФИ). */
    { feedUrl: "https://www.cbr.ru/rss/RssNews", vendorSlug: "cbr_ru" },
    { feedUrl: "https://www.cbr.ru/rss/RssPress", vendorSlug: "cbr_press_ru" },
    /** Русские тексты о выходе обновлений безопасности (Microsoft, Google и др.). */
    { feedUrl: "https://safe-surf.ru/rss", vendorSlug: "safe_surf_ru" },
    /** IT-новости на русском, часто упоминания CVE и уязвимостей. */
    { feedUrl: "https://www.opennet.ru/opennews/opennews_all_noadv.rss", vendorSlug: "opennet_ru" },
    /** Профильная ИБ-пресса (русский). */
    { feedUrl: "https://xakep.ru/rss/post/", vendorSlug: "xakep_ru" },

    { feedUrl: "https://www.debian.org/security/dsa?format=rss", vendorSlug: "debian" },
    { feedUrl: "https://ubuntu.com/security/notices/rss.xml", vendorSlug: "ubuntu" },
    { feedUrl: "https://security.suse.com/rss.xml", vendorSlug: "suse" },
    { feedUrl: "https://www.redhat.com/en/rss/blog/security", vendorSlug: "redhat" },
    {
      feedUrl: "https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml",
      vendorSlug: "oracle"
    },
    /** Публичный RSS API (не страница update-guide в браузере — она отдаёт HTML). */
    { feedUrl: "https://api.msrc.microsoft.com/update-guide/rss", vendorSlug: "microsoft" },
    { feedUrl: "https://aws.amazon.com/security/security-bulletins/rss/feed/", vendorSlug: "aws" },
    {
      feedUrl: "https://cloud.google.com/feeds/google-cloud-security-bulletins.xml",
      vendorSlug: "google_cloud"
    },
    { feedUrl: "https://www.cisa.gov/uscert/ncas/alerts.xml", vendorSlug: "cisa_alerts" },
    { feedUrl: "https://www.cisa.gov/uscert/ncas/current-activity.xml", vendorSlug: "cisa_activity" },
    { feedUrl: "https://www.cisa.gov/uscert/ics/advisories/advisories.xml", vendorSlug: "cisa_ics" },
    { feedUrl: "https://kubernetes.io/feed.xml", vendorSlug: "kubernetes" },
    { feedUrl: "https://blog.cloudflare.com/rss/", vendorSlug: "cloudflare" },
    { feedUrl: "https://unit42.paloaltonetworks.com/feed/", vendorSlug: "unit42" },
    { feedUrl: "https://www.sentinelone.com/labs/feed/", vendorSlug: "sentinelone" }
  ];
}

function loadSourcesFromEnv(): PatchFeedSource[] {
  const raw = process.env.PATCH_ADVISORY_SOURCES?.trim();
  if (!raw) return defaultSources();
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return defaultSources();
    const out: PatchFeedSource[] = [];
    for (const row of parsed) {
      if (!row || typeof row !== "object") continue;
      const o = row as Record<string, unknown>;
      const feedUrl = typeof o.feedUrl === "string" ? o.feedUrl.trim() : "";
      const vendorSlug =
        typeof o.vendorSlug === "string" && o.vendorSlug.trim().length > 0
          ? o.vendorSlug.trim().toLowerCase().replace(/\s+/g, "_")
          : "unknown";
      if (feedUrl.startsWith("http://") || feedUrl.startsWith("https://")) {
        out.push({ feedUrl, vendorSlug });
      }
    }
    return out;
  } catch {
    return defaultSources();
  }
}

function extractCveIds(text: string): string[] {
  const re = /\bCVE-\d{4}-\d+\b/gi;
  const set = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    set.add(m[0].toUpperCase());
  }
  return [...set].sort();
}

function dedupeKey(feedUrl: string, item: RssFeedItem): string {
  const basis = item.link?.trim() || item.id || item.title;
  return createHash("sha256").update(`${feedUrl}\n${basis}`).digest("hex");
}

function parsePubDate(isoOrRfc: string | null): Date | null {
  if (!isoOrRfc) return null;
  const d = new Date(isoOrRfc);
  if (Number.isNaN(d.getTime())) return null;
  return d;
}

@Injectable()
export class VendorAdvisoryIngestJob implements OnModuleInit {
  constructor(@Inject(DbService) private readonly db: DbService) {}

  async onModuleInit() {
    const intervalMs = Math.max(60_000, Number(process.env.PATCH_ADVISORY_POLL_INTERVAL_MS ?? 30 * 60 * 1000));
    const initialDelayMs = Number(process.env.PATCH_ADVISORY_INITIAL_DELAY_MS ?? 8_000);

    setTimeout(() => {
      this.runForever(intervalMs).catch((e) => {
        // eslint-disable-next-line no-console
        console.error(e);
        process.exit(1);
      });
    }, initialDelayMs);
  }

  private async runForever(intervalMs: number) {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const startedAt = Date.now();
      try {
        // eslint-disable-next-line no-console
        console.log("[ingest:patch-advisory] цикл: старт");
        await this.runOnce();
        // eslint-disable-next-line no-console
        console.log("[ingest:patch-advisory] цикл: завершён");
      } catch (e) {
        // eslint-disable-next-line no-console
        console.error("[ingest:patch-advisory] ошибка цикла", e);
      } finally {
        const sleep = Math.max(5_000, intervalMs - (Date.now() - startedAt));
        await new Promise((r) => setTimeout(r, sleep));
      }
    }
  }

  private async runOnce() {
    const sources = loadSourcesFromEnv();
    if (sources.length === 0) {
      // eslint-disable-next-line no-console
      console.log(
        "[ingest:patch-advisory] PATCH_ADVISORY_SOURCES задан как пустой список — импорт лент отключён. Удалите переменную для источников по умолчанию или укажите JSON с лентами."
      );
      return;
    }

    let upserted = 0;
    for (const src of sources) {
      // eslint-disable-next-line no-await-in-loop
      const n = await this.ingestFeed(src);
      upserted += n;
    }
    if (upserted > 0) {
      // eslint-disable-next-line no-console
      console.log(`[ingest:patch-advisory] записей обработано: ${upserted}`);
    }
  }

  private async ingestFeed(src: PatchFeedSource): Promise<number> {
    const res = await fetch(src.feedUrl, {
      headers: {
        accept: "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.8",
        "user-agent": "vuln-intel-platform/1.0 (patch-advisory-ingest)"
      },
      signal: AbortSignal.timeout(Math.max(10_000, Number(process.env.PATCH_ADVISORY_FETCH_TIMEOUT_MS ?? 45_000)))
    });
    if (!res.ok) {
      // eslint-disable-next-line no-console
      console.warn(`[ingest:patch-advisory] лента ответила HTTP ${res.status}: ${src.feedUrl}`);
      return 0;
    }
    const xml = await res.text();
    const items = parseRssOrAtom(xml);
    let n = 0;
    for (const item of items) {
      if (!item.title?.trim()) continue;
      const link = item.link?.trim() || src.feedUrl;
      const text = `${item.title}\n${item.descriptionText}`;
      const cveIds = extractCveIds(text);
      const key = dedupeKey(src.feedUrl, item);
      const publishedAt = parsePubDate(item.pubDate);
      const rawItem = {
        title: item.title,
        link,
        pubDate: item.pubDate,
        description: item.descriptionText.slice(0, 8000)
      };

      // eslint-disable-next-line no-await-in-loop
      await this.db.query(
        `INSERT INTO vendor_advisory (
           dedupe_key, feed_url, vendor_slug, title, link, summary, published_at, cve_ids, raw_item
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)
         ON CONFLICT (dedupe_key) DO UPDATE SET
           title = EXCLUDED.title,
           link = EXCLUDED.link,
           summary = EXCLUDED.summary,
           published_at = COALESCE(EXCLUDED.published_at, vendor_advisory.published_at),
           cve_ids = EXCLUDED.cve_ids,
           raw_item = EXCLUDED.raw_item,
           fetched_at = now()`,
        [
          key,
          src.feedUrl,
          src.vendorSlug,
          item.title.slice(0, 2000),
          link.slice(0, 4000),
          item.descriptionText ? item.descriptionText.slice(0, 12000) : null,
          publishedAt,
          cveIds,
          JSON.stringify(rawItem)
        ]
      );
      n++;
    }
    return n;
  }
}

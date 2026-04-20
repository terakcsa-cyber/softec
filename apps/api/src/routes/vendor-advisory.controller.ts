import { Controller, Get, NotFoundException, Param, ParseUUIDPipe, Query } from "@nestjs/common";
import { DbService } from "../services/db.service.js";

type Row = {
  id: string;
  feed_url: string;
  vendor_slug: string;
  title: string;
  link: string;
  summary: string | null;
  published_at: Date | null;
  cve_ids: string[];
  fetched_at: Date;
  created_at: Date;
};

type RowDetail = Row & { raw_item: unknown | null };

@Controller("vendor-advisories")
export class VendorAdvisoryController {
  constructor(private readonly db: DbService) {}

  @Get("vendors")
  async vendors() {
    const r = await this.db.query<{ vendor_slug: string }>(
      `SELECT DISTINCT vendor_slug FROM vendor_advisory ORDER BY vendor_slug ASC`
    );
    return { items: r.rows.map((x) => x.vendor_slug) };
  }

  /** Полная карточка записи (включая сырой фрагмент из RSS для просмотра в UI). */
  @Get(":id")
  async detail(@Param("id", ParseUUIDPipe) id: string) {
    const r = await this.db.query<RowDetail>(
      `SELECT id, feed_url, vendor_slug, title, link, summary, published_at, cve_ids, fetched_at, created_at, raw_item
         FROM vendor_advisory WHERE id = $1::uuid`,
      [id]
    );
    const row = r.rows[0];
    if (!row) throw new NotFoundException();

    return {
      id: row.id,
      feedUrl: row.feed_url,
      vendorSlug: row.vendor_slug,
      title: row.title,
      link: row.link,
      summary: row.summary,
      publishedAt: row.published_at ? new Date(row.published_at).toISOString() : null,
      cveIds: row.cve_ids ?? [],
      fetchedAt: new Date(row.fetched_at).toISOString(),
      createdAt: new Date(row.created_at).toISOString(),
      rawItem: row.raw_item
    };
  }

  @Get()
  async list(
    @Query("limit") limitRaw?: string,
    @Query("page") pageRaw?: string,
    @Query("offset") offsetRaw?: string,
    @Query("vendor") vendorRaw?: string,
    @Query("q") qRaw?: string
  ) {
    /** Размер страницы (записей за один запрос). */
    const pageSize = Math.max(1, Math.min(100, Number(limitRaw ?? 20)));
    const vendor = vendorRaw?.trim().toLowerCase() || null;
    const q = qRaw?.trim() || null;

    /** Только «свежие» записи: окно 7 суток по дате публикации или, если её нет, по времени загрузки. */
    const params: unknown[] = [];
    const where: string[] = [`COALESCE(published_at, fetched_at) >= now() - interval '7 days'`];

    if (vendor) {
      params.push(vendor);
      where.push(`vendor_slug = $${params.length}`);
    }
    if (q) {
      params.push(`%${q.toLowerCase()}%`);
      const idx = params.length;
      where.push(
        `(lower(title) LIKE $${idx} OR lower(COALESCE(summary,'')) LIKE $${idx} OR EXISTS (SELECT 1 FROM unnest(cve_ids) c WHERE lower(c::text) LIKE $${idx}))`
      );
    }
    const whereSql = `WHERE ${where.join(" AND ")}`;

    const countR = await this.db.query<{ n: string }>(
      `SELECT COUNT(*)::text AS n FROM vendor_advisory ${whereSql}`,
      params
    );
    const total = Number(countR.rows[0]?.n ?? 0);

    let offset = 0;
    if (offsetRaw !== undefined && offsetRaw !== "") {
      offset = Math.max(0, Number(offsetRaw));
    } else {
      const page = Math.max(1, Number(pageRaw ?? 1));
      offset = (page - 1) * pageSize;
    }
    /** Не уходить за пределы выборки. */
    if (offset >= total && total > 0) {
      offset = Math.floor((total - 1) / pageSize) * pageSize;
    }

    const pageFromOffset = total > 0 ? Math.floor(offset / pageSize) + 1 : 1;
    const totalPages = total > 0 ? Math.ceil(total / pageSize) : 0;

    params.push(pageSize, offset);
    const limIdx = params.length - 1;
    const offIdx = params.length;

    const r = await this.db.query<Row>(
      `SELECT id, feed_url, vendor_slug, title, link, summary, published_at, cve_ids, fetched_at, created_at
         FROM vendor_advisory
         ${whereSql}
     ORDER BY published_at DESC NULLS LAST, fetched_at DESC
        LIMIT $${limIdx} OFFSET $${offIdx}`,
      params
    );

    return {
      items: r.rows.map((row) => ({
        id: row.id,
        feedUrl: row.feed_url,
        vendorSlug: row.vendor_slug,
        title: row.title,
        link: row.link,
        summary: row.summary,
        publishedAt: row.published_at ? new Date(row.published_at).toISOString() : null,
        cveIds: row.cve_ids ?? [],
        fetchedAt: new Date(row.fetched_at).toISOString(),
        createdAt: new Date(row.created_at).toISOString()
      })),
      total,
      page: pageFromOffset,
      pageSize,
      totalPages,
      /** Окно выборки в API (для UI). */
      recentDays: 7
    };
  }
}

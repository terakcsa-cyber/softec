import { Controller, Get, Query } from "@nestjs/common";
import { DbService } from "../services/db.service.js";

const PRODUCT_OK = `vp.product_key_norm <> '' AND btrim(vp.product) <> '' AND vp.product NOT IN ('-', '*') AND vp.vendor NOT IN ('-', '*')`;

type Band = "all" | "risk90" | "risk70" | "kev" | "exploit";

type KeyRow = {
  vendor_key: string;
  product_key_norm: string;
  vendor: string;
  product: string;
  max_risk?: number | null;
  cve_count?: number | null;
};

type EnrichRow = {
  vendor_key: string;
  product_key_norm: string;
  cve_count: number;
  max_risk: number | null;
  max_epss: number | null;
  kev_count: number;
  exploit_count: number;
  poc_count: number;
};

type VendorFacet = { vendor_key: string; vendor: string; count: number };

type CatalogFacts = {
  products: number;
  withKev: number;
  withExploit: number;
  risk90: number;
  risk70: number;
  highestRisk: number | null;
  vendors: Array<{ vendorKey: string; vendor: string; count: number }>;
};

type Slice = {
  total: number | null;
  withKev: number | null;
  highestRisk: number | null;
  vendors: Array<{ vendorKey: string; vendor: string; count: number }>;
  items: KeyRow[];
};

let factsCache: { at: number; value: CatalogFacts } | null = null;
const FACTS_TTL_MS = 60_000;

function likePattern(raw: string | undefined) {
  const q = raw?.trim().toLowerCase() ?? "";
  if (q.length < 2) return null;
  return `%${q.replace(/[\\%_]/g, (ch) => `\\${ch}`)}%`;
}

function cleanToken(raw: string | undefined) {
  const value = raw?.trim().toLowerCase() ?? "";
  if (!value || value === "all") return null;
  return value.slice(0, 160);
}

function bandOf(raw: string | undefined): Band {
  if (raw === "risk90" || raw === "risk70" || raw === "kev" || raw === "exploit" || raw === "all") return raw;
  return "risk70";
}

function clampInt(raw: string | undefined, fallback: number, min: number, max: number) {
  const n = Number(raw);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

function num(value: unknown): number | null {
  if (value == null || value === "") return null;
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) ? n : null;
}

function int(value: unknown) {
  return num(value) ?? 0;
}

function filterSql(q: string | null, vendor: string | null, startAt: number) {
  const values: unknown[] = [];
  let sql = "";
  let i = startAt;
  if (q) {
    values.push(q);
    i += 1;
    sql += ` AND (
      lower(vp.vendor) LIKE $${i} ESCAPE '\\'
      OR lower(vp.product) LIKE $${i} ESCAPE '\\'
      OR lower(vp.vendor_key) LIKE $${i} ESCAPE '\\'
      OR lower(vp.product_key_norm) LIKE $${i} ESCAPE '\\'
      OR lower(replace(vp.product, '_', ' ')) LIKE $${i} ESCAPE '\\'
    )`;
  }
  if (vendor) {
    values.push(vendor);
    i += 1;
    sql += ` AND (vp.vendor_key = $${i} OR lower(vp.vendor) = $${i})`;
  }
  return { sql, values };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function text(value: unknown) {
  return typeof value === "string" ? value.trim() : "";
}

function versionLabel(match: Record<string, unknown>) {
  const start = text(match.versionStartIncluding);
  const endEx = text(match.versionEndExcluding);
  const endIn = text(match.versionEndIncluding);
  if (start || endEx || endIn) {
    return [start ? `от ${start}` : "", endEx ? `до ${endEx}` : "", endIn ? `по ${endIn}` : ""].filter(Boolean).join(" ");
  }
  const criteria = text(match.criteria || match.cpe23Uri);
  const version = criteria.split(":")[5] ?? "";
  if (!version || version === "*" || version === "-") return "";
  return version.replace(/_/g, " ");
}

function walkVersions(node: unknown, affected: string[], fixed: string[]) {
  if (affected.length >= 8 && fixed.length >= 8) return;
  if (Array.isArray(node)) {
    for (const item of node) walkVersions(item, affected, fixed);
    return;
  }
  const rec = asRecord(node);
  if (!rec) return;
  const matches = rec.cpeMatch ?? rec.cpe_match;
  if (Array.isArray(matches)) {
    for (const item of matches) {
      const match = asRecord(item);
      if (!match) continue;
      const label = versionLabel(match);
      if (!label) continue;
      const bucket = match.vulnerable === false ? fixed : affected;
      if (!bucket.includes(label) && bucket.length < 8) bucket.push(label);
    }
  }
  if (Array.isArray(rec.nodes)) walkVersions(rec.nodes, affected, fixed);
}

function referenceHasPatch(references: unknown) {
  if (!Array.isArray(references)) return false;
  return references.some((item) => {
    const rec = asRecord(item);
    const tags = Array.isArray(rec?.tags) ? rec.tags.map((tag) => text(tag).toLowerCase()) : [];
    return tags.some((tag) => tag.includes("patch"));
  });
}

function mapVendors(rows: VendorFacet[]) {
  return rows.map((row) => ({
    vendorKey: row.vendor_key,
    vendor: row.vendor,
    count: int(row.count)
  }));
}

@Controller("products")
export class ProductsController {
  constructor(private readonly db: DbService) {}

  /**
   * Facets for VulnControl filters: full catalog (not top-N window).
   * `kind=vendors` — distinct vendors; `kind=products` — products (optionally scoped by vendor).
   * Empty `q` returns an alphabetical page; with `q` searches the whole catalog.
   */
  @Get("facets")
  async facets(
    @Query("kind") kindRaw?: string,
    @Query("q") qRaw?: string,
    @Query("vendor") vendorRaw?: string,
    @Query("limit") limitRaw?: string
  ) {
    const kind = kindRaw === "products" ? "products" : "vendors";
    const limit = clampInt(limitRaw, 200, 20, 500);
    const vendor = cleanToken(vendorRaw);
    const needle = qRaw?.trim().toLowerCase() ?? "";
    const q = needle.length >= 1 ? `%${needle.replace(/[\\%_]/g, (ch) => `\\${ch}`)}%` : null;

    if (kind === "vendors") {
      const values: unknown[] = [];
      let where = PRODUCT_OK;
      if (q) {
        values.push(q);
        where += ` AND (
          lower(vp.vendor) LIKE $1 ESCAPE '\\'
          OR lower(vp.vendor_key) LIKE $1 ESCAPE '\\'
        )`;
      }
      values.push(limit);
      const limIdx = values.length;
      const r = await this.db.query<{ vendor: string; count: number }>(
        `SELECT max(vp.vendor) AS vendor,
                count(DISTINCT vp.product_key_norm)::int AS count
           FROM cve_vendor_product vp
          WHERE ${where}
          GROUP BY vp.vendor_key
          ORDER BY count DESC, lower(max(vp.vendor)) ASC
          LIMIT $${limIdx}`,
        values
      );
      return {
        kind: "vendors" as const,
        totalHint: q ? r.rows.length : null,
        items: r.rows.map((row) => ({
          id: row.vendor,
          label: row.vendor,
          count: int(row.count)
        }))
      };
    }

    const values: unknown[] = [];
    let where = PRODUCT_OK;
    if (vendor) {
      values.push(vendor);
      where += ` AND (vp.vendor_key = $${values.length} OR lower(vp.vendor) = $${values.length})`;
    }
    if (q) {
      values.push(q);
      const i = values.length;
      where += ` AND (
        lower(vp.product) LIKE $${i} ESCAPE '\\'
        OR lower(vp.product_key_norm) LIKE $${i} ESCAPE '\\'
        OR lower(replace(vp.product, '_', ' ')) LIKE $${i} ESCAPE '\\'
        ${vendor ? "" : `OR lower(vp.vendor) LIKE $${i} ESCAPE '\\'`}
      )`;
    }
    values.push(limit);
    const limIdx = values.length;
    const r = await this.db.query<{ product: string; vendor: string; count: number }>(
      `SELECT max(vp.product) AS product,
              max(vp.vendor) AS vendor,
              count(DISTINCT vp.cve_id)::int AS count
         FROM cve_vendor_product vp
        WHERE ${where}
        GROUP BY vp.vendor_key, vp.product_key_norm
        ORDER BY count DESC, lower(max(vp.product)) ASC
        LIMIT $${limIdx}`,
      values
    );
    return {
      kind: "products" as const,
      vendor: vendorRaw?.trim() || null,
      totalHint: q ? r.rows.length : null,
      items: r.rows.map((row) => ({
        id: row.product,
        label: vendor ? row.product : `${row.product} · ${row.vendor}`,
        product: row.product,
        vendor: row.vendor,
        count: int(row.count)
      }))
    };
  }

  @Get()
  async list(
    @Query("q") qRaw?: string,
    @Query("vendor") vendorRaw?: string,
    @Query("band") bandRaw?: string,
    @Query("limit") limitRaw?: string,
    @Query("offset") offsetRaw?: string
  ) {
    const band = bandOf(bandRaw);
    const q = likePattern(qRaw);
    const vendor = cleanToken(vendorRaw);
    const limit = clampInt(limitRaw, 25, 1, 40);
    const offset = clampInt(offsetRaw, 0, 0, 2_500);
    const catalogPromise = this.catalogFacts();

    if (band === "all" && !q && !vendor) {
      const [catalog, keys] = await Promise.all([catalogPromise, this.alphaPage(limit, offset)]);
      return {
        catalog,
        total: catalog.products,
        withKev: catalog.withKev,
        highestRisk: catalog.highestRisk,
        vendors: catalog.vendors,
        items: await this.enrich(keys)
      };
    }

    const [catalog, slice] = await Promise.all([catalogPromise, this.slice(band, q, vendor, limit, offset)]);
    return {
      catalog,
      total: slice.total,
      withKev: slice.withKev,
      highestRisk: slice.highestRisk,
      vendors: slice.vendors,
      items: await this.enrich(slice.items)
    };
  }

  @Get("detail")
  async detail(@Query("vendorKey") vendorKeyRaw?: string, @Query("productKey") productKeyRaw?: string) {
    const vendorKey = cleanToken(vendorKeyRaw);
    const productKey = cleanToken(productKeyRaw);
    if (!vendorKey || !productKey) return { found: false };

    const [agg, cves] = await Promise.all([
      this.db.query<{
        vendor: string | null;
        product: string | null;
        cve_count: number;
        max_risk: number | null;
        max_epss: number | null;
        kev_count: number;
        exploit_count: number;
        poc_count: number;
      }>(
        `SELECT max(vp.vendor) AS vendor,
                max(vp.product) AS product,
                count(*)::int AS cve_count,
                max(rs.score)::int AS max_risk,
                max(es.score) AS max_epss,
                count(*) FILTER (WHERE k.cve_id IS NOT NULL)::int AS kev_count,
                count(*) FILTER (WHERE COALESCE(ei.has_public_exploit, false))::int AS exploit_count,
                count(*) FILTER (WHERE COALESCE(ei.has_poc, false))::int AS poc_count
           FROM cve_vendor_product vp
           LEFT JOIN risk_score rs ON rs.cve_id = vp.cve_id
           LEFT JOIN epss_score es ON es.cve_id = vp.cve_id
           LEFT JOIN kev k ON k.cve_id = vp.cve_id
           LEFT JOIN cve_exploit_intel ei ON ei.cve_id = vp.cve_id
          WHERE vp.vendor_key = $1 AND vp.product_key_norm = $2`,
        [vendorKey, productKey]
      ),
      this.db.query<{
        cve_id: string;
        risk_score: number | null;
        epss: number | null;
        cvss_base: number | null;
        kev: boolean;
        has_poc: boolean;
        has_public_exploit: boolean;
        published_at: string | null;
        configurations: unknown;
        cve_configurations: unknown;
        references: unknown;
        cve_references: unknown;
      }>(
        `SELECT c.cve_id,
                rs.score::int AS risk_score,
                es.score AS epss,
                c.cvss_base,
                (k.cve_id IS NOT NULL) AS kev,
                COALESCE(ei.has_poc, false) AS has_poc,
                COALESCE(ei.has_public_exploit, false) AS has_public_exploit,
                c.published_at,
                c.raw->'configurations' AS configurations,
                c.raw->'cve'->'configurations' AS cve_configurations,
                c.raw->'references' AS references,
                c.raw->'cve'->'references' AS cve_references
           FROM cve_vendor_product vp
           JOIN cve c ON c.cve_id = vp.cve_id
           LEFT JOIN risk_score rs ON rs.cve_id = c.cve_id
           LEFT JOIN epss_score es ON es.cve_id = c.cve_id
           LEFT JOIN kev k ON k.cve_id = c.cve_id
           LEFT JOIN cve_exploit_intel ei ON ei.cve_id = c.cve_id
          WHERE vp.vendor_key = $1 AND vp.product_key_norm = $2
          ORDER BY rs.score DESC NULLS LAST, c.published_at DESC NULLS LAST
          LIMIT 30`,
        [vendorKey, productKey]
      )
    ]);

    const head = agg.rows[0];
    if (!head || int(head.cve_count) === 0) return { found: false };

    const versions: string[] = [];
    const fixedVersions: string[] = [];
    const items = cves.rows.map((row) => {
      const affected: string[] = [];
      const fixed: string[] = [];
      walkVersions(row.configurations ?? row.cve_configurations, affected, fixed);
      for (const label of affected) if (!versions.includes(label) && versions.length < 24) versions.push(label);
      for (const label of fixed) if (!fixedVersions.includes(label) && fixedVersions.length < 24) fixedVersions.push(label);
      const hasPatch = referenceHasPatch(row.references) || referenceHasPatch(row.cve_references) || fixed.length > 0;
      return {
        cve_id: row.cve_id,
        risk_score: num(row.risk_score),
        epss: num(row.epss),
        cvss_base: num(row.cvss_base),
        kev: Boolean(row.kev),
        has_poc: Boolean(row.has_poc),
        has_public_exploit: Boolean(row.has_public_exploit),
        published_at: row.published_at,
        version: affected[0] ?? null,
        has_patch: hasPatch
      };
    });

    return {
      found: true,
      vendorKey,
      productKey,
      vendor: head.vendor,
      product: head.product,
      cveCount: int(head.cve_count),
      maxRisk: num(head.max_risk),
      maxEpss: num(head.max_epss),
      kevCount: int(head.kev_count),
      exploitCount: int(head.exploit_count),
      pocCount: int(head.poc_count),
      shown: items.length,
      versions,
      fixedVersions,
      cves: items
    };
  }

  private async catalogFacts(): Promise<CatalogFacts> {
    if (factsCache && Date.now() - factsCache.at < FACTS_TTL_MS) return factsCache.value;
    const name = PRODUCT_OK;
    const [products, kev, exploit, risk90, risk70, highest, vendors] = await Promise.all([
      this.db.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM (
           SELECT 1 FROM cve_vendor_product vp WHERE ${name} GROUP BY vp.vendor_key, vp.product_key_norm
         ) s`
      ),
      this.db.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM (
           SELECT DISTINCT vp.vendor_key, vp.product_key_norm
             FROM kev k
             JOIN cve_vendor_product vp ON vp.cve_id = k.cve_id
            WHERE ${name}
         ) s`
      ),
      this.db.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM (
           SELECT DISTINCT vp.vendor_key, vp.product_key_norm
             FROM cve_exploit_intel ei
             JOIN cve_vendor_product vp ON vp.cve_id = ei.cve_id
            WHERE (ei.has_public_exploit OR ei.has_poc) AND ${name}
         ) s`
      ),
      this.db.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM (
           SELECT 1
             FROM risk_score rs
             JOIN cve_vendor_product vp ON vp.cve_id = rs.cve_id
            WHERE rs.score >= 90 AND ${name}
            GROUP BY vp.vendor_key, vp.product_key_norm
         ) s`
      ),
      this.db.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM (
           SELECT 1
             FROM risk_score rs
             JOIN cve_vendor_product vp ON vp.cve_id = rs.cve_id
            WHERE rs.score >= 70 AND ${name}
            GROUP BY vp.vendor_key, vp.product_key_norm
         ) s`
      ),
      this.db.query<{ n: number | null }>(
        `SELECT max(rs.score)::int AS n
           FROM risk_score rs
          WHERE EXISTS (
            SELECT 1 FROM cve_vendor_product vp WHERE vp.cve_id = rs.cve_id AND ${name}
          )`
      ),
      this.db.query<VendorFacet>(
        `SELECT vp.vendor_key, max(vp.vendor) AS vendor, count(DISTINCT vp.product_key_norm)::int AS count
           FROM cve_vendor_product vp
          WHERE ${name}
          GROUP BY vp.vendor_key
          ORDER BY count DESC
          LIMIT 24`
      )
    ]);
    const value: CatalogFacts = {
      products: int(products.rows[0]?.n),
      withKev: int(kev.rows[0]?.n),
      withExploit: int(exploit.rows[0]?.n),
      risk90: int(risk90.rows[0]?.n),
      risk70: int(risk70.rows[0]?.n),
      highestRisk: num(highest.rows[0]?.n),
      vendors: mapVendors(vendors.rows)
    };
    factsCache = { at: Date.now(), value };
    return value;
  }

  private async alphaPage(limit: number, offset: number) {
    const r = await this.db.query<KeyRow>(
      `SELECT DISTINCT ON (vp.vendor_key, vp.product_key_norm)
              vp.vendor_key, vp.product_key_norm, vp.vendor, vp.product
         FROM cve_vendor_product vp
        WHERE ${PRODUCT_OK}
        ORDER BY vp.vendor_key, vp.product_key_norm
        LIMIT $1 OFFSET $2`,
      [limit, offset]
    );
    return r.rows;
  }

  private async slice(band: Band, q: string | null, vendor: string | null, limit: number, offset: number): Promise<Slice> {
    if (band === "risk90" || band === "risk70") return this.riskSlice(band === "risk90" ? 90 : 70, q, vendor, limit, offset);
    if (band === "kev") return this.signalSlice("kev", q, vendor, limit, offset);
    if (band === "exploit") return this.signalSlice("exploit", q, vendor, limit, offset);
    return this.catalogSlice(q, vendor, limit, offset);
  }

  private async riskSlice(min: number, q: string | null, vendor: string | null, limit: number, offset: number): Promise<Slice> {
    const filter = filterSql(q, vendor, 1);
    const where = `rs.score >= $1 AND ${PRODUCT_OK}${filter.sql}`;
    const base = [min, ...filter.values];
    const [count, page, vendors] = await Promise.all([
      this.db.query<{ total: number; with_kev: number; highest: number | null }>(
        `SELECT count(*)::int AS total,
                count(*) FILTER (WHERE has_kev)::int AS with_kev,
                max(max_risk)::int AS highest
           FROM (
             SELECT max(rs.score)::int AS max_risk,
                    bool_or(k.cve_id IS NOT NULL) AS has_kev
               FROM risk_score rs
               JOIN cve_vendor_product vp ON vp.cve_id = rs.cve_id
               LEFT JOIN kev k ON k.cve_id = vp.cve_id
              WHERE ${where}
              GROUP BY vp.vendor_key, vp.product_key_norm
           ) s`,
        base
      ),
      this.db.query<KeyRow>(
        `SELECT vp.vendor_key, vp.product_key_norm,
                max(vp.vendor) AS vendor,
                max(vp.product) AS product,
                max(rs.score)::int AS max_risk
           FROM risk_score rs
           JOIN cve_vendor_product vp ON vp.cve_id = rs.cve_id
          WHERE ${where}
          GROUP BY vp.vendor_key, vp.product_key_norm
          ORDER BY max(rs.score) DESC, vp.vendor_key, vp.product_key_norm
          LIMIT $${base.length + 1} OFFSET $${base.length + 2}`,
        [...base, limit, offset]
      ),
      this.db.query<VendorFacet>(
        `SELECT vp.vendor_key, max(vp.vendor) AS vendor, count(DISTINCT vp.product_key_norm)::int AS count
           FROM risk_score rs
           JOIN cve_vendor_product vp ON vp.cve_id = rs.cve_id
          WHERE ${where}
          GROUP BY vp.vendor_key
          ORDER BY count DESC
          LIMIT 24`,
        base
      )
    ]);
    const head = count.rows[0];
    return {
      total: int(head?.total),
      withKev: int(head?.with_kev),
      highestRisk: num(head?.highest),
      vendors: mapVendors(vendors.rows),
      items: page.rows
    };
  }

  private async signalSlice(kind: "kev" | "exploit", q: string | null, vendor: string | null, limit: number, offset: number): Promise<Slice> {
    const filter = filterSql(q, vendor, 0);
    const signal =
      kind === "kev"
        ? `JOIN kev sig ON sig.cve_id = vp.cve_id`
        : `JOIN cve_exploit_intel sig ON sig.cve_id = vp.cve_id AND (sig.has_public_exploit OR sig.has_poc)`;
    const where = `${PRODUCT_OK}${filter.sql}`;
    const [count, page, vendors] = await Promise.all([
      this.db.query<{ total: number; with_kev: number; highest: number | null }>(
        `SELECT count(*)::int AS total,
                count(*) FILTER (WHERE has_kev)::int AS with_kev,
                max(max_risk)::int AS highest
           FROM (
             SELECT max(rs.score)::int AS max_risk,
                    bool_or(k.cve_id IS NOT NULL) AS has_kev
               FROM cve_vendor_product vp
               ${signal}
               LEFT JOIN risk_score rs ON rs.cve_id = vp.cve_id
               LEFT JOIN kev k ON k.cve_id = vp.cve_id
              WHERE ${where}
              GROUP BY vp.vendor_key, vp.product_key_norm
           ) s`,
        filter.values
      ),
      this.db.query<KeyRow>(
        `SELECT vp.vendor_key, vp.product_key_norm,
                max(vp.vendor) AS vendor,
                max(vp.product) AS product,
                max(rs.score)::int AS max_risk,
                count(DISTINCT vp.cve_id)::int AS cve_count
           FROM cve_vendor_product vp
           ${signal}
           LEFT JOIN risk_score rs ON rs.cve_id = vp.cve_id
          WHERE ${where}
          GROUP BY vp.vendor_key, vp.product_key_norm
          ORDER BY count(DISTINCT vp.cve_id) DESC, max(rs.score) DESC NULLS LAST, vp.vendor_key
          LIMIT $${filter.values.length + 1} OFFSET $${filter.values.length + 2}`,
        [...filter.values, limit, offset]
      ),
      this.db.query<VendorFacet>(
        `SELECT vp.vendor_key, max(vp.vendor) AS vendor, count(DISTINCT vp.product_key_norm)::int AS count
           FROM cve_vendor_product vp
           ${signal}
          WHERE ${where}
          GROUP BY vp.vendor_key
          ORDER BY count DESC
          LIMIT 24`,
        filter.values
      )
    ]);
    const head = count.rows[0];
    return {
      total: int(head?.total),
      withKev: int(head?.with_kev),
      highestRisk: num(head?.highest),
      vendors: mapVendors(vendors.rows),
      items: page.rows
    };
  }

  private async catalogSlice(q: string | null, vendor: string | null, limit: number, offset: number): Promise<Slice> {
    const filter = filterSql(q, vendor, 0);
    const where = `${PRODUCT_OK}${filter.sql}`;
    const [count, page, vendors] = await Promise.all([
      this.db.query<{ total: number; with_kev: number; highest: number | null }>(
        `SELECT count(*)::int AS total,
                count(*) FILTER (WHERE has_kev)::int AS with_kev,
                max(max_risk)::int AS highest
           FROM (
             SELECT max(rs.score)::int AS max_risk,
                    bool_or(k.cve_id IS NOT NULL) AS has_kev
               FROM cve_vendor_product vp
               LEFT JOIN risk_score rs ON rs.cve_id = vp.cve_id
               LEFT JOIN kev k ON k.cve_id = vp.cve_id
              WHERE ${where}
              GROUP BY vp.vendor_key, vp.product_key_norm
           ) s`,
        filter.values
      ),
      this.db.query<KeyRow>(
        `SELECT vp.vendor_key, vp.product_key_norm,
                max(vp.vendor) AS vendor,
                max(vp.product) AS product,
                count(*)::int AS cve_count
           FROM cve_vendor_product vp
          WHERE ${where}
          GROUP BY vp.vendor_key, vp.product_key_norm
          ORDER BY count(*) DESC, vp.vendor_key, vp.product_key_norm
          LIMIT $${filter.values.length + 1} OFFSET $${filter.values.length + 2}`,
        [...filter.values, limit, offset]
      ),
      this.db.query<VendorFacet>(
        `SELECT vp.vendor_key, max(vp.vendor) AS vendor, count(DISTINCT vp.product_key_norm)::int AS count
           FROM cve_vendor_product vp
          WHERE ${where}
         GROUP BY vp.vendor_key
         ORDER BY count DESC
         LIMIT 24`,
        filter.values
      )
    ]);
    const head = count.rows[0];
    return {
      total: head ? int(head.total) : null,
      withKev: head ? int(head.with_kev) : null,
      highestRisk: head ? num(head.highest) : null,
      vendors: mapVendors(vendors.rows),
      items: page.rows
    };
  }

  private async enrich(keys: KeyRow[]) {
    if (!keys.length) return [];
    const stats = await this.db.query<EnrichRow>(
      `SELECT vp.vendor_key,
              vp.product_key_norm,
              count(*)::int AS cve_count,
              max(rs.score)::int AS max_risk,
              max(es.score) AS max_epss,
              count(*) FILTER (WHERE k.cve_id IS NOT NULL)::int AS kev_count,
              count(*) FILTER (WHERE COALESCE(ei.has_public_exploit, false))::int AS exploit_count,
              count(*) FILTER (WHERE COALESCE(ei.has_poc, false))::int AS poc_count
         FROM unnest($1::text[], $2::text[]) AS keys(vendor_key, product_key_norm)
         JOIN cve_vendor_product vp
           ON vp.vendor_key = keys.vendor_key
          AND vp.product_key_norm = keys.product_key_norm
         LEFT JOIN risk_score rs ON rs.cve_id = vp.cve_id
         LEFT JOIN epss_score es ON es.cve_id = vp.cve_id
         LEFT JOIN kev k ON k.cve_id = vp.cve_id
         LEFT JOIN cve_exploit_intel ei ON ei.cve_id = vp.cve_id
        GROUP BY vp.vendor_key, vp.product_key_norm`,
      [keys.map((row) => row.vendor_key), keys.map((row) => row.product_key_norm)]
    );
    const byKey = new Map(stats.rows.map((row) => [`${row.vendor_key}\0${row.product_key_norm}`, row]));
    return keys.map((row) => {
      const stat = byKey.get(`${row.vendor_key}\0${row.product_key_norm}`);
      return {
        vendorKey: row.vendor_key,
        productKey: row.product_key_norm,
        vendor: row.vendor,
        product: row.product,
        cveCount: stat ? int(stat.cve_count) : int(row.cve_count),
        maxRisk: stat ? num(stat.max_risk) : num(row.max_risk),
        maxEpss: stat ? num(stat.max_epss) : null,
        kevCount: stat ? int(stat.kev_count) : 0,
        exploitCount: stat ? int(stat.exploit_count) : 0,
        pocCount: stat ? int(stat.poc_count) : 0
      };
    });
  }
}

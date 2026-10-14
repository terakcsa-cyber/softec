import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import path from "node:path";
import { BadRequestException, Injectable } from "@nestjs/common";
import PDFDocument from "pdfkit";
import {
  DIGEST_NARRATIVE_FAILED,
  DIGEST_NARRATIVE_REJECTED,
  DIGEST_NARRATIVE_SKIPPED,
  digestFactsText,
  filterDigestNarrative,
  isDigestNarrativeConfigured,
  runDigestNarrative,
  type DigestCveNote,
  type DigestNarrativeFacts,
  type DigestNarrativeOutcome,
  type DigestNarrativeSection
} from "@vuln-intel/shared";
import { DbService } from "./db.service.js";
import { IntegrationSettingsService } from "./integration-settings.service.js";

type PdfDoc = PDFKit.PDFDocument;

const require = createRequire(import.meta.url);
const FONT_DIR = path.join(path.dirname(require.resolve("dejavu-fonts-ttf/package.json")), "ttf");

const MONTHS_NOM = [
  "январь", "февраль", "март", "апрель", "май", "июнь",
  "июль", "август", "сентябрь", "октябрь", "ноябрь", "декабрь"
];
const MONTHS_GEN = [
  "января", "февраля", "марта", "апреля", "мая", "июня",
  "июля", "августа", "сентября", "октября", "ноября", "декабря"
];
const MONTHS_TITLE = [
  "Январь", "Февраль", "Март", "Апрель", "Май", "Июнь",
  "Июль", "Август", "Сентябрь", "Октябрь", "Ноябрь", "Декабрь"
];

const NOTABLE_CAP = 10;
const KEV_CAP = 12;

type MonthWindow = {
  year: number;
  month: number;
  lastDay: number;
  startIso: string;
  endIso: string;
  startDay: string;
  endDay: string;
  label: string;
  monthTitle: string;
  windowLabel: string;
  periodLabel: string;
};

type DayRow = { day: string; label: string; published: number; critical: number };
type VendorRow = { vendor: string; count: number };
type ProductRow = { product: string; vendor: string; count: number };
type KevRow = {
  cveId: string;
  dateAdded: string;
  vendor: string;
  product: string;
  name: string;
  cvss: string;
  epss: string;
  publishedDay: string;
};
type NotableCve = DigestCveNote & { publishedDay: string; signal: string };

type MonthCatalog = {
  window: MonthWindow;
  issuedAt: string;
  issuedLabel: string;
  accountEmail: string;
  published: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unscored: number;
  kevAdded: number;
  vckevAdded: number;
  highEpss: number;
  epssSpikes: number;
  publicExploit: number;
  poc: number;
  vckevOnly: number;
  epssHistoryPoints: number;
  epssHistoryCves: number;
  days: DayRow[];
  peak: { label: string; published: number } | null;
  vendors: VendorRow[];
  products: ProductRow[];
  kevRows: KevRow[];
  cves: NotableCve[];
  facts: DigestNarrativeFacts;
};

type PreviewNarrative = {
  status: DigestNarrativeOutcome["status"];
  lead: string;
  summary: string;
  cases: string;
  close: string;
  text: string;
};

@Injectable()
export class MonthlyDigestService {
  private readonly narrativeCache = new Map<string, { at: number; story: DigestNarrativeOutcome }>();
  private readonly narrativeInflight = new Map<string, Promise<DigestNarrativeOutcome>>();

  constructor(
    private readonly db: DbService,
    private readonly integration: IntegrationSettingsService
  ) {}

  async preview(year: number, month: number, accountEmail: string) {
    const catalog = await this.load(year, month, accountEmail);
    const llm = await this.integration.getDigestLlmConfig();
    const story = await this.narrate(catalog, llm);
    return present(catalog, story);
  }

  async pdf(body: unknown, accountEmail: string): Promise<{ buffer: Buffer; filename: string }> {
    const raw = asRecord(body);
    const year = asInt(raw.year);
    const month = asInt(raw.month);
    if (year == null || month == null) throw new BadRequestException("Нужен календарный месяц");
    const catalog = await this.load(year, month, accountEmail, issuedFrom(raw.issuedAt));
    const llm = await this.integration.getDigestLlmConfig();
    const story = isDigestNarrativeConfigured(llm)
      ? acceptClientStory(raw.narrative, digestFactsText(catalog.facts)) ?? await this.narrate(catalog, llm)
      : skippedStory();
    const buffer = await renderMonthPdf(catalog, story);
    const mm = String(catalog.window.month).padStart(2, "0");
    return { buffer, filename: `vulncontrol-digest-${catalog.window.year}-${mm}.pdf` };
  }

  private async load(year: number, month: number, accountEmail: string, issuedAt = new Date()): Promise<MonthCatalog> {
    const window = monthWindow(year, month);
    const params = [window.startIso, window.endIso, window.startDay, window.endDay];
    const [counts, intel, kevCount, vckevCount, history, vendors, products, days, notableIds, kevRows] =
      await Promise.all([
        this.db.query<{
          published: number;
          critical: number;
          high: number;
          medium: number;
          low: number;
          unscored: number;
        }>(
          `SELECT COUNT(*)::int AS published,
                  COUNT(*) FILTER (WHERE cvss_base >= 9)::int AS critical,
                  COUNT(*) FILTER (WHERE cvss_base >= 7 AND cvss_base < 9)::int AS high,
                  COUNT(*) FILTER (WHERE cvss_base >= 4 AND cvss_base < 7)::int AS medium,
                  COUNT(*) FILTER (WHERE cvss_base IS NOT NULL AND cvss_base < 4)::int AS low,
                  COUNT(*) FILTER (WHERE cvss_base IS NULL)::int AS unscored
             FROM cve
            WHERE published_at >= $1::timestamptz
              AND published_at < $2::timestamptz`,
          [window.startIso, window.endIso]
        ),
        this.db.query<{
          high_epss: number;
          spikes: number;
          exploit: number;
          poc: number;
          vckev_only: number;
        }>(
          `SELECT COUNT(*) FILTER (WHERE es.score >= 0.7)::int AS high_epss,
                  COUNT(*) FILTER (WHERE ei.epss_spike)::int AS spikes,
                  COUNT(*) FILTER (WHERE ei.has_public_exploit)::int AS exploit,
                  COUNT(*) FILTER (WHERE ei.has_poc)::int AS poc,
                  COUNT(*) FILTER (WHERE ei.vckev_only)::int AS vckev_only
             FROM cve c
             LEFT JOIN epss_score es ON es.cve_id = c.cve_id
             LEFT JOIN cve_exploit_intel ei ON ei.cve_id = c.cve_id
            WHERE c.published_at >= $1::timestamptz
              AND c.published_at < $2::timestamptz`,
          [window.startIso, window.endIso]
        ),
        this.db.query<{ n: number }>(
          `SELECT COUNT(*)::int AS n
             FROM kev
            WHERE date_added >= $1::date
              AND date_added < $2::date`,
          [window.startDay, window.endDay]
        ),
        this.db.query<{ n: number }>(
          `SELECT COUNT(*)::int AS n
             FROM vulncheck_kev
            WHERE date_added >= $1::timestamptz
              AND date_added < $2::timestamptz`,
          [window.startIso, window.endIso]
        ),
        this.db.query<{ points: number; cves: number }>(
          `SELECT COUNT(*)::int AS points,
                  COUNT(DISTINCT h.cve_id)::int AS cves
             FROM epss_score_history h
             JOIN cve c ON c.cve_id = h.cve_id
            WHERE c.published_at >= $1::timestamptz
              AND c.published_at < $2::timestamptz
              AND h.scored_at >= $3::date
              AND h.scored_at < $4::date`,
          params
        ),
        this.db.query<{ vendor: string; n: number }>(
          `SELECT vp.vendor, COUNT(DISTINCT c.cve_id)::int AS n
             FROM cve c
             JOIN cve_vendor_product vp ON vp.cve_id = c.cve_id
            WHERE c.published_at >= $1::timestamptz
              AND c.published_at < $2::timestamptz
              AND btrim(vp.vendor) <> ''
            GROUP BY vp.vendor
            ORDER BY n DESC, vp.vendor ASC
            LIMIT 8`,
          [window.startIso, window.endIso]
        ),
        this.db.query<{ product: string; vendor: string; n: number }>(
          `SELECT vp.product, vp.vendor, COUNT(DISTINCT c.cve_id)::int AS n
             FROM cve c
             JOIN cve_vendor_product vp ON vp.cve_id = c.cve_id
            WHERE c.published_at >= $1::timestamptz
              AND c.published_at < $2::timestamptz
              AND btrim(COALESCE(vp.product, '')) <> ''
            GROUP BY vp.product, vp.vendor
            ORDER BY n DESC, vp.product ASC
            LIMIT 8`,
          [window.startIso, window.endIso]
        ),
        this.db.query<{ day: string; published: number; critical: number }>(
          `SELECT to_char(date_trunc('day', published_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD') AS day,
                  COUNT(*)::int AS published,
                  COUNT(*) FILTER (WHERE cvss_base >= 9)::int AS critical
             FROM cve
            WHERE published_at >= $1::timestamptz
              AND published_at < $2::timestamptz
            GROUP BY 1
            ORDER BY 1`,
          [window.startIso, window.endIso]
        ),
        this.db.query<{ cve_id: string }>(
          `SELECT c.cve_id
             FROM cve c
             LEFT JOIN epss_score es ON es.cve_id = c.cve_id
             LEFT JOIN kev k ON k.cve_id = c.cve_id
            WHERE c.published_at >= $1::timestamptz
              AND c.published_at < $2::timestamptz
            ORDER BY (k.cve_id IS NOT NULL) DESC,
                     COALESCE(c.cvss_base, 0) DESC,
                     COALESCE(es.score, 0) DESC,
                     c.published_at DESC,
                     c.cve_id ASC
            LIMIT ${NOTABLE_CAP}`,
          [window.startIso, window.endIso]
        ),
        this.db.query<{
          cve_id: string;
          date_added: string;
          vendor: string | null;
          product: string | null;
          name: string | null;
          cvss_base: number | null;
          epss: number | null;
          published_day: string | null;
        }>(
          `SELECT k.cve_id,
                  to_char(k.date_added, 'YYYY-MM-DD') AS date_added,
                  k.vendor_project AS vendor,
                  k.product,
                  k.vulnerability_name AS name,
                  c.cvss_base,
                  es.score AS epss,
                  to_char(c.published_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS published_day
             FROM kev k
             LEFT JOIN cve c ON c.cve_id = k.cve_id
             LEFT JOIN epss_score es ON es.cve_id = k.cve_id
            WHERE k.date_added >= $1::date
              AND k.date_added < $2::date
            ORDER BY k.date_added DESC, k.cve_id ASC
            LIMIT ${KEV_CAP}`,
          [window.startDay, window.endDay]
        )
      ]);

    const count = counts.rows[0];
    const intelRow = intel.rows[0];
    const historyRow = history.rows[0];
    const dayRows = days.rows.map((row) => ({
      day: row.day,
      label: dayLabel(row.day),
      published: num(row.published),
      critical: num(row.critical)
    }));
    const peak = dayRows.reduce<DayRow | null>((best, row) => {
      if (!best || row.published > best.published) return row;
      return best;
    }, null);
    const kevList: KevRow[] = kevRows.rows.map((row) => ({
      cveId: row.cve_id,
      dateAdded: row.date_added,
      vendor: clipText(row.vendor, 80),
      product: clipText(row.product, 80),
      name: clipText(row.name, 180),
      cvss: row.cvss_base == null ? "" : formatScore(Number(row.cvss_base)),
      epss: row.epss == null ? "" : formatScore(Number(row.epss)),
      publishedDay: row.published_day ?? ""
    }));
    const cves = await this.hydrateNotable(
      notableIds.rows.map((row) => row.cve_id),
      window
    );
    const issuedLabel = formatMsk(issuedAt.toISOString());
    const catalogBase = {
      window,
      issuedAt: issuedAt.toISOString(),
      issuedLabel,
      accountEmail: clipText(accountEmail, 120) || "текущая сессия",
      published: num(count?.published),
      critical: num(count?.critical),
      high: num(count?.high),
      medium: num(count?.medium),
      low: num(count?.low),
      unscored: num(count?.unscored),
      kevAdded: num(kevCount.rows[0]?.n),
      vckevAdded: num(vckevCount.rows[0]?.n),
      highEpss: num(intelRow?.high_epss),
      epssSpikes: num(intelRow?.spikes),
      publicExploit: num(intelRow?.exploit),
      poc: num(intelRow?.poc),
      vckevOnly: num(intelRow?.vckev_only),
      epssHistoryPoints: num(historyRow?.points),
      epssHistoryCves: num(historyRow?.cves),
      days: dayRows.filter((row) => row.published > 0),
      peak: peak && peak.published > 0 ? { label: peak.label, published: peak.published } : null,
      vendors: vendors.rows.map((row) => ({ vendor: clipText(row.vendor, 80), count: num(row.n) })),
      products: products.rows.map((row) => ({
        product: clipText(row.product, 80),
        vendor: clipText(row.vendor, 80),
        count: num(row.n)
      })),
      kevRows: kevList,
      cves
    };
    return { ...catalogBase, facts: buildFacts(catalogBase) };
  }

  private async hydrateNotable(ids: string[], window: MonthWindow): Promise<NotableCve[]> {
    if (!ids.length) return [];
    const rows = await this.db.query<{
      cve_id: string;
      published_day: string | null;
      cvss_base: number | null;
      epss: number | null;
      kev: boolean;
      kev_in_month: boolean;
      vendor: string | null;
      product: string | null;
      description: string | null;
      has_public_exploit: boolean;
      has_poc: boolean;
      epss_spike: boolean;
    }>(
      `SELECT c.cve_id,
              to_char(c.published_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS published_day,
              c.cvss_base,
              es.score AS epss,
              (k.cve_id IS NOT NULL) AS kev,
              (k.date_added >= $2::date AND k.date_added < $3::date) AS kev_in_month,
              vp.vendor,
              vp.product,
              NULLIF(substring(regexp_replace(COALESCE(
                c.raw->'descriptions'->0->>'value',
                c.raw->'cve'->'descriptions'->0->>'value',
                c.raw->'cve'->'description'->'description_data'->0->>'value',
                ''
              ), E'\\s+', ' ', 'g') for 280), '') AS description,
              COALESCE(ei.has_public_exploit, false) AS has_public_exploit,
              COALESCE(ei.has_poc, false) AS has_poc,
              COALESCE(ei.epss_spike, false) AS epss_spike
         FROM cve c
         LEFT JOIN epss_score es ON es.cve_id = c.cve_id
         LEFT JOIN kev k ON k.cve_id = c.cve_id
         LEFT JOIN cve_exploit_intel ei ON ei.cve_id = c.cve_id
         LEFT JOIN LATERAL (
           SELECT vp.vendor, vp.product
             FROM cve_vendor_product vp
            WHERE vp.cve_id = c.cve_id
            ORDER BY vp.vendor_key ASC, vp.product_key_norm ASC
            LIMIT 1
         ) vp ON TRUE
        WHERE c.cve_id = ANY($1::text[])`,
      [ids, window.startDay, window.endDay]
    );
    const byId = new Map(rows.rows.map((row) => [row.cve_id, row]));
    const notes: NotableCve[] = [];
    for (const id of ids) {
      const row = byId.get(id);
      if (!row) continue;
      const signals = [
        row.kev_in_month ? "KEV в этом месяце" : row.kev ? "KEV" : "",
        row.has_public_exploit ? "публичный эксплойт" : "",
        row.has_poc ? "PoC" : "",
        row.epss_spike ? "скачок EPSS" : ""
      ].filter(Boolean);
      notes.push({
        cveId: row.cve_id,
        description: clipText(row.description, 280),
        vendor: clipText(row.vendor, 80),
        product: clipText(row.product, 80),
        cvss: row.cvss_base == null ? "" : formatScore(Number(row.cvss_base)),
        epss: row.epss == null ? "" : formatScore(Number(row.epss)),
        kev: row.kev ? "KEV" : "",
        publishedDay: row.published_day ?? "",
        signal: signals.join(", ")
      });
    }
    return notes;
  }

  private async narrate(catalog: MonthCatalog, llm: Awaited<ReturnType<IntegrationSettingsService["getDigestLlmConfig"]>>) {
    if (!isDigestNarrativeConfigured(llm)) return skippedStory();
    const key = `${catalog.window.year}-${catalog.window.month}:${createHash("sha256").update(digestFactsText(catalog.facts)).digest("hex")}`;
    const hit = this.narrativeCache.get(key);
    if (hit && Date.now() - hit.at < 120_000) return hit.story;
    const pending = this.narrativeInflight.get(key);
    if (pending) return pending;
    const job = runDigestNarrative({ facts: catalog.facts, llm, kind: "month" })
      .then((story) => {
        if (story.status === "generated") this.narrativeCache.set(key, { at: Date.now(), story });
        return story;
      })
      .finally(() => {
        this.narrativeInflight.delete(key);
      });
    this.narrativeInflight.set(key, job);
    return job;
  }
}

function present(catalog: MonthCatalog, story: DigestNarrativeOutcome) {
  const tiles = tilesOf(catalog);
  return {
    kind: "month" as const,
    year: catalog.window.year,
    month: catalog.window.month,
    monthLabel: catalog.window.label,
    monthTitle: catalog.window.monthTitle,
    title: `Дайджест уязвимостей · ${catalog.window.monthTitle}`,
    windowLabel: catalog.window.windowLabel,
    periodLabel: catalog.window.periodLabel,
    issuedAt: catalog.issuedAt,
    issuedLabel: catalog.issuedLabel,
    accountEmail: catalog.accountEmail,
    status: story.status,
    searched: false,
    text: story.text,
    sources: ["Каталог VulnControl"],
    note:
      story.status === "generated"
        ? "Рассказ написал DeepSeek один раз по фактам каталога за этот месяц. Числа и CVE вне этого набора отбрасываются."
        : story.lead,
    coverage: catalog.facts.coverage,
    sourcesNote: sourcesNote(catalog),
    figures: {
      published: catalog.published,
      critical: catalog.critical,
      high: catalog.high,
      medium: catalog.medium,
      low: catalog.low,
      unscored: catalog.unscored,
      kevAdded: catalog.kevAdded,
      vckevAdded: catalog.vckevAdded,
      highEpss: catalog.highEpss,
      epssSpikes: catalog.epssSpikes,
      publicExploit: catalog.publicExploit,
      poc: catalog.poc,
      epssHistoryPoints: catalog.epssHistoryPoints,
      epssHistoryCves: catalog.epssHistoryCves,
      notableCves: catalog.cves.length
    },
    tiles,
    metrics: catalog.facts.sections[0]?.metrics ?? [],
    exploit: catalog.facts.sections[2]?.metrics ?? [],
    days: catalog.days.map((row) => ({
      label: row.label,
      published: formatInt(row.published),
      critical: formatInt(row.critical)
    })),
    vendors: catalog.vendors.map((row) => ({ vendor: row.vendor, count: formatInt(row.count) })),
    products: catalog.products.map((row) => ({
      product: row.product,
      vendor: row.vendor || "—",
      count: formatInt(row.count)
    })),
    kevRows: catalog.kevRows.map((row) => ({
      cveId: row.cveId,
      dateAdded: row.dateAdded,
      product: row.product || row.vendor || "—",
      cvss: row.cvss || "—",
      epss: row.epss || "—"
    })),
    cves: catalog.cves.map((row) => ({
      cveId: row.cveId,
      vendor: row.vendor || "",
      product: row.product || "",
      cvss: row.cvss || "—",
      epss: row.epss || "—",
      kev: row.kev || "—",
      publishedDay: row.publishedDay,
      signal: row.signal,
      description: row.description
    })),
    narrative: {
      status: story.status,
      lead: story.lead,
      summary: story.summary,
      cases: story.cases,
      close: story.close,
      text: story.text
    } satisfies PreviewNarrative
  };
}

function buildFacts(catalog: Omit<MonthCatalog, "facts">): DigestNarrativeFacts {
  const history =
    catalog.epssHistoryPoints > 0
      ? `В истории EPSS за этот месяц ${formatInt(catalog.epssHistoryPoints)} точек по ${formatInt(catalog.epssHistoryCves)} CVE, опубликованным в месяце.`
      : "Истории EPSS за этот месяц в каталоге нет: EPSS ниже — текущий снимок, не движение внутри месяца.";
  const peak = catalog.peak
    ? `Максимум публикаций за день: ${formatInt(catalog.peak.published)}, день ${catalog.peak.label}.`
    : "Дней с публикациями нет.";
  const coverage = [
    `Календарный месяц UTC ${catalog.window.periodLabel}.`,
    `Публикации считаются по published_at с ${catalog.window.startDay} включительно до ${catalog.window.endDay} не включая.`,
    `CISA KEV — date_added в этом месяце, в том числе если CVE опубликован раньше. В списке не больше ${KEV_CAP} строк, полное число — в метрике.`,
    `Заметных CVE в рассказе не больше ${NOTABLE_CAP}. Это не все публикации месяца.`,
    history,
    "Публичный эксплойт, PoC и скачок EPSS — текущие флаги intel у CVE, опубликованных в месяце. Их нельзя складывать в одну долю.",
    "Хосты, активы, серверы и IP в выпуск не входят."
  ].join(" ");
  const summary: DigestNarrativeSection = {
    title: "Сводка месяца",
    status: "ready",
    note: "Числа относятся только к выбранному календарному месяцу.",
    metrics: [
      { label: "Опубликовано", value: formatInt(catalog.published) },
      { label: "CVSS ≥ 9", value: formatInt(catalog.critical) },
      { label: "CVSS 7–8.9", value: formatInt(catalog.high) },
      { label: "CVSS 4–6.9", value: formatInt(catalog.medium) },
      { label: "CVSS < 4", value: formatInt(catalog.low) },
      { label: "Без CVSS", value: formatInt(catalog.unscored) },
      { label: "Новые CISA KEV", value: formatInt(catalog.kevAdded) },
      { label: "Новые VulnCheck KEV", value: formatInt(catalog.vckevAdded) }
    ],
    bars: [],
    tables: []
  };
  const trend: DigestNarrativeSection = {
    title: "Ряд публикаций",
    status: catalog.days.length ? "ready" : "empty",
    note: peak,
    metrics: [
      { label: "Публикации", value: formatInt(catalog.published) },
      { label: "CVSS ≥ 9 за месяц", value: formatInt(catalog.critical) }
    ],
    bars: [],
    tables: []
  };
  const exploit: DigestNarrativeSection = {
    title: "Эксплойт и EPSS",
    status: "ready",
    note: history,
    metrics: [
      { label: "EPSS ≥ 0.7", value: formatInt(catalog.highEpss) },
      { label: "Скачок EPSS", value: formatInt(catalog.epssSpikes) },
      { label: "Публичный эксплойт", value: formatInt(catalog.publicExploit) },
      { label: "Есть PoC", value: formatInt(catalog.poc) },
      { label: "VulnCheck KEV, не CISA", value: formatInt(catalog.vckevOnly) },
      { label: "Точек истории EPSS", value: formatInt(catalog.epssHistoryPoints) }
    ],
    bars: [],
    tables: []
  };
  const vendors: DigestNarrativeSection = {
    title: "Вендоры и продукты",
    status: catalog.vendors.length || catalog.products.length ? "ready" : "empty",
    note: "Сколько опубликованных в месяце CVE связано с вендором или продуктом. Одна запись может входить в несколько строк.",
    metrics: [],
    bars: [],
    tables: [
      ...(catalog.vendors.length
        ? [{ columns: ["Вендор", "CVE"], rows: catalog.vendors.map((row) => [row.vendor, formatInt(row.count)]) }]
        : []),
      ...(catalog.products.length
        ? [{
            columns: ["Продукт", "Вендор", "CVE"],
            rows: catalog.products.map((row) => [row.product, row.vendor || "—", formatInt(row.count)])
          }]
        : [])
    ]
  };
  const kev: DigestNarrativeSection = {
    title: "CISA KEV месяца",
    status: catalog.kevRows.length ? "ready" : "empty",
    note: `Добавления CISA KEV за месяц: ${formatInt(catalog.kevAdded)}. В таблице не больше ${KEV_CAP}.`,
    metrics: [{ label: "Новые CISA KEV", value: formatInt(catalog.kevAdded) }],
    bars: [],
    tables: catalog.kevRows.length
      ? [{
          columns: ["CVE", "Дата", "Продукт", "CVSS", "EPSS"],
          rows: catalog.kevRows.map((row) => [
            row.cveId,
            row.dateAdded,
            row.product || row.vendor || "—",
            row.cvss || "—",
            row.epss || "—"
          ])
        }]
      : []
  };
  const cveNotes: DigestCveNote[] = [];
  const seen = new Set<string>();
  for (const row of catalog.cves) {
    if (cveNotes.length >= 12) break;
    seen.add(row.cveId);
    cveNotes.push({
      cveId: row.cveId,
      description: [row.description, row.signal, row.publishedDay ? `опубликовано ${row.publishedDay}` : ""]
        .filter(Boolean)
        .join(". "),
      vendor: row.vendor,
      product: row.product,
      cvss: row.cvss,
      epss: row.epss,
      kev: row.kev
    });
  }
  for (const row of catalog.kevRows) {
    if (cveNotes.length >= 12) break;
    if (seen.has(row.cveId)) continue;
    seen.add(row.cveId);
    cveNotes.push({
      cveId: row.cveId,
      description: [row.name, row.publishedDay ? `опубликовано ${row.publishedDay}` : "опубликовано раньше этого месяца"]
        .filter(Boolean)
        .join(". "),
      vendor: row.vendor,
      product: row.product,
      cvss: row.cvss,
      epss: row.epss,
      kev: "KEV"
    });
  }
  return {
    title: `Дайджест уязвимостей · ${catalog.window.monthTitle}`,
    windowLabel: catalog.window.windowLabel,
    issuedAt: catalog.issuedLabel,
    coverage,
    sections: [summary, trend, exploit, vendors, kev],
    cveNotes
  };
}

function sourcesNote(catalog: Omit<MonthCatalog, "facts">) {
  return [
    `В выпуск вошли публикации каталога за ${catalog.window.windowLabel}: ${formatInt(catalog.published)}.`,
    `Заметных CVE в рассказе: ${formatInt(catalog.cves.length)} из ${formatInt(catalog.published)}.`,
    `CISA KEV с датой добавления в этом месяце: ${formatInt(catalog.kevAdded)}, в таблице ${formatInt(catalog.kevRows.length)}.`,
    `Вендоров в топе: ${formatInt(catalog.vendors.length)}, продуктов: ${formatInt(catalog.products.length)}.`,
    catalog.epssHistoryPoints > 0
      ? `История EPSS за месяц: ${formatInt(catalog.epssHistoryPoints)} точек.`
      : "Истории EPSS за месяц нет, показан текущий снимок."
  ].join(" ");
}

function tilesOf(catalog: Omit<MonthCatalog, "facts">) {
  return [
    { label: "Опубликовано", value: formatInt(catalog.published) },
    { label: "CVSS ≥ 9", value: formatInt(catalog.critical) },
    { label: "Новые CISA KEV", value: formatInt(catalog.kevAdded) },
    { label: "EPSS ≥ 0.7", value: formatInt(catalog.highEpss) },
    { label: "Публичный эксплойт", value: formatInt(catalog.publicExploit) }
  ];
}

function skippedStory(): DigestNarrativeOutcome {
  return {
    status: "skipped",
    text: DIGEST_NARRATIVE_SKIPPED,
    lead: DIGEST_NARRATIVE_SKIPPED,
    summary: "",
    cases: "",
    close: ""
  };
}

function acceptClientStory(value: unknown, factsText: string): DigestNarrativeOutcome | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  if (row.status === "skipped") return skippedStory();
  if (row.status === "failed") {
    const lead = row.lead === DIGEST_NARRATIVE_REJECTED ? DIGEST_NARRATIVE_REJECTED : DIGEST_NARRATIVE_FAILED;
    return { status: "failed", text: lead, lead, summary: "", cases: "", close: "" };
  }
  if (row.status !== "generated") return null;
  const parts = {
    lead: filterDigestNarrative(clipText(row.lead, 4000), factsText),
    summary: filterDigestNarrative(clipText(row.summary, 4000), factsText),
    cases: filterDigestNarrative(clipText(row.cases, 8000), factsText),
    close: filterDigestNarrative(clipText(row.close, 2000), factsText)
  };
  const text = [parts.lead, parts.summary, parts.cases, parts.close].filter(Boolean).join("\n\n");
  if (!text) {
    return {
      status: "failed",
      text: DIGEST_NARRATIVE_REJECTED,
      lead: DIGEST_NARRATIVE_REJECTED,
      summary: "",
      cases: "",
      close: ""
    };
  }
  return { status: "generated", text, ...parts };
}

function monthWindow(year: number, month: number): MonthWindow {
  if (!Number.isInteger(year) || year < 1999 || year > 2100 || !Number.isInteger(month) || month < 1 || month > 12) {
    throw new BadRequestException("Нужен календарный месяц");
  }
  const start = new Date(Date.UTC(year, month - 1, 1));
  const end = new Date(Date.UTC(year, month, 1));
  const lastDay = new Date(Date.UTC(year, month, 0)).getUTCDate();
  const mm = String(month).padStart(2, "0");
  return {
    year,
    month,
    lastDay,
    startIso: start.toISOString(),
    endIso: end.toISOString(),
    startDay: start.toISOString().slice(0, 10),
    endDay: end.toISOString().slice(0, 10),
    label: `${MONTHS_NOM[month - 1]} ${year}`,
    monthTitle: `${MONTHS_TITLE[month - 1]} ${year}`,
    windowLabel: `1–${lastDay} ${MONTHS_GEN[month - 1]} ${year}`,
    periodLabel: `01.${mm}.${year}–${String(lastDay).padStart(2, "0")}.${mm}.${year}`
  };
}

function asRecord(body: unknown): Record<string, unknown> {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new BadRequestException("Нужен объект дайджеста");
  return body as Record<string, unknown>;
}

function asInt(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) ? value : null;
}

function issuedFrom(value: unknown): Date | undefined {
  if (typeof value !== "string") return undefined;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return undefined;
  const delta = Date.now() - date.getTime();
  if (delta < -60_000 || delta > 6 * 60 * 60 * 1000) return undefined;
  return date;
}

function num(value: unknown): number {
  const n = Number(value ?? 0);
  return Number.isFinite(n) ? n : 0;
}

function formatInt(value: number): string {
  return new Intl.NumberFormat("ru-RU").format(value);
}

function formatScore(value: number): string {
  return new Intl.NumberFormat("ru-RU", { maximumFractionDigits: 4 }).format(value);
}

function dayLabel(day: string): string {
  const [, month, date] = day.split("-");
  if (!month || !date) return day;
  return `${date}.${month}`;
}

function clipText(value: unknown, max: number): string {
  if (typeof value !== "string" && typeof value !== "number") return "";
  return String(value)
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);
}

function formatMsk(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  const label = new Intl.DateTimeFormat("ru-RU", {
    day: "numeric",
    month: "long",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "Europe/Moscow",
    hour12: false
  }).format(date);
  return `${label} МСК`;
}

const READING = [
  "Публикации — CVE с published_at внутри выбранного календарного месяца.",
  "CISA KEV — дата добавления в каталог KEV попадает в этот месяц. Это не дата публикации CVE.",
  "EPSS, публичный эксплойт и PoC — текущий снимок у опубликованных в месяце CVE. Эти счётчики пересекаются.",
  "Список заметных CVE короче полного числа публикаций. Полное число стоит в сводке.",
  "Если ключ дайджеста не задан, связного рассказа нет. Факты каталога остаются.",
  "Пустой список остаётся пустым. Недостающие числа не достраиваются."
];

function renderMonthPdf(catalog: MonthCatalog, story: DigestNarrativeOutcome): Promise<Buffer> {
  const doc = new PDFDocument({
    size: "A4",
    margins: { top: 58, bottom: 52, left: 48, right: 48 },
    bufferPages: true,
    info: { Title: catalog.facts.title, Author: "VulnControl" }
  });
  const chunks: Buffer[] = [];
  doc.on("data", (chunk: Buffer) => chunks.push(chunk));
  const done = new Promise<Buffer>((resolve, reject) => {
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);
  });
  doc.registerFont("sans", path.join(FONT_DIR, "DejaVuSans.ttf"));
  doc.registerFont("sans-bold", path.join(FONT_DIR, "DejaVuSans-Bold.ttf"));
  doc.on("pageAdded", () => drawRunningHeader(doc, catalog.facts.title));

  doc.rect(0, 0, doc.page.width, 8).fill("#1d4ed8");
  doc.fillColor("#64748b").font("sans").fontSize(9).text("VULNCONTROL", 48, 36);
  doc.fillColor("#0f172a").font("sans-bold").fontSize(22).text("Дайджест уязвимостей", 48, 54, { width: doc.page.width - 96 });
  doc.moveDown(0.2);
  doc.font("sans").fontSize(12).fillColor("#1e293b").text(catalog.window.monthTitle);
  doc.moveDown(0.35);
  doc.font("sans").fontSize(10).fillColor("#334155").text(
    "Фокус: CVE, опубликованные в этом календарном месяце, добавления CISA KEV, текущие сигналы EPSS, публичные эксплойты и PoC, вендоры и продукты."
  );
  doc.moveDown(0.6);
  drawTiles(doc, tilesOf(catalog));
  prose(doc, story.lead || DIGEST_NARRATIVE_SKIPPED);
  prose(doc, sourcesNote(catalog));
  doc.moveDown(0.2);
  doc.font("sans").fontSize(10).fillColor("#334155");
  doc.text(`Период: ${catalog.window.periodLabel}`);
  doc.text(`Окно: ${catalog.window.windowLabel}`);
  doc.text(`Подготовлено: ${catalog.issuedLabel}`);
  doc.text(`Учётная запись: ${catalog.accountEmail}`);

  chapter(doc, "1", "Краткий вывод");
  prose(doc, story.status === "generated" ? story.summary || story.lead : story.lead || DIGEST_NARRATIVE_SKIPPED);
  prose(doc, "Ниже — цифры только этого календарного месяца и короткое пояснение, что считает каждая. Сравнения с прошлым месяцем в каталоге нет.");
  drawMetrics(doc, catalog.facts.sections[0]);

  chapter(doc, "2", "Метрики месяца и ряд публикаций");
  prose(doc, catalog.facts.sections[1]?.note || "Ряд — дни, в которые каталог видит публикации.");
  drawMetrics(doc, catalog.facts.sections[1]);
  drawBars(doc, catalog.days);

  chapter(doc, "3", "Заметные CVE месяца");
  prose(
    doc,
    `Таблица — не больше ${NOTABLE_CAP} записей, опубликованных в месяце, в порядке KEV, CVSS и EPSS. Пустой месяц остаётся пустым.`
  );
  drawTable(
    doc,
    ["CVE", "Продукт", "CVSS", "EPSS", "KEV"],
    catalog.cves.map((row) => [row.cveId, row.product || row.vendor || "—", row.cvss || "—", row.epss || "—", row.kev || "—"])
  );
  if (story.status === "generated" && story.cases) prose(doc, story.cases);

  chapter(doc, "4", "Вендоры и продукты");
  prose(doc, catalog.facts.sections[3]?.note || "Топ публикаций месяца.");
  for (const table of catalog.facts.sections[3]?.tables ?? []) {
    drawTable(doc, table.columns, table.rows);
  }
  if (!catalog.vendors.length && !catalog.products.length) prose(doc, "Нет строк.");

  chapter(doc, "5", "Что вошло в CISA KEV");
  prose(doc, catalog.facts.sections[4]?.note || "Добавления KEV за месяц.");
  drawTable(
    doc,
    ["CVE", "Дата", "Продукт", "CVSS", "EPSS"],
    catalog.kevRows.map((row) => [row.cveId, row.dateAdded, row.product || row.vendor || "—", row.cvss || "—", row.epss || "—"])
  );

  chapter(doc, "6", "Эксплойт и EPSS");
  prose(
    doc,
    "EPSS — текущая оценка вероятности эксплуатации, не подтверждение атаки. Флаги эксплойта и PoC пересекаются. Если истории EPSS за месяц нет, движение внутри месяца не выводится."
  );
  drawMetrics(doc, catalog.facts.sections[2]);

  chapter(doc, "7", "Ключевые записи");
  if (!catalog.cves.length) prose(doc, "Ключевых записей за этот месяц нет.");
  for (const note of catalog.cves) {
    ensureRoom(doc, 78);
    const who = [note.product, note.vendor].filter(Boolean).join(" · ");
    doc.moveDown(0.35);
    doc.font("sans-bold").fontSize(11).fillColor("#0f172a").text(who ? `${note.cveId} — ${who}` : note.cveId);
    const bits = [note.cvss ? `CVSS ${note.cvss}` : "", note.epss ? `EPSS ${note.epss}` : "", note.signal].filter(Boolean);
    if (bits.length) doc.font("sans").fontSize(9).fillColor("#64748b").text(bits.join("   ·   "));
    doc.font("sans").fontSize(10).fillColor("#1e293b").text(note.description || "Короткого описания в каталоге нет.");
  }

  chapter(doc, "8", "Как читать этот выпуск");
  for (const line of READING) prose(doc, line);
  if (story.status === "generated" && story.close) prose(doc, story.close);
  prose(doc, catalog.facts.coverage);
  prose(
    doc,
    story.status === "generated"
      ? "Рассказ собран DeepSeek только из этих цифр и коротких описаний. Предложение с числом или CVE вне этого набора отбрасывается."
      : story.lead || DIGEST_NARRATIVE_SKIPPED
  );

  stampPages(doc, catalog.facts.title);
  doc.end();
  return done;
}

function drawTiles(doc: PdfDoc, tiles: Array<{ value: string; label: string }>) {
  if (!tiles.length) return;
  const y = doc.y;
  const gap = 6;
  const width = (doc.page.width - 96 - gap * (tiles.length - 1)) / tiles.length;
  tiles.forEach((tile, index) => {
    const x = 48 + index * (width + gap);
    doc.roundedRect(x, y, width, 62, 6).fill("#f8fafc");
    doc.fillColor("#0f172a").font("sans-bold").fontSize(12).text(tile.value, x + 6, y + 10, { width: width - 12, lineBreak: false });
    doc.fillColor("#64748b").font("sans").fontSize(7).text(tile.label, x + 6, y + 32, { width: width - 12 });
  });
  doc.x = 48;
  doc.y = y + 74;
}

function drawMetrics(doc: PdfDoc, section: DigestNarrativeSection | undefined) {
  if (!section) return;
  if (section.status === "empty") return prose(doc, "Нет строк.");
  for (const metric of section.metrics) {
    ensureRoom(doc, 28);
    doc.moveDown(0.2);
    doc.font("sans-bold").fontSize(12).fillColor("#0f172a").text(metric.value, { continued: true });
    doc.font("sans").fontSize(10).fillColor("#334155").text(`   ${metric.label}`);
  }
}

function drawBars(doc: PdfDoc, days: DayRow[]) {
  if (!days.length) return prose(doc, "Нет публикаций.");
  doc.moveDown(0.3);
  doc.font("sans").fontSize(9).fillColor("#64748b").text("Дни с публикациями");
  for (const row of days) {
    ensureRoom(doc, 14);
    doc.font("sans").fontSize(9).fillColor("#1e293b").text(`${row.label}    ${formatInt(row.published)}    CVSS ≥ 9: ${formatInt(row.critical)}`);
  }
}

function drawTable(doc: PdfDoc, columns: string[], rows: string[][]) {
  if (!rows.length) return prose(doc, "Нет строк.");
  doc.moveDown(0.3);
  if (columns.length) doc.font("sans-bold").fontSize(8).fillColor("#64748b").text(columns.join("   ·   "));
  for (const row of rows) {
    ensureRoom(doc, 16);
    doc.font("sans").fontSize(8).fillColor("#0f172a").text(row.join("   ·   "));
  }
}

function chapter(doc: PdfDoc, n: string, title: string) {
  ensureRoom(doc, 64);
  doc.moveDown(0.85);
  doc.font("sans-bold").fontSize(14).fillColor("#0f172a").text(`${n}. ${title}`);
  doc.moveDown(0.25);
}

function prose(doc: PdfDoc, text: string) {
  if (!text.trim()) return;
  ensureRoom(doc, 36);
  doc.moveDown(0.15);
  doc.font("sans").fontSize(10).fillColor("#1e293b").text(text, { width: doc.page.width - 96 });
}

function drawRunningHeader(doc: PdfDoc, title: string) {
  const previousX = doc.x;
  const previousY = doc.y;
  doc.font("sans").fontSize(8).fillColor("#64748b").text(title, 48, 28, { width: doc.page.width - 140, lineBreak: false });
  doc.x = previousX;
  doc.y = Math.max(previousY, 58);
}

function stampPages(doc: PdfDoc, title: string) {
  const range = doc.bufferedPageRange();
  for (let i = 0; i < range.count; i++) {
    doc.switchToPage(range.start + i);
    doc.font("sans").fontSize(8).fillColor("#64748b").text(`Стр. ${i + 1}`, 48, doc.page.height - 36, {
      width: doc.page.width - 96,
      align: "right",
      lineBreak: false
    });
    if (i > 0) {
      doc.font("sans").fontSize(8).fillColor("#64748b").text(title, 48, 28, { width: doc.page.width - 140, lineBreak: false });
    }
  }
}

function ensureRoom(doc: PdfDoc, height: number) {
  const bottom = doc.page.height - doc.page.margins.bottom;
  if (doc.y + height > bottom) doc.addPage();
}

async function loadOpenMonthSources(startDay: string, endDay: string, startIso: string, endIso: string) {
  const [cisa, nvd] = await Promise.all([
    fetchText("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", 25_000, 12_000_000),
    fetchText(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${encodeURIComponent(startIso)}&pubEndDate=${encodeURIComponent(endIso)}&resultsPerPage=20`,
      25_000,
      4_000_000
    )
  ]);
  const blocks: string[] = [];
  const titles: string[] = [];
  const cisaLines = cisa ? cisaMonthLines(cisa, startDay, endDay) : null;
  if (cisaLines) {
    titles.push("CISA KEV");
    blocks.push(`CISA KEV, записи с dateAdded с ${startDay} до ${endDay} (открытая выгрузка, не каталог платформы):\n${cisaLines}`);
  }
  const nvdLines = nvd ? nvdMonthLines(nvd) : null;
  if (nvdLines) {
    titles.push("NVD");
    blocks.push(`NVD, выборка публикаций ${startIso} — ${endIso} (открытый API, не полный месяц и не каталог платформы):\n${nvdLines}`);
  }
  return {
    titles,
    text: blocks.join("\n\n").slice(0, 24_000)
  };
}

function cisaMonthLines(raw: string, startDay: string, endDay: string): string | null {
  try {
    const parsed = JSON.parse(raw) as { vulnerabilities?: Array<Record<string, unknown>> };
    const rows = (parsed.vulnerabilities ?? [])
      .filter((row) => {
        const added = String(row.dateAdded ?? "");
        return added >= startDay && added < endDay;
      })
      .slice(0, 40)
      .map((row) =>
        [row.cveID, row.dateAdded, row.vendorProject, row.product, row.vulnerabilityName, row.shortDescription, row.requiredAction]
          .map((part) => String(part ?? "").replace(/\s+/g, " ").trim())
          .filter(Boolean)
          .join(" | ")
          .slice(0, 500)
      );
    return rows.length ? rows.join("\n") : "За этот месяц в выгрузке нет новых записей KEV.";
  } catch {
    return null;
  }
}

function nvdMonthLines(raw: string): string | null {
  try {
    const parsed = JSON.parse(raw) as {
      totalResults?: number;
      vulnerabilities?: Array<{ cve?: Record<string, unknown> }>;
    };
    const rows = (parsed.vulnerabilities ?? []).slice(0, 20).map((item) => {
      const cve = item.cve ?? {};
      const descriptions = Array.isArray(cve.descriptions) ? cve.descriptions : [];
      const english = descriptions.find((row) => {
        return Boolean(row && typeof row === "object" && (row as { lang?: string }).lang === "en");
      }) as { value?: string } | undefined;
      const metrics = cve.metrics && typeof cve.metrics === "object" ? (cve.metrics as Record<string, unknown>) : {};
      const v31 = Array.isArray(metrics.cvssMetricV31) ? metrics.cvssMetricV31[0] : undefined;
      const score = v31 && typeof v31 === "object" ? (v31 as { cvssData?: { baseScore?: number } }).cvssData?.baseScore : undefined;
      return [cve.id, cve.published, score != null ? `CVSS ${score}` : "", english?.value]
        .map((part) => String(part ?? "").replace(/\s+/g, " ").trim())
        .filter(Boolean)
        .join(" | ")
        .slice(0, 500);
    }).filter(Boolean);
    const total = typeof parsed.totalResults === "number" ? parsed.totalResults : rows.length;
    if (!rows.length) return `За этот интервал NVD не вернул публикации. totalResults=${total}.`;
    return `totalResults=${total}. В запрос попали первые ${rows.length} записей ответа, не весь месяц.\n${rows.join("\n")}`;
  } catch {
    return null;
  }
}

function fetchText(url: string, timeoutMs: number, limit: number) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, {
    signal: controller.signal,
    headers: { accept: "application/json", "user-agent": "vuln-intel-digest" }
  })
    .then(async (response) => (response.ok ? (await response.text()).slice(0, limit) : ""))
    .catch(() => "")
    .finally(() => clearTimeout(timer));
}

async function renderOpenWebPdf(input: {
  title: string;
  monthLabel: string;
  text: string;
  sources: string[];
  accountEmail: string;
}) {
  const doc = new PDFDocument({ size: "A4", margin: 48, info: { Title: input.title } });
  doc.registerFont("sans", path.join(FONT_DIR, "DejaVuSans.ttf"));
  doc.registerFont("sans-bold", path.join(FONT_DIR, "DejaVuSans-Bold.ttf"));
  const chunks: Buffer[] = [];
  const done = new Promise<Buffer>((resolve, reject) => {
    doc.on("data", (chunk: Buffer) => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);
  });
  doc.font("sans").fontSize(18).fillColor("#0f172a").text(input.title, { width: 500 });
  doc.moveDown(0.3);
  doc.fontSize(10).fillColor("#64748b").text(`Период: ${input.monthLabel}`, { width: 500 });
  doc.text(`Источники: ${input.sources.join(", ") || "открытые выгрузки"}`, { width: 500 });
  doc.text("Цифры каталога VulnControl в этот отчёт не входили.", { width: 500 });
  doc.moveDown(0.6);
  doc.fontSize(11).fillColor("#0f172a").text(input.text, { width: 500, align: "left" });
  doc.moveDown(0.8);
  doc.fontSize(8).fillColor("#64748b").text(`Выпустил: ${input.accountEmail}`, { width: 500 });
  doc.end();
  return done;
}

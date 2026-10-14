import { createRequire } from "node:module";
import path from "node:path";
import { BadRequestException, Injectable } from "@nestjs/common";
import PDFDocument from "pdfkit";
import {
  parseOpenWebDigest,
  runOpenWebDigest,
  type OpenDigestChart,
  type OpenDigestDocument
} from "@vuln-intel/shared";
import { IntegrationSettingsService } from "./integration-settings.service.js";

const require = createRequire(import.meta.url);
const FONT_DIR = path.join(path.dirname(require.resolve("dejavu-fonts-ttf/package.json")), "ttf");

const MONTHS_NOM = [
  "январь", "февраль", "март", "апрель", "май", "июнь",
  "июль", "август", "сентябрь", "октябрь", "ноябрь", "декабрь"
];
const MONTHS_TITLE = [
  "Январь", "Февраль", "Март", "Апрель", "Май", "Июнь",
  "Июль", "Август", "Сентябрь", "Октябрь", "Ноябрь", "Декабрь"
];

@Injectable()
export class OpenMonthDigestService {
  constructor(private readonly integration: IntegrationSettingsService) {}

  async preview(year: number, month: number) {
    const window = monthWindow(year, month);
    const sources = await loadOpenMonthSources(year, month, window.startDay, window.endDay, window.startIso, window.endIso);
    if (!sources.text.trim()) {
      return {
        kind: "month" as const,
        year,
        month,
        monthLabel: window.label,
        status: "failed" as const,
        searched: false,
        text: "Открытые выгрузки за этот месяц не загрузились. Отчёт не собран.",
        sources: [] as string[],
        charts: [] as OpenDigestChart[],
        note: "Запрос в DeepSeek не отправлялся: без материалов из интернета рассказ был бы выдуманным. Цифры каталога VulnControl не использовались."
      };
    }
    const llm = await this.integration.getDigestLlmConfig();
    const story = await runOpenWebDigest({
      monthLabel: window.label,
      sourcesText: sources.text,
      llm
    });
    const note = story.status === "skipped"
      ? "Ключ DeepSeek не задан. Сохраните его в «Настройки → Текст и LLM»: он нужен этому дайджесту и кнопке AI на одной карточке. Очередь каталога из‑за этого не стартует."
      : story.searched
        ? "DeepSeek искал в открытом интернете и собрал вывод. Графики построены по открытым фидам (CISA KEV, NVD, EPSS). Каталог VulnControl не использовался."
        : "Платформа сняла CISA KEV, NVD, EPSS и бюллетени; DeepSeek написал слайды по этому сырью. Web-search API не ответил вовремя. Графики — из фидов.";
    return {
      kind: "month" as const,
      year,
      month,
      monthLabel: window.label,
      monthTitle: window.monthTitle,
      period: `${window.startDay.split("-").reverse().join(".")}–${shiftDay(window.endDay)}`,
      status: story.status,
      searched: story.searched,
      text: story.text,
      document: story.document,
      charts: sources.charts,
      sources: sources.titles,
      note
    };
  }

  async pdf(body: unknown, accountEmail: string): Promise<{ buffer: Buffer; filename: string }> {
    const raw = asRecord(body);
    const year = asInt(raw.year);
    const month = asInt(raw.month);
    if (year == null || month == null) throw new BadRequestException("Нужен календарный месяц");
    const window = monthWindow(year, month);
    const text = typeof raw.text === "string" ? raw.text.trim().slice(0, 24_000) : "";
    const document = acceptDocument(raw.document, text);
    if (!text && !document) throw new BadRequestException("Нет текста предпросмотра");
    const sources = Array.isArray(raw.sources)
      ? raw.sources.map((item) => String(item).slice(0, 80)).filter(Boolean).slice(0, 12)
      : [];
    const charts = parseCharts(raw.charts);
    const buffer = await renderBriefPdf({
      monthTitle: window.monthTitle,
      period: `${window.startDay.split("-").reverse().join(".")}–${shiftDay(window.endDay)}`,
      prepared: preparedLabel(),
      text,
      document,
      charts,
      sources,
      accountEmail: accountEmail.slice(0, 120) || "текущая сессия"
    });
    const mm = String(window.month).padStart(2, "0");
    return { buffer, filename: `vulncontrol-digest-${window.year}-${mm}.pdf` };
  }
}

function monthWindow(year: number, month: number) {
  if (!Number.isInteger(year) || year < 1999 || year > 2100 || !Number.isInteger(month) || month < 1 || month > 12) {
    throw new BadRequestException("Нужен календарный месяц");
  }
  const start = new Date(Date.UTC(year, month - 1, 1));
  const end = new Date(Date.UTC(year, month, 1));
  return {
    year,
    month,
    startIso: start.toISOString(),
    endIso: end.toISOString(),
    startDay: start.toISOString().slice(0, 10),
    endDay: end.toISOString().slice(0, 10),
    label: `${MONTHS_NOM[month - 1]} ${year}`,
    monthTitle: `${MONTHS_TITLE[month - 1]} ${year}`
  };
}

function asRecord(body: unknown): Record<string, unknown> {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new BadRequestException("Нужен объект дайджеста");
  return body as Record<string, unknown>;
}

function asInt(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) ? value : null;
}

async function loadOpenMonthSources(year: number, month: number, startDay: string, endDay: string, startIso: string, endIso: string) {
  const prev = shiftMonth(year, month, -1);
  const prevStart = new Date(Date.UTC(prev.year, prev.month - 1, 1));
  const prevEnd = new Date(Date.UTC(prev.year, prev.month, 1));
  const [cisa, nvd, nvdPrev, cisaNews, fstecHtml] = await Promise.all([
    fetchText("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", 30_000, 12_000_000),
    fetchText(nvdUrl(startIso, endIso, 100), 30_000, 8_000_000),
    fetchText(nvdUrl(prevStart.toISOString(), prevEnd.toISOString(), 1), 25_000, 200_000),
    fetchText("https://www.cisa.gov/news-events/cybersecurity-advisories", 15_000, 400_000),
    fetchText("https://bdu.fstec.ru/", 12_000, 300_000)
  ]);
  const blocks: string[] = [];
  const titles: string[] = [];
  const charts: OpenDigestChart[] = [];
  const facts: string[] = [
    "СЫРЬЁ ДЛЯ ВЫВОДА И ГРАФИКОВ. Это открытые фиды, не каталог VulnControl.",
    "Описания вендоров пересказывать нельзя. Числа ниже можно цитировать."
  ];
  const cisaPack = cisa
    ? cisaMonthPack(cisa, startDay, endDay, prevStart.toISOString().slice(0, 10), prevEnd.toISOString().slice(0, 10))
    : null;
  if (cisaPack) {
    titles.push("CISA KEV");
    facts.push(`Новых CISA KEV за этот месяц: ${cisaPack.count}. За предыдущий месяц: ${cisaPack.previous}.`);
    if (cisaPack.vendors) facts.push(`Сколько записей KEV по вендорам: ${cisaPack.vendors}.`);
    if (cisaPack.weeksText) facts.push(`KEV по неделям месяца: ${cisaPack.weeksText}.`);
    blocks.push(`Поля KEV, dateAdded с ${startDay} до ${endDay}:\n${cisaPack.text}`);
    charts.push({
      id: "kev_compare",
      slide: "Месяц в цифрах",
      title: "Новые CISA KEV: месяц vs прошлый",
      kind: "compare",
      bars: [
        { label: "Этот месяц", value: cisaPack.count },
        { label: "Прошлый", value: cisaPack.previous }
      ]
    });
    if (cisaPack.weekBars.length) {
      charts.push({
        id: "kev_weeks",
        slide: "Динамика CVE",
        title: "Добавления в CISA KEV по неделям",
        kind: "bars",
        bars: cisaPack.weekBars
      });
    }
    if (cisaPack.vendorBars.length) {
      charts.push({
        id: "kev_vendors",
        slide: "Технологии под давлением",
        title: "Топ вендоров в новых CISA KEV",
        kind: "bars",
        bars: cisaPack.vendorBars
      });
    }
  }
  const nvdPack = nvd ? nvdMonthPack(nvd) : null;
  const prevTotal = nvdPrev ? nvdTotal(nvdPrev) : null;
  if (nvdPack) {
    titles.push("NVD");
    facts.push(`Публикаций NVD за этот месяц, totalResults: ${nvdPack.total}.`);
    if (prevTotal != null) facts.push(`Публикаций NVD за предыдущий месяц, totalResults: ${prevTotal}.`);
    if (nvdPack.severityText) facts.push(`CVSS в выборке NVD (первые записи ответа): ${nvdPack.severityText}.`);
    blocks.push(`NVD ${startIso} — ${endIso}, sample=${nvdPack.sampleSize}, totalResults=${nvdPack.total}:\n${nvdPack.text}`);
    if (prevTotal != null) {
      charts.push({
        id: "nvd_compare",
        slide: "Динамика CVE",
        title: "Публикации NVD: месяц vs прошлый",
        kind: "compare",
        bars: [
          { label: "Этот месяц", value: nvdPack.total },
          { label: "Прошлый", value: prevTotal }
        ]
      });
    }
    if (nvdPack.severityBars.length) {
      charts.push({
        id: "cvss_sample",
        slide: "Критичность уязвимостей",
        title: "CVSS в выборке NVD (не весь месяц)",
        kind: "bars",
        bars: nvdPack.severityBars
      });
    }
  }
  const epssPack = cisaPack ? await loadEpssPack(cisaPack.ids) : null;
  if (epssPack) {
    titles.push("FIRST EPSS");
    facts.push(`EPSS по CVE из KEV месяца: ${epssPack.summary}.`);
    blocks.push(`EPSS FIRST на CVE из KEV этого месяца:\n${epssPack.text}`);
    if (epssPack.bandBars.length) {
      charts.push({
        id: "epss_bands",
        slide: "CVSS против EPSS",
        title: "Распределение EPSS по KEV месяца",
        kind: "bars",
        bars: epssPack.bandBars
      });
    }
  }
  const pages = cisaPack ? await loadVendorPages(cisaPack.pageUrls) : [];
  if (pages.length) {
    titles.push("страницы бюллетеней");
    blocks.push(pages.join("\n\n"));
  }
  if (cisaNews) {
    const news = stripHtml(cisaNews).slice(0, 1_200);
    if (news.length > 200) {
      titles.push("CISA advisories");
      blocks.push(`Выдержка CISA cybersecurity advisories (не цитировать дословно):\n${news}`);
    }
  }
  if (fstecHtml) {
    const fstec = stripHtml(fstecHtml).slice(0, 900);
    if (fstec.length > 180) {
      titles.push("БДУ ФСТЭК");
      blocks.push(`Выдержка bdu.fstec.ru (фон для РФ, не полный реестр):\n${fstec}`);
    }
  }
  return {
    titles,
    charts,
    text: [facts.join("\n"), ...blocks].join("\n\n").slice(0, 32_000)
  };
}

function parseCharts(value: unknown): OpenDigestChart[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (!item || typeof item !== "object") return [];
    const row = item as Record<string, unknown>;
    const id = String(row.id ?? "").slice(0, 40);
    const slide = String(row.slide ?? "").slice(0, 80);
    const title = String(row.title ?? "").slice(0, 120);
    const kind: OpenDigestChart["kind"] = row.kind === "compare" ? "compare" : "bars";
    const bars = Array.isArray(row.bars)
      ? row.bars.flatMap((bar) => {
          if (!bar || typeof bar !== "object") return [];
          const cell = bar as { label?: unknown; value?: unknown };
          const label = String(cell.label ?? "").slice(0, 40);
          const num = Number(cell.value);
          if (!label || !Number.isFinite(num) || num < 0) return [];
          return [{ label, value: Math.round(num) }];
        }).slice(0, 12)
      : [];
    if (!id || !slide || !title || bars.length < 1) return [];
    const chart: OpenDigestChart = { id, slide, title, kind, bars };
    return [chart];
  }).slice(0, 8);
}

function nvdUrl(startIso: string, endIso: string, results: number) {
  return `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${encodeURIComponent(startIso)}&pubEndDate=${encodeURIComponent(endIso)}&resultsPerPage=${results}`;
}

function cisaMonthPack(raw: string, startDay: string, endDay: string, prevStart: string, prevEnd: string) {
  try {
    const parsed = JSON.parse(raw) as { vulnerabilities?: Array<Record<string, unknown>> };
    const all = parsed.vulnerabilities ?? [];
    const inRange = (row: Record<string, unknown>, from: string, to: string) => {
      const added = String(row.dateAdded ?? "");
      return added >= from && added < to;
    };
    const current = all.filter((row) => inRange(row, startDay, endDay));
    const previous = all.filter((row) => inRange(row, prevStart, prevEnd)).length;
    const vendorBars = topVendorBars(current);
    const vendors = vendorBars.map((row) => `${row.label} ${row.value}`).join(", ");
    const weekBars = kevWeekBars(current, startDay, endDay);
    const weeksText = weekBars.map((row) => `${row.label} ${row.value}`).join(", ");
    const lines = current.slice(0, 60).map((row) =>
      [row.cveID, row.dateAdded, row.vendorProject, row.product, row.vulnerabilityName]
        .map((part) => String(part ?? "").replace(/\s+/g, " ").trim())
        .filter(Boolean)
        .join(" | ")
        .slice(0, 220)
    );
    const ids = current
      .map((row) => String(row.cveID ?? "").trim().toUpperCase())
      .filter((id) => /^CVE-\d{4}-\d{4,}$/.test(id));
    const pageUrls = current.flatMap((row) => linksIn(String(row.notes ?? ""))).slice(0, 10);
    return {
      count: current.length,
      previous,
      vendors,
      vendorBars,
      weekBars,
      weeksText,
      ids,
      pageUrls,
      text: lines.length ? lines.join("\n") : "За этот месяц в выгрузке нет новых записей KEV."
    };
  } catch {
    return null;
  }
}

function topVendorBars(rows: Array<Record<string, unknown>>) {
  const counts = new Map<string, number>();
  for (const row of rows) {
    const name = String(row.vendorProject ?? "").replace(/\s+/g, " ").trim();
    if (!name) continue;
    counts.set(name, (counts.get(name) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 8)
    .map(([label, value]) => ({ label: label.slice(0, 18), value }));
}

function kevWeekBars(rows: Array<Record<string, unknown>>, startDay: string, endDay: string) {
  const start = new Date(`${startDay}T00:00:00Z`);
  const end = new Date(`${endDay}T00:00:00Z`);
  const buckets: Array<{ label: string; from: string; to: string; value: number }> = [];
  let cursor = new Date(start);
  let week = 1;
  while (cursor < end) {
    const from = cursor.toISOString().slice(0, 10);
    const next = new Date(cursor);
    next.setUTCDate(next.getUTCDate() + 7);
    const to = (next < end ? next : end).toISOString().slice(0, 10);
    buckets.push({ label: `Нед. ${week}`, from, to, value: 0 });
    cursor = next;
    week += 1;
    if (week > 6) break;
  }
  for (const row of rows) {
    const added = String(row.dateAdded ?? "");
    const bucket = buckets.find((item) => added >= item.from && added < item.to);
    if (bucket) bucket.value += 1;
  }
  return buckets.map((item) => ({ label: item.label, value: item.value }));
}

function nvdMonthPack(raw: string) {
  const parsed = readNvd(raw);
  if (!parsed) return null;
  const rows = parsed.rows;
  if (!rows.length && parsed.total == null) return null;
  const total = parsed.total ?? rows.length;
  const severityBars = parsed.severityBars;
  const severityText = severityBars.map((row) => `${row.label} ${row.value}`).join(", ");
  const text = rows.length
    ? `totalResults=${total}. В запрос попали первые ${rows.length} записей ответа, не весь месяц.\n${rows.join("\n")}`
    : `За этот интервал NVD не вернул публикации. totalResults=${total}.`;
  return {
    total,
    text,
    sampleSize: rows.length,
    severityBars,
    severityText
  };
}

function nvdTotal(raw: string) {
  return readNvd(raw)?.total ?? null;
}

function readNvd(raw: string): {
  total: number | null;
  rows: string[];
  severityBars: Array<{ label: string; value: number }>;
} | null {
  try {
    const parsed = JSON.parse(raw) as {
      totalResults?: number;
      vulnerabilities?: Array<{ cve?: Record<string, unknown> }>;
    };
    const bands = { critical: 0, high: 0, medium: 0, low: 0, none: 0 };
    const rows = (parsed.vulnerabilities ?? []).slice(0, 80).map((item) => {
      const cve = item.cve ?? {};
      const descriptions = Array.isArray(cve.descriptions) ? cve.descriptions : [];
      const english = descriptions.find((row) => Boolean(row && typeof row === "object" && (row as { lang?: string }).lang === "en")) as { value?: string } | undefined;
      const metrics = cve.metrics && typeof cve.metrics === "object" ? (cve.metrics as Record<string, unknown>) : {};
      const v31 = Array.isArray(metrics.cvssMetricV31) ? metrics.cvssMetricV31[0] : undefined;
      const v30 = Array.isArray(metrics.cvssMetricV30) ? metrics.cvssMetricV30[0] : undefined;
      const metric = (v31 && typeof v31 === "object" ? v31 : v30 && typeof v30 === "object" ? v30 : null) as
        | { cvssData?: { baseScore?: number } }
        | null;
      const score = metric?.cvssData?.baseScore;
      if (typeof score !== "number") bands.none += 1;
      else if (score >= 9) bands.critical += 1;
      else if (score >= 7) bands.high += 1;
      else if (score >= 4) bands.medium += 1;
      else bands.low += 1;
      const blurb = String(english?.value ?? "").replace(/\s+/g, " ").trim().slice(0, 140);
      return [cve.id, cve.published, score != null ? `CVSS ${score}` : "", blurb]
        .map((part) => String(part ?? "").replace(/\s+/g, " ").trim())
        .filter(Boolean)
        .join(" | ")
        .slice(0, 220);
    }).filter(Boolean);
    const severityBars = [
      { label: "Critical", value: bands.critical },
      { label: "High", value: bands.high },
      { label: "Medium", value: bands.medium },
      { label: "Low", value: bands.low },
      { label: "Нет CVSS", value: bands.none }
    ].filter((row) => row.value > 0);
    return {
      total: typeof parsed.totalResults === "number" ? parsed.totalResults : null,
      rows,
      severityBars
    };
  } catch {
    return null;
  }
}

function shiftMonth(year: number, month: number, delta: number) {
  const date = new Date(Date.UTC(year, month - 1 + delta, 1));
  return { year: date.getUTCFullYear(), month: date.getUTCMonth() + 1 };
}

function shiftDay(isoDay: string) {
  const date = new Date(`${isoDay}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() - 1);
  const day = String(date.getUTCDate()).padStart(2, "0");
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  return `${day}.${month}.${date.getUTCFullYear()}`;
}

function preparedLabel() {
  return new Intl.DateTimeFormat("ru-RU", { timeZone: "Europe/Moscow", day: "2-digit", month: "2-digit", year: "numeric" }).format(new Date());
}

function acceptDocument(value: unknown, text: string): OpenDigestDocument | null {
  if (!value || typeof value !== "object") return null;
  return parseOpenWebDigest(JSON.stringify(value), text);
}

function linksIn(notes: string) {
  return [...notes.matchAll(/https?:\/\/[^\s)]+/g)]
    .map((match) => match[0].replace(/[.,;]+$/, ""))
    .filter((url) => !url.includes("cisa.gov") && !url.includes("nvd.nist.gov"));
}

async function loadEpssPack(ids: string[]) {
  const unique = [...new Set(ids)].slice(0, 60);
  if (!unique.length) return null;
  const chunks: string[][] = [];
  for (let index = 0; index < unique.length; index += 20) chunks.push(unique.slice(index, index + 20));
  const scores: Array<{ cve: string; epss: number; percentile: number | null }> = [];
  for (const group of chunks) {
    const raw = await fetchText(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(group.join(","))}`, 15_000, 500_000);
    if (!raw) continue;
    try {
      const parsed = JSON.parse(raw) as { data?: Array<{ cve?: string; epss?: string; percentile?: string }> };
      for (const row of parsed.data ?? []) {
        const epss = Number(row.epss);
        const percentile = Number(row.percentile);
        if (!row.cve || !Number.isFinite(epss)) continue;
        scores.push({
          cve: String(row.cve).toUpperCase(),
          epss,
          percentile: Number.isFinite(percentile) ? percentile : null
        });
      }
    } catch {
      // skip chunk
    }
  }
  if (!scores.length) return null;
  const bands = { low: 0, mid: 0, high: 0, extreme: 0 };
  for (const row of scores) {
    if (row.epss >= 0.7) bands.extreme += 1;
    else if (row.epss >= 0.4) bands.high += 1;
    else if (row.epss >= 0.1) bands.mid += 1;
    else bands.low += 1;
  }
  const bandBars = [
    { label: "<0.1", value: bands.low },
    { label: "0.1–0.4", value: bands.mid },
    { label: "0.4–0.7", value: bands.high },
    { label: "≥0.7", value: bands.extreme }
  ];
  const top = [...scores].sort((a, b) => b.epss - a.epss).slice(0, 12);
  const text = top
    .map((row) => `${row.cve} | epss ${row.epss}${row.percentile != null ? ` percentile ${row.percentile}` : ""}`)
    .join("\n");
  const summary = bandBars.map((row) => `${row.label}: ${row.value}`).join(", ");
  return { text, summary, bandBars };
}

async function loadVendorPages(urls: string[]) {
  const picked = [...new Set(urls)].slice(0, 6);
  const pages = await Promise.all(picked.map(async (url) => {
    const raw = stripHtml(await fetchText(url, 12_000, 400_000));
    if (raw.length < 180) return "";
    return `Выдержка ${url} (не цитировать дословно):\n${raw.slice(0, 1_100)}`;
  }));
  return pages.filter(Boolean);
}

function stripHtml(raw: string) {
  return raw
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function fetchText(url: string, timeoutMs: number, limit: number) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, {
    signal: controller.signal,
    headers: { accept: "application/json,text/html;q=0.9,*/*;q=0.8", "user-agent": "vuln-intel-digest" }
  })
    .then(async (response) => (response.ok ? (await response.text()).slice(0, limit) : ""))
    .catch(() => "")
    .finally(() => clearTimeout(timer));
}

type PdfDoc = InstanceType<typeof PDFDocument>;

const NAVY = "#0E1C36";
const GOLD = "#C4A35A";
const INK = "#142033";
const MUTED = "#5C6B7A";
const LINE = "#E4E8EE";
const PAPER = "#F4F6FA";
const WHITE = "#FFFFFF";
/** 16:9 presentation slide (960×540 pt). */
const SLIDE_W = 960;
const SLIDE_H = 540;
const LEFT = 48;
const RIGHT = 48;
const TOP = 42;
const BOTTOM = 36;
const WIDTH = SLIDE_W - LEFT - RIGHT;

export async function renderBriefPdf(input: {
  monthTitle: string;
  period: string;
  prepared: string;
  text: string;
  document: OpenDigestDocument | null;
  charts?: OpenDigestChart[];
  sources: string[];
  accountEmail: string;
}) {
  const doc = new PDFDocument({
    size: [SLIDE_W, SLIDE_H],
    margin: 0,
    info: { Title: `Ежемесячный обзор ландшафта уязвимостей — ${input.monthTitle}` }
  });
  doc.registerFont("sans", path.join(FONT_DIR, "DejaVuSans.ttf"));
  doc.registerFont("sans-bold", path.join(FONT_DIR, "DejaVuSans-Bold.ttf"));
  const chunks: Buffer[] = [];
  const done = new Promise<Buffer>((resolve, reject) => {
    doc.on("data", (chunk: Buffer) => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);
  });

  const brief = input.document;
  const charts = input.charts ?? [];
  const totalSlides = 1 + (brief?.sections.length ?? (input.text ? 1 : 0)) + (brief?.closing ? 1 : 0) + 1;
  let pageNo = 1;

  drawTitleSlide(doc, input, pageNo, totalSlides);

  if (brief) {
    for (const section of brief.sections) {
      doc.addPage({ size: [SLIDE_W, SLIDE_H], margin: 0 });
      pageNo += 1;
      drawContentSlide(doc, {
        monthTitle: input.monthTitle,
        period: input.period,
        section,
        charts: charts.filter((chart) => chart.slide === section.title),
        pageNo,
        totalSlides
      });
    }
    if (brief.closing) {
      doc.addPage({ size: [SLIDE_W, SLIDE_H], margin: 0 });
      pageNo += 1;
      drawClosingSlide(doc, {
        monthTitle: input.monthTitle,
        period: input.period,
        closing: brief.closing,
        pageNo,
        totalSlides
      });
    }
  } else if (input.text) {
    doc.addPage({ size: [SLIDE_W, SLIDE_H], margin: 0 });
    pageNo += 1;
    drawFallbackTextSlide(doc, input.monthTitle, input.period, input.text, pageNo, totalSlides);
  }

  doc.addPage({ size: [SLIDE_W, SLIDE_H], margin: 0 });
  pageNo += 1;
  drawSourcesSlide(doc, {
    monthTitle: input.monthTitle,
    period: input.period,
    sources: input.sources,
    accountEmail: input.accountEmail,
    pageNo,
    totalSlides: pageNo
  });

  doc.end();
  return done;
}

function formatBriefNumber(value: string) {
  const trimmed = value.trim();
  if (!/^\d{4,}$/.test(trimmed)) return value;
  return new Intl.NumberFormat("ru-RU").format(Number(trimmed));
}

function drawSlideChrome(
  doc: PdfDoc,
  monthTitle: string,
  period: string,
  pageNo: number,
  totalSlides: number,
  eyebrow: string
) {
  doc.rect(0, 0, SLIDE_W, SLIDE_H).fill(WHITE);
  doc.rect(0, 0, SLIDE_W, 8).fill(NAVY);
  doc.rect(0, SLIDE_H - 28, SLIDE_W, 28).fill(PAPER);
  doc.font("sans").fontSize(9).fillColor(GOLD).text(eyebrow, LEFT, 18, { width: WIDTH, lineBreak: false });
  doc.font("sans").fontSize(8).fillColor(MUTED).text(
    `${monthTitle} · ${period}`,
    LEFT,
    SLIDE_H - 18,
    { width: WIDTH - 80, lineBreak: false }
  );
  doc.font("sans").fontSize(8).fillColor(MUTED).text(
    `${pageNo} / ${totalSlides}`,
    LEFT,
    SLIDE_H - 18,
    { width: WIDTH, align: "right", lineBreak: false }
  );
}

function drawTitleSlide(
  doc: PdfDoc,
  input: {
    monthTitle: string;
    period: string;
    prepared: string;
    document: OpenDigestDocument | null;
    text: string;
  },
  pageNo: number,
  totalSlides: number
) {
  doc.rect(0, 0, SLIDE_W, SLIDE_H).fill(NAVY);
  doc.rect(0, 0, SLIDE_W, 8).fill(GOLD);
  doc.font("sans").fontSize(11).fillColor(GOLD).text("VULNERABILITY THREAT INTELLIGENCE", LEFT, 56, { width: WIDTH });
  doc.font("sans-bold").fontSize(28).fillColor(WHITE).text("Ежемесячный обзор ландшафта уязвимостей", LEFT, 88, {
    width: WIDTH * 0.92,
    lineGap: 4
  });
  doc.font("sans").fontSize(18).fillColor(WHITE).text(input.monthTitle, LEFT, 170, { width: WIDTH });
  const focus = input.document?.focus || "Открытые источники: CISA KEV, NVD, EPSS и бюллетени вендоров.";
  doc.font("sans").fontSize(12).fillColor("#D5DCE6").text(focus, LEFT, 208, { width: WIDTH * 0.88, lineGap: 3 });

  const kpis = input.document?.kpis ?? [];
  if (kpis.length) {
    const gap = 12;
    const boxW = (WIDTH - gap * (kpis.length - 1)) / kpis.length;
    const y = 270;
    kpis.forEach((item, index) => {
      const x = LEFT + index * (boxW + gap);
      doc.roundedRect(x, y, boxW, 72, 6).fill("#162446");
      doc.font("sans-bold").fontSize(20).fillColor(GOLD).text(formatBriefNumber(item.value), x + 14, y + 14, { width: boxW - 28 });
      doc.font("sans").fontSize(9).fillColor("#C9D3E2").text(item.label, x + 14, y + 42, { width: boxW - 28 });
    });
  }

  const lead = input.document?.lead || "";
  if (lead) {
    doc.font("sans").fontSize(11).fillColor("#E8EEF6").text(lead, LEFT, kpis.length ? 360 : 270, {
      width: WIDTH * 0.92,
      lineGap: 3,
      height: 110
    });
  }
  doc.font("sans").fontSize(9).fillColor("#9AA8BA").text(
    `Период: ${input.period}  ·  Подготовлено: ${input.prepared}  ·  ${pageNo}/${totalSlides}`,
    LEFT,
    SLIDE_H - 36,
    { width: WIDTH }
  );
}

function drawContentSlide(
  doc: PdfDoc,
  args: {
    monthTitle: string;
    period: string;
    section: OpenDigestDocument["sections"][number];
    charts: OpenDigestChart[];
    pageNo: number;
    totalSlides: number;
  }
) {
  const { section, charts } = args;
  drawSlideChrome(doc, args.monthTitle, args.period, args.pageNo, args.totalSlides, section.title.toUpperCase());
  const headline = section.headline?.trim() || section.title;
  doc.font("sans-bold").fontSize(20).fillColor(NAVY).text(headline, LEFT, TOP + 14, { width: WIDTH, lineGap: 2 });
  let y = doc.y + 10;

  const hasChart = charts.length > 0;
  const textWidth = hasChart ? WIDTH * 0.52 : WIDTH;

  for (const paragraph of section.paragraphs.slice(0, hasChart ? 1 : 2)) {
    doc.font("sans").fontSize(11).fillColor(INK).text(paragraph, LEFT, y, { width: textWidth, lineGap: 2 });
    y = doc.y + 8;
  }

  if (section.bullets.length) {
    const bullets = section.bullets.slice(0, hasChart ? 5 : 7);
    if (hasChart) {
      for (const bullet of bullets) {
        doc.circle(LEFT + 4, y + 5, 2).fill(GOLD);
        doc.font("sans").fontSize(10).fillColor(INK).text(bullet, LEFT + 14, y, { width: textWidth - 14, lineGap: 1 });
        y = doc.y + 6;
      }
    } else {
      const colGap = 28;
      const colW = (WIDTH - colGap) / 2;
      const mid = Math.ceil(bullets.length / 2);
      const leftBullets = bullets.slice(0, mid);
      const rightBullets = bullets.slice(mid);
      const startY = y;
      let leftY = startY;
      let rightY = startY;
      for (const bullet of leftBullets) {
        doc.circle(LEFT + 4, leftY + 6, 2).fill(GOLD);
        doc.font("sans").fontSize(11).fillColor(INK).text(bullet, LEFT + 14, leftY, { width: colW - 14, lineGap: 2 });
        leftY = doc.y + 8;
      }
      for (const bullet of rightBullets) {
        doc.circle(LEFT + colW + colGap + 4, rightY + 6, 2).fill(GOLD);
        doc.font("sans").fontSize(11).fillColor(INK).text(bullet, LEFT + colW + colGap + 14, rightY, {
          width: colW - 14,
          lineGap: 2
        });
        rightY = doc.y + 8;
      }
      y = Math.max(leftY, rightY) + 6;
    }
  }

  if (hasChart) {
    const chart = charts[0]!;
    drawBarChart(doc, chart, LEFT + textWidth + 24, TOP + 70, WIDTH - textWidth - 24, 280);
  }

  if (section.table?.rows.length) {
    drawSlideTable(doc, section.table, Math.max(y + 8, hasChart ? TOP + 360 : y));
  }
}

function drawBarChart(doc: PdfDoc, chart: OpenDigestChart, x: number, y: number, width: number, height: number) {
  const bars = chart.bars.filter((bar) => Number.isFinite(bar.value) && bar.value >= 0).slice(0, 8);
  if (!bars.length) return;
  doc.roundedRect(x, y, width, height, 8).fill(PAPER);
  doc.font("sans-bold").fontSize(11).fillColor(NAVY).text(chart.title, x + 14, y + 12, { width: width - 28 });
  const max = Math.max(...bars.map((bar) => bar.value), 1);
  const plotX = x + 14;
  const plotY = y + 40;
  const plotW = width - 28;
  const plotH = height - 70;
  const gap = 8;
  const barW = Math.max(12, (plotW - gap * (bars.length - 1)) / bars.length);
  bars.forEach((bar, index) => {
    const bx = plotX + index * (barW + gap);
    const bh = Math.max(4, (bar.value / max) * (plotH - 28));
    const by = plotY + (plotH - 28) - bh;
    doc.roundedRect(bx, by, barW, bh, 3).fill(index === 0 ? NAVY : GOLD);
    doc.font("sans-bold").fontSize(9).fillColor(INK).text(String(bar.value), bx, by - 14, {
      width: barW,
      align: "center",
      lineBreak: false
    });
    doc.font("sans").fontSize(8).fillColor(MUTED).text(bar.label, bx - 2, plotY + plotH - 22, {
      width: barW + 4,
      align: "center"
    });
  });
}

function drawSlideTable(doc: PdfDoc, table: { columns: string[]; rows: string[][] }, startY: number) {
  const maxRows = Math.min(table.rows.length, 6);
  const weights =
    table.columns.length === 4
      ? [150, 180, 160, WIDTH - 490]
      : table.columns.map(() => WIDTH / Math.max(table.columns.length, 1));
  let y = startY;
  doc.rect(LEFT, y, WIDTH, 26).fill(NAVY);
  let x = LEFT;
  table.columns.forEach((column, index) => {
    doc.font("sans-bold").fontSize(10).fillColor(WHITE).text(column, x + 8, y + 7, {
      width: weights[index]! - 16,
      lineBreak: false
    });
    x += weights[index]!;
  });
  y += 26;
  for (let rowIndex = 0; rowIndex < maxRows; rowIndex += 1) {
    const row = table.rows[rowIndex]!;
    const height =
      Math.max(
        22,
        ...row.map((cell, index) => doc.font("sans").fontSize(10).heightOfString(cell, { width: weights[index]! - 16 }) + 10)
      );
    if (y + height > SLIDE_H - BOTTOM - 8) break;
    if (rowIndex % 2 === 0) doc.rect(LEFT, y, WIDTH, height).fill(PAPER);
    x = LEFT;
    row.forEach((cell, index) => {
      doc.font(index === 0 ? "sans-bold" : "sans").fontSize(10).fillColor(INK).text(cell, x + 8, y + 5, {
        width: weights[index]! - 16
      });
      x += weights[index]!;
    });
    y += height;
  }
}

function drawClosingSlide(
  doc: PdfDoc,
  args: { monthTitle: string; period: string; closing: string; pageNo: number; totalSlides: number }
) {
  drawSlideChrome(doc, args.monthTitle, args.period, args.pageNo, args.totalSlides, "ВЫВОДЫ ДЛЯ РУКОВОДСТВА");
  doc.font("sans-bold").fontSize(22).fillColor(NAVY).text("Что зафиксировать по итогам месяца", LEFT, TOP + 18, { width: WIDTH });
  doc.roundedRect(LEFT, TOP + 70, WIDTH, 280, 8).fill(PAPER);
  doc.rect(LEFT, TOP + 70, 6, 280).fill(GOLD);
  doc.font("sans").fontSize(14).fillColor(INK).text(args.closing, LEFT + 28, TOP + 92, {
    width: WIDTH - 48,
    lineGap: 5
  });
}

function drawFallbackTextSlide(
  doc: PdfDoc,
  monthTitle: string,
  period: string,
  text: string,
  pageNo: number,
  totalSlides: number
) {
  drawSlideChrome(doc, monthTitle, period, pageNo, totalSlides, "ОБЗОР");
  doc.font("sans-bold").fontSize(20).fillColor(NAVY).text("Сводка месяца", LEFT, TOP + 18, { width: WIDTH });
  doc.font("sans").fontSize(12).fillColor(INK).text(text.slice(0, 2_400), LEFT, TOP + 56, {
    width: WIDTH,
    lineGap: 3,
    height: SLIDE_H - TOP - BOTTOM - 80
  });
}

function drawSourcesSlide(
  doc: PdfDoc,
  args: {
    monthTitle: string;
    period: string;
    sources: string[];
    accountEmail: string;
    pageNo: number;
    totalSlides: number;
  }
) {
  drawSlideChrome(doc, args.monthTitle, args.period, args.pageNo, args.totalSlides, "ИСТОЧНИКИ И ОГРАНИЧЕНИЯ");
  doc.font("sans-bold").fontSize(22).fillColor(NAVY).text("Основные источники", LEFT, TOP + 18, { width: WIDTH });
  const lines = args.sources.length
    ? args.sources
    : ["CISA KEV", "NVD", "FIRST EPSS", "Бюллетени вендоров"];
  let y = TOP + 64;
  for (const line of lines) {
    doc.circle(LEFT + 4, y + 6, 2).fill(GOLD);
    doc.font("sans").fontSize(13).fillColor(INK).text(line, LEFT + 16, y, { width: WIDTH - 16 });
    y = doc.y + 10;
  }
  doc.font("sans").fontSize(11).fillColor(MUTED).text(
    "Цифры каталога VulnControl в презентацию не входили. Количественные выводы опираются только на открытые выгрузки, доступные на момент сборки.",
    LEFT,
    Math.max(y + 24, SLIDE_H - 110),
    { width: WIDTH, lineGap: 3 }
  );
  doc.font("sans").fontSize(9).fillColor(MUTED).text(`Выпустил: ${args.accountEmail}`, LEFT, SLIDE_H - 52, { width: WIDTH });
}

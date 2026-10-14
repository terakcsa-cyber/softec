import { createRequire } from "node:module";
import path from "node:path";
import { BadRequestException, Injectable } from "@nestjs/common";
import PDFDocument from "pdfkit";
import {
  DIGEST_NARRATIVE_FAILED,
  DIGEST_NARRATIVE_SKIPPED,
  runDigestNarrative,
  type DigestCveNote,
  type DigestNarrativeFacts,
  type DigestNarrativeOutcome,
  type DigestNarrativeSection
} from "@vuln-intel/shared";
import { IntegrationSettingsService } from "./integration-settings.service.js";
import { MonthlyDigestService } from "./monthly-digest.service.js";

type PdfDoc = PDFKit.PDFDocument;

const require = createRequire(import.meta.url);
const FONT_DIR = path.join(path.dirname(require.resolve("dejavu-fonts-ttf/package.json")), "ttf");

const SECTION_IDS = new Set(["summary", "trend", "exploit", "vendors", "cves", "tasks"]);
const STATUSES = new Set(["empty", "error", "ready", "loading"]);

const ROW_CAP: Record<string, number> = {
  summary: 20,
  trend: 40,
  exploit: 40,
  vendors: 40,
  cves: 50,
  tasks: 200
};

type ParsedDigest = {
  filename: string;
  accountEmail: string;
  facts: DigestNarrativeFacts;
};

@Injectable()
export class PeriodDigestPdfService {
  constructor(
    private readonly integration: IntegrationSettingsService,
    private readonly monthly: MonthlyDigestService
  ) {}

  async build(body: unknown, accountEmail: string): Promise<{ buffer: Buffer; filename: string }> {
    const parsed = parsePeriodDigestBody(body, accountEmail);
    const llm = await this.integration.getDigestLlmConfig();
    let story: DigestNarrativeOutcome = {
      status: "failed",
      text: DIGEST_NARRATIVE_FAILED,
      lead: DIGEST_NARRATIVE_FAILED,
      summary: "",
      cases: "",
      close: ""
    };
    try {
      story = await runDigestNarrative({
        facts: parsed.facts,
        llm
      });
    } catch {
      story = { ...story, lead: DIGEST_NARRATIVE_FAILED, text: DIGEST_NARRATIVE_FAILED };
    }
    const buffer = await renderPdf(parsed, story);
    return { buffer, filename: parsed.filename };
  }

  async previewMonth(year: number, month: number, accountEmail = "") {
    return this.monthly.preview(year, month, accountEmail);
  }

  async buildMonthPdf(body: unknown, accountEmail: string): Promise<{ buffer: Buffer; filename: string }> {
    return this.monthly.pdf(body, accountEmail);
  }
}

function parsePeriodDigestBody(body: unknown, accountEmail: string): ParsedDigest {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new BadRequestException("Нужен объект дайджеста");
  }
  const raw = body as Record<string, unknown>;
  const title = clip(raw.title, 180);
  if (!title) throw new BadRequestException("Нужно название отчёта");
  const windowLabel = clip(raw.windowLabel, 80) || "Период не указан";
  const issuedIso = typeof raw.issuedAt === "string" && !Number.isNaN(new Date(raw.issuedAt).getTime())
    ? new Date(raw.issuedAt).toISOString()
    : new Date().toISOString();
  const issuedLabel = clip(raw.issuedLabel, 80) || formatMsk(issuedIso);
  const coverage = clip(raw.coverage, 800);
  const sections = parseSections(raw.sections);
  const cveNotes = parseNotes(raw.cveNotes);
  const facts: DigestNarrativeFacts = {
    title,
    windowLabel,
    issuedAt: issuedLabel,
    coverage,
    sections,
    cveNotes
  };
  return {
    filename: `vulncontrol-digest-${fileDay(issuedIso)}.pdf`,
    accountEmail: clip(accountEmail, 120) || "текущая сессия",
    facts
  };
}

function parseSections(value: unknown): DigestNarrativeSection[] {
  if (!Array.isArray(value)) return [];
  const sections: DigestNarrativeSection[] = [];
  for (const item of value) {
    if (sections.length >= 6) break;
    if (!item || typeof item !== "object" || Array.isArray(item)) continue;
    const row = item as Record<string, unknown>;
    const id = clip(row.id, 32);
    if (!SECTION_IDS.has(id)) continue;
    const status = typeof row.status === "string" && STATUSES.has(row.status) ? row.status : "empty";
    sections.push({
      title: clip(row.title, 120) || id,
      status: status as DigestNarrativeSection["status"],
      note: clip(row.note, 700),
      metrics: parseMetrics(row.metrics),
      bars: parseBars(row.bars),
      tables: parseTables(row.tables, ROW_CAP[id] ?? 40)
    });
  }
  return sections;
}

function parseMetrics(value: unknown): DigestNarrativeSection["metrics"] {
  if (!Array.isArray(value)) return [];
  const metrics: DigestNarrativeSection["metrics"] = [];
  for (const item of value) {
    if (metrics.length >= 16) break;
    if (!item || typeof item !== "object" || Array.isArray(item)) continue;
    const row = item as Record<string, unknown>;
    const label = clip(row.label, 80);
    const metricValue = clip(row.value, 40);
    if (!label) continue;
    metrics.push({ label, value: metricValue || "—" });
  }
  return metrics;
}

function parseBars(value: unknown): DigestNarrativeSection["bars"] {
  if (!Array.isArray(value)) return [];
  const bars: DigestNarrativeSection["bars"] = [];
  for (const item of value) {
    if (bars.length >= 40) break;
    if (!item || typeof item !== "object" || Array.isArray(item)) continue;
    const row = item as Record<string, unknown>;
    const label = clip(row.label, 40);
    const display = clip(row.display, 40);
    if (!label) continue;
    bars.push({ label, display: display || "—" });
  }
  return bars;
}

function parseTables(value: unknown, rowCap: number): DigestNarrativeSection["tables"] {
  if (!Array.isArray(value)) return [];
  const tables: DigestNarrativeSection["tables"] = [];
  for (const item of value) {
    if (tables.length >= 3) break;
    if (!item || typeof item !== "object" || Array.isArray(item)) continue;
    const row = item as Record<string, unknown>;
    const columns = Array.isArray(row.columns)
      ? row.columns.map((cell) => clip(cell, 40)).filter(Boolean).slice(0, 8)
      : [];
    const rows: string[][] = [];
    if (Array.isArray(row.rows)) {
      for (const rawRow of row.rows) {
        if (rows.length >= rowCap) break;
        if (!Array.isArray(rawRow)) continue;
        rows.push(rawRow.slice(0, columns.length || 8).map((cell) => clip(cell, 180) || "—"));
      }
    }
    if (!columns.length && !rows.length) continue;
    tables.push({ columns, rows });
  }
  return tables;
}

function parseNotes(value: unknown): DigestNarrativeFacts["cveNotes"] {
  if (!Array.isArray(value)) return [];
  const notes: DigestNarrativeFacts["cveNotes"] = [];
  for (const item of value) {
    if (notes.length >= 12) break;
    if (!item || typeof item !== "object" || Array.isArray(item)) continue;
    const row = item as Record<string, unknown>;
    const cveId = clip(row.cveId, 24).toUpperCase();
    if (!/^CVE-\d{4}-\d{4,7}$/.test(cveId)) continue;
    const description = clip(row.description, 420);
    notes.push({
      cveId,
      description,
      vendor: clip(row.vendor, 80),
      product: clip(row.product, 80),
      cvss: clip(row.cvss, 24),
      epss: clip(row.epss, 24),
      kev: clip(row.kev, 16)
    });
  }
  return notes;
}

function clip(value: unknown, max: number): string {
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

function fileDay(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "report";
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Europe/Moscow",
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).format(date);
}

const MONTHS_RU = [
  "январь",
  "февраль",
  "март",
  "апрель",
  "май",
  "июнь",
  "июль",
  "август",
  "сентябрь",
  "октябрь",
  "ноябрь",
  "декабрь"
];

function monthBounds(year: number, month: number) {
  if (!Number.isInteger(year) || year < 1999 || year > 2100 || !Number.isInteger(month) || month < 1 || month > 12) {
    throw new BadRequestException("Нужен календарный месяц");
  }
  const mm = String(month).padStart(2, "0");
  const last = new Date(Date.UTC(year, month, 0)).getUTCDate();
  const dd = String(last).padStart(2, "0");
  return {
    year,
    month,
    label: `${MONTHS_RU[month - 1]} ${year}`,
    startIso: `${year}-${mm}-01T00:00:00.000`,
    endIso: `${year}-${mm}-${dd}T23:59:59.999`,
    startDay: `${year}-${mm}-01`,
    endDay: `${year}-${mm}-${dd}`
  };
}

async function loadOpenMonthSources(bounds: ReturnType<typeof monthBounds>): Promise<{ text: string; titles: string[] }> {
  const lines: string[] = [];
  const titles: string[] = [];
  const kev = await loadCisaMonth(bounds.startDay, bounds.endDay);
  titles.push(kev.title);
  lines.push(kev.text);
  const nvd = await loadNvdMonth(bounds.startIso, bounds.endIso);
  titles.push(nvd.title);
  lines.push(nvd.text);
  return { text: lines.join("\n\n"), titles };
}

async function loadCisaMonth(startDay: string, endDay: string): Promise<{ title: string; text: string }> {
  try {
    const res = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", {
      signal: AbortSignal.timeout(25_000),
      headers: { accept: "application/json", "user-agent": "vuln-intel-digest" }
    });
    if (!res.ok) return { title: "CISA KEV", text: `CISA KEV не открылся (${res.status}).` };
    const data = (await res.json()) as { vulnerabilities?: Array<Record<string, unknown>> };
    const rows = (data.vulnerabilities ?? []).filter((row) => {
      const day = typeof row.dateAdded === "string" ? row.dateAdded.slice(0, 10) : "";
      return day >= startDay && day <= endDay;
    });
    const lines = rows.slice(0, 40).map((row) => {
      return [row.cveID, row.dateAdded, row.vendorProject, row.product, row.vulnerabilityName, row.shortDescription]
        .map((part) => (typeof part === "string" ? part.replace(/\s+/g, " ").trim() : ""))
        .filter(Boolean)
        .join(" | ")
        .slice(0, 500);
    });
    const head = `Источник: каталог CISA KEV, поле dateAdded с ${startDay} по ${endDay}. Записей: ${rows.length}.`;
    return { title: "CISA KEV", text: [head, ...lines].join("\n") || head };
  } catch {
    return { title: "CISA KEV", text: "CISA KEV не открылся." };
  }
}

async function loadNvdMonth(startIso: string, endIso: string): Promise<{ title: string; text: string }> {
  try {
    const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
    url.searchParams.set("pubStartDate", startIso);
    url.searchParams.set("pubEndDate", endIso);
    url.searchParams.set("resultsPerPage", "12");
    const res = await fetch(url, {
      signal: AbortSignal.timeout(25_000),
      headers: { accept: "application/json", "user-agent": "vuln-intel-digest" }
    });
    if (!res.ok) return { title: "NVD", text: `NVD не открылся (${res.status}).` };
    const data = (await res.json()) as {
      totalResults?: number;
      vulnerabilities?: Array<{ cve?: { id?: string; descriptions?: Array<{ lang?: string; value?: string }>; published?: string } }>;
    };
    const lines = (data.vulnerabilities ?? []).slice(0, 12).map((item) => {
      const cve = item.cve;
      const description = cve?.descriptions?.find((row) => row.lang === "en")?.value ?? cve?.descriptions?.[0]?.value ?? "";
      return [cve?.id, cve?.published, description.replace(/\s+/g, " ").trim().slice(0, 360)].filter(Boolean).join(" | ");
    });
    const head = `Источник: NVD 2.0, публикации с ${startIso.slice(0, 10)} по ${endIso.slice(0, 10)}. Всего в ответе API: ${data.totalResults ?? lines.length}. В промпт вошли первые ${lines.length}.`;
    return { title: "NVD", text: [head, ...lines].join("\n") };
  } catch {
    return { title: "NVD", text: "NVD не открылся." };
  }
}

function parseMonthPdfBody(body: unknown): { year: number; month: number; monthLabel: string; text: string; sources: string[] } {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new BadRequestException("Нужен объект дайджеста");
  const raw = body as Record<string, unknown>;
  const year = Number(raw.year);
  const month = Number(raw.month);
  const bounds = monthBounds(year, month);
  const text = clip(raw.text, 12_000);
  if (!text) throw new BadRequestException("Нет текста предпросмотра");
  const sources = Array.isArray(raw.sources) ? raw.sources.map((item) => clip(item, 80)).filter(Boolean).slice(0, 8) : [];
  return { year, month, monthLabel: bounds.label, text, sources };
}

function renderOpenWebPdf(input: {
  title: string;
  monthLabel: string;
  text: string;
  sources: string[];
  accountEmail: string;
  issuedLabel: string;
}): Promise<Buffer> {
  const doc = new PDFDocument({
    size: "A4",
    margins: { top: 58, bottom: 52, left: 48, right: 48 },
    bufferPages: true,
    info: { Title: input.title, Author: "VulnControl" }
  });
  const chunks: Buffer[] = [];
  doc.on("data", (chunk: Buffer) => chunks.push(chunk));
  const done = new Promise<Buffer>((resolve, reject) => {
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);
  });
  doc.registerFont("sans", path.join(FONT_DIR, "DejaVuSans.ttf"));
  doc.registerFont("sans-bold", path.join(FONT_DIR, "DejaVuSans-Bold.ttf"));
  doc.font("sans-bold").fontSize(18).fillColor("#0f172a").text(input.title, { width: 500 });
  doc.moveDown(0.4);
  doc.font("sans").fontSize(10).fillColor("#334155").text(`${input.monthLabel}. Выпущен ${input.issuedLabel}. ${input.accountEmail}`);
  doc.moveDown(0.3);
  doc.font("sans").fontSize(9).fillColor("#475569").text(
    "Текст написал DeepSeek по открытым источникам за месяц. Сводка каталога VulnControl в отчёт не подставлялась.",
    { width: 500 }
  );
  if (input.sources.length) {
    doc.moveDown(0.3);
    doc.text(`Источники: ${input.sources.join(", ")}.`, { width: 500 });
  }
  doc.moveDown(0.8);
  for (const paragraph of input.text.split(/\n{2,}/)) {
    const block = paragraph.trim();
    if (!block) continue;
    const heading = !block.includes(".") && block.length < 80;
    doc.font(heading ? "sans-bold" : "sans").fontSize(heading ? 12 : 10).fillColor("#0f172a").text(block, { width: 500, lineGap: 2 });
    doc.moveDown(0.6);
  }
  doc.end();
  return done;
}

const GLOSS: Record<string, string> = {
  "Всего CVE": "Размер каталога на момент выпуска. Выбранное окно это число не режет.",
  "CVSS ≥ 9": "Сколько записей каталога имеют базовый CVSS не ниже 9.",
  "CVSS 7–8.9": "Сколько записей каталога попадают в этот диапазон CVSS.",
  "CVSS 4–6.9": "Сколько записей каталога попадают в этот диапазон CVSS.",
  "CVSS < 4": "Сколько записей каталога имеют базовый CVSS ниже 4.",
  "Без CVSS": "Записи каталога без базовой оценки CVSS.",
  "CISA KEV": "Записи каталога, которые есть в CISA KEV. Это не доля и не список задач.",
  "EPSS ≥ 0.7": "Записи с оценкой EPSS не ниже 0.7. EPSS — вероятность эксплуатации, не подтверждение атаки.",
  "Публикации за 24 часа": "Сколько CVE опубликовано за последние 24 часа. Это не дельта к прошлому окну.",
  "Публикации": "Сумма публикаций по показанным дням ряда. Сравнения с прошлым окном нет.",
  "Новые CISA KEV": "Новые отметки CISA KEV по показанным дням ряда, не весь каталог KEV.",
  "Публичный эксплойт": "Записи intel с публичным эксплойтом. Счётчик пересекается с PoC и KEV.",
  "Есть PoC": "Записи intel с PoC. Это не доля от каталога и не исключает другие сигналы.",
  "Скачок EPSS": "Записи intel, у которых отмечен скачок EPSS.",
  "VulnCheck KEV, не CISA": "Записи VulnCheck KEV, которых нет в CISA KEV.",
  "Новые VulnCheck KEV, 7 дней": "Новые записи VulnCheck KEV за 7 дней.",
  "Строк intel": "Сколько строк в снимке exploit intel.",
  "CVE в окне": "Сколько CVE попало в окно публикаций, которое вернул API вендоров."
};

const TILE_LABELS = ["Всего CVE", "CISA KEV", "EPSS ≥ 0.7", "Публикации за 24 часа"];

function renderPdf(parsed: ParsedDigest, story: DigestNarrativeOutcome): Promise<Buffer> {
  const doc = new PDFDocument({
    size: "A4",
    margins: { top: 58, bottom: 52, left: 48, right: 48 },
    bufferPages: true,
    info: { Title: parsed.facts.title, Author: "VulnControl" }
  });
  const chunks: Buffer[] = [];
  doc.on("data", (chunk: Buffer) => chunks.push(chunk));
  const done = new Promise<Buffer>((resolve, reject) => {
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);
  });

  doc.registerFont("sans", path.join(FONT_DIR, "DejaVuSans.ttf"));
  doc.registerFont("sans-bold", path.join(FONT_DIR, "DejaVuSans-Bold.ttf"));
  doc.on("pageAdded", () => {
    drawRunningHeader(doc, parsed.facts.title);
  });

  drawCover(doc, parsed, story);
  chapter(doc, "1", "Краткий вывод");
  prose(doc, story.status === "generated" ? story.summary || story.lead : story.lead || DIGEST_NARRATIVE_SKIPPED);
  prose(
    doc,
    "Ниже — цифры сводки и короткое пояснение, что именно считает каждая. Новых процентов и сравнения с прошлым периодом здесь нет: конструктор их не отдаёт."
  );
  drawFacts(doc, sectionById(parsed.facts, "summary"), true);

  chapter(doc, "2", "Метрики окна и ряд публикаций");
  prose(
    doc,
    "Ряд — публикации по дням аналитики внутри выбранного окна. Если API короче окна, в выпуске только показанные дни. Рост или падение к прошлому периоду не вычисляется."
  );
  drawFacts(doc, sectionById(parsed.facts, "trend"), true);

  chapter(doc, "3", "Заметные записи выборки");
  prose(
    doc,
    "Таблица — первые строки выборки по риску, не весь каталог и не отдельный рейтинг месяца. Пустая выборка остаётся пустой."
  );
  drawCveTable(doc, parsed.facts.cveNotes.slice(0, 10));
  if (story.status === "generated" && story.cases) prose(doc, story.cases);
  else prose(doc, story.lead || DIGEST_NARRATIVE_SKIPPED);

  chapter(doc, "4", "Публикации по вендорам и продуктам");
  prose(
    doc,
    "Это число публикаций в окне ответа API, не длиннее 30 дней. Список показывает, где в этом окне больше записей. Он не говорит, какая доля каталога «эксплуатируется»."
  );
  drawFacts(doc, sectionById(parsed.facts, "vendors"), false);

  chapter(doc, "5", "Ключевые записи");
  prose(
    doc,
    story.status === "generated"
      ? "У каждой записи сначала факты выборки, затем короткое описание из каталога. Связный текст выше собран только из этих фактов."
      : `${story.lead || DIGEST_NARRATIVE_SKIPPED} Рядом с записью остаётся короткое описание из каталога, без добавленного вывода.`
  );
  drawCases(doc, parsed.facts.cveNotes.slice(0, 8));

  chapter(doc, "6", "Почему рядом с CVSS стоят KEV и EPSS");
  prose(
    doc,
    "CVSS в сводке — распределение оценок по каталогу. CISA KEV — отдельный признак известной эксплуатации, он не выводится из CVSS. EPSS — оценка вероятности эксплуатации в ближайший период, а не подтверждение, что атака уже идёт. Публичный эксплойт и PoC в intel пересекаются: их нельзя складывать в одну долю."
  );
  drawFacts(doc, sectionById(parsed.facts, "exploit"), true);

  chapter(doc, "7", "Как читать этот выпуск");
  for (const line of READING) prose(doc, line);
  const tasks = sectionById(parsed.facts, "tasks");
  if (tasks) {
    prose(doc, "Задачи в выпуске — список рабочего стола. Статусы здесь только для чтения и этим файлом не меняются.");
    drawFacts(doc, tasks, false);
  } else {
    prose(doc, "Раздел задач в этот выпуск не включён.");
  }

  chapter(doc, "8", "Методология и источники");
  prose(
    doc,
    "Цифры взяты из тех же ответов, что конструктор отчёта: сводка каталога, ряд аналитики, exploit intel, окно вендоров и продуктов, страница выборки CVE и список задач. Пустой ответ остаётся пустым."
  );
  if (parsed.facts.coverage) prose(doc, parsed.facts.coverage);
  prose(
    doc,
    story.status === "generated"
      ? "Рассказ собран одним запросом к модели дайджеста только из этих цифр и коротких описаний. Предложение с числом или CVE вне этого набора отбрасывается."
      : story.lead || DIGEST_NARRATIVE_SKIPPED
  );
  if (story.status === "generated" && story.close) prose(doc, story.close);
  prose(doc, `Учётная запись: ${parsed.accountEmail}`);

  stampPages(doc);
  doc.end();
  return done;
}

const READING = [
  "1. Сводка каталога — снимок всего каталога. Окно дайджеста её не режет.",
  "2. Ряд публикаций — только показанные дни. Сравнения с прошлым окном в данных нет.",
  "3. KEV, EPSS, эксплойт и PoC пересекаются. Это не части одного целого и не проценты.",
  "4. Выборка CVE — страница API по риску, не весь каталог.",
  "5. Описание под записью — текст каталога. Если ключ дайджеста не задан, связного рассказа нет.",
  "6. Пустой раздел остаётся пустым. Недостающие числа не достраиваются."
];

function drawCover(doc: PdfDoc, parsed: ParsedDigest, story: DigestNarrativeOutcome) {
  const facts = parsed.facts;
  doc.rect(0, 0, doc.page.width, 8).fill("#1d4ed8");
  doc.fillColor("#64748b").font("sans").fontSize(9).text("VULNCONTROL", 48, 36);
  doc.fillColor("#0f172a").font("sans-bold").fontSize(22).text("Дайджест уязвимостей", 48, 54, { width: doc.page.width - 96 });
  doc.moveDown(0.2);
  doc.font("sans").fontSize(12).fillColor("#1e293b").text(facts.title);
  doc.moveDown(0.35);
  doc.font("sans").fontSize(10).fillColor("#334155").text(
    "Фокус: записи каталога, CISA KEV, сигналы EPSS, публичные эксплойты и PoC, ряд публикаций и выборка по риску."
  );
  doc.moveDown(0.7);
  drawTiles(doc, tilesFrom(facts));
  doc.moveDown(0.3);
  prose(doc, story.lead || DIGEST_NARRATIVE_SKIPPED);
  prose(
    doc,
    "Дайджест устроен как обзор: сначала вывод, затем цифра и сразу пояснение, что она считает. Это снимок каталога, а не проверка конкретного контура."
  );
  doc.moveDown(0.2);
  doc.font("sans").fontSize(10).fillColor("#334155");
  doc.text(`Период: ${facts.windowLabel}`);
  doc.text(`Подготовлено: ${facts.issuedAt}`);
  doc.text(`Учётная запись: ${parsed.accountEmail}`);
}

function tilesFrom(facts: DigestNarrativeFacts): Array<{ value: string; label: string }> {
  const summary = sectionById(facts, "summary");
  const byLabel = new Map((summary?.metrics ?? []).map((metric) => [metric.label, metric.value]));
  return TILE_LABELS.filter((label) => byLabel.has(label)).map((label) => ({
    label,
    value: byLabel.get(label) || "—"
  }));
}

function drawTiles(doc: PdfDoc, tiles: Array<{ value: string; label: string }>) {
  if (!tiles.length) return;
  const y = doc.y;
  const gap = 8;
  const width = (doc.page.width - 96 - gap * (tiles.length - 1)) / tiles.length;
  tiles.forEach((tile, index) => {
    const x = 48 + index * (width + gap);
    doc.roundedRect(x, y, width, 70, 6).fill("#f8fafc");
    doc.fillColor("#0f172a").font("sans-bold").fontSize(14).text(tile.value, x + 8, y + 12, {
      width: width - 16,
      lineBreak: false
    });
    doc.fillColor("#64748b").font("sans").fontSize(8).text(tile.label, x + 8, y + 38, { width: width - 16 });
  });
  doc.x = 48;
  doc.y = y + 82;
}

function drawFacts(doc: PdfDoc, section: DigestNarrativeSection | undefined, withGloss: boolean) {
  if (!section) {
    prose(doc, "Раздел не включён в этот выпуск.");
    return;
  }
  if (section.note) doc.font("sans").fontSize(9).fillColor("#64748b").text(section.note);
  if (section.status === "empty") return prose(doc, "Нет строк.");
  if (section.status === "error") return prose(doc, "Раздел не загрузился. В выпуске не будет выдуманных чисел.");
  if (section.status === "loading") return prose(doc, "Раздел ещё загружается.");
  for (const metric of section.metrics) {
    ensureRoom(doc, 36);
    doc.moveDown(0.25);
    doc.font("sans-bold").fontSize(12).fillColor("#0f172a").text(metric.value, { continued: true });
    doc.font("sans").fontSize(10).fillColor("#334155").text(`   ${metric.label}`);
    const gloss = GLOSS[metric.label];
    if (withGloss && gloss) {
      doc.font("sans").fontSize(9).fillColor("#475569").text(gloss);
    }
  }
  if (section.bars.length) {
    doc.moveDown(0.35);
    doc.font("sans").fontSize(9).fillColor("#64748b").text("Публикации по дням");
    for (const bar of section.bars) {
      ensureRoom(doc, 16);
      doc.font("sans").fontSize(9).fillColor("#1e293b").text(`${bar.label}    ${bar.display}`);
    }
  }
  for (const table of section.tables) drawTable(doc, table, 12);
}

function drawCveTable(doc: PdfDoc, notes: DigestCveNote[]) {
  if (!notes.length) return prose(doc, "В этот выпуск не вошла выборка CVE с идентификаторами.");
  drawTable(doc, {
    columns: ["CVE", "Продукт", "CVSS", "EPSS", "KEV"],
    rows: notes.map((note) => [
      note.cveId,
      note.product || note.vendor || "—",
      note.cvss || "—",
      note.epss || "—",
      note.kev || "—"
    ])
  }, 10);
}

function drawCases(doc: PdfDoc, notes: DigestCveNote[]) {
  if (!notes.length) return prose(doc, "Ключевых записей в этом выпуске нет.");
  for (const note of notes) {
    ensureRoom(doc, 78);
    const who = [note.product, note.vendor].filter(Boolean).join(" · ");
    doc.moveDown(0.35);
    doc.font("sans-bold").fontSize(11).fillColor("#0f172a").text(who ? `${note.cveId} — ${who}` : note.cveId);
    const bits = [
      note.cvss ? `CVSS ${note.cvss}` : "",
      note.epss ? `EPSS ${note.epss}` : "",
      note.kev ? "CISA KEV" : ""
    ].filter(Boolean);
    if (bits.length) doc.font("sans").fontSize(9).fillColor("#64748b").text(bits.join("   ·   "));
    doc.font("sans").fontSize(10).fillColor("#1e293b").text(note.description || "Короткого описания в каталоге нет.");
  }
}

function drawTable(doc: PdfDoc, table: DigestNarrativeSection["tables"][number], rowCap: number) {
  const rows = table.rows.slice(0, rowCap);
  if (table.columns.length) {
    doc.moveDown(0.3);
    doc.font("sans-bold").fontSize(8).fillColor("#64748b").text(table.columns.join("   ·   "));
  }
  if (!rows.length) return prose(doc, "Нет строк.");
  for (const row of rows) {
    ensureRoom(doc, 22);
    doc.font("sans").fontSize(8).fillColor("#0f172a").text(row.join("   ·   "));
  }
  if (table.rows.length > rows.length) {
    prose(doc, "В разделе есть ещё строки. Полное число уже указано в пояснении раздела, здесь они не дописываются.");
  }
}

function sectionById(facts: DigestNarrativeFacts, id: string) {
  return facts.sections.find((section) => section.title && sectionMatches(section, id));
}

function sectionMatches(section: DigestNarrativeSection, id: string) {
  const title = section.title.toLowerCase();
  if (id === "summary") return title.includes("сводк");
  if (id === "trend") return title.includes("тренд");
  if (id === "exploit") return title.includes("exploit") || title.includes("эксплойт");
  if (id === "vendors") return title.includes("вендор");
  if (id === "tasks") return title.includes("задач");
  return false;
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
  doc.font("sans").fontSize(8).fillColor("#64748b").text(title, 48, 28, {
    width: doc.page.width - 140,
    lineBreak: false
  });
  doc.x = previousX;
  doc.y = Math.max(previousY, 58);
}

function stampPages(doc: PdfDoc) {
  const range = doc.bufferedPageRange();
  for (let i = 0; i < range.count; i++) {
    doc.switchToPage(range.start + i);
    const margins = doc.page.margins;
    const savedBottom = margins.bottom;
    const savedX = doc.x;
    const savedY = doc.y;
    margins.bottom = 0;
    doc.font("sans").fontSize(8).fillColor("#64748b").text(`Стр. ${i + 1}`, 48, doc.page.height - 36, {
      width: doc.page.width - 96,
      align: "right",
      lineBreak: false
    });
    margins.bottom = savedBottom;
    doc.x = savedX;
    doc.y = savedY;
  }
}

function ensureRoom(doc: PdfDoc, height: number) {
  const bottom = doc.page.height - doc.page.margins.bottom;
  if (doc.y + height > bottom) doc.addPage();
}

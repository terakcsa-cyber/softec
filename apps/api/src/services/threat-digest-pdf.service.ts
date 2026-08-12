import { createRequire } from "node:module";
import path from "node:path";
import { Injectable } from "@nestjs/common";
import PDFDocument from "pdfkit";
import type { ThreatDigestPayload } from "@vuln-intel/shared";
import { buildThreatDigestFallbackSummaryRu, THREAT_SIGNAL_LABEL } from "@vuln-intel/shared";

type PdfDoc = PDFKit.PDFDocument;

const require = createRequire(import.meta.url);
const FONT_DIR = path.join(path.dirname(require.resolve("dejavu-fonts-ttf/package.json")), "ttf");

const FONTS = {
  regular: path.join(FONT_DIR, "DejaVuSans.ttf"),
  bold: path.join(FONT_DIR, "DejaVuSans-Bold.ttf"),
  oblique: path.join(FONT_DIR, "DejaVuSans-Oblique.ttf")
} as const;

const COLORS = {
  bg: "#0f172a",
  card: "#1e293b",
  cardLight: "#f1f5f9",
  accent: "#f59e0b",
  danger: "#ef4444",
  warn: "#f97316",
  ok: "#22c55e",
  info: "#3b82f6",
  purple: "#8b5cf6",
  text: "#f8fafc",
  ink: "#0f172a",
  muted: "#64748b",
  line: "#334155",
  white: "#ffffff"
};

const VENDOR_PALETTE = [
  "#f59e0b",
  "#ef4444",
  "#8b5cf6",
  "#06b6d4",
  "#22c55e",
  "#ec4899",
  "#3b82f6",
  "#f97316",
  "#14b8a6",
  "#a855f7"
];

const SIGNAL_LABEL_RU: Record<string, string> = {
  vulncheck_kev: "VulnCheck KEV",
  metasploit: "Metasploit",
  exploit_db: "Exploit-DB",
  nvd_exploit_tag: "NVD exploit",
  poc_github: "GitHub PoC",
  poc_public: "Публичный PoC",
  poc_gitlab: "GitLab PoC",
  nuclei: "Nuclei",
  github_advisory: "GitHub Advisory",
  in_the_wild: "In-the-wild"
};

type ChartSlice = { label: string; value: number; color: string };

function polar(cx: number, cy: number, r: number, angle: number) {
  return { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) };
}

function formatMsk(iso: string, opts: Intl.DateTimeFormatOptions): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat("ru-RU", { ...opts, timeZone: "Europe/Moscow" }).format(d);
}

function mskFilenameDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "report";
  return new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Moscow" }).format(d);
}

function formatWindowRange(generatedAt: string, windowHours: number): string {
  const end = new Date(generatedAt);
  if (Number.isNaN(end.getTime())) return `${windowHours} ч`;
  const start = new Date(end.getTime() - windowHours * 3_600_000);
  const fmt = (d: Date) =>
    new Intl.DateTimeFormat("ru-RU", {
      day: "numeric",
      month: "short",
      hour: "2-digit",
      minute: "2-digit",
      timeZone: "Europe/Moscow",
      hour12: false
    }).format(d);
  return `${fmt(start)} — ${fmt(end)} МСК`;
}

function pluralHours(n: number): string {
  const mod10 = n % 10;
  const mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) return `${n} час`;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return `${n} часа`;
  return `${n} часов`;
}

function signalLabelRu(type: string): string {
  return SIGNAL_LABEL_RU[type] ?? THREAT_SIGNAL_LABEL[type] ?? type;
}

type PageCtx = { num: number; dateLabel: string };

@Injectable()
export class ThreatDigestPdfService {
  async build(payload: ThreatDigestPayload): Promise<{ buffer: Buffer; filename: string }> {
    const doc = new PDFDocument({ size: "A4", margin: 48 });
    const chunks: Buffer[] = [];
    doc.on("data", (c: Buffer) => chunks.push(c));

    const done = new Promise<Buffer>((resolve, reject) => {
      doc.on("end", () => resolve(Buffer.concat(chunks)));
      doc.on("error", reject);
    });

    this.registerFonts(doc);

    const dateLabel = formatMsk(payload.generatedAt, {
      day: "numeric",
      month: "long",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false
    });
    const windowRange = formatWindowRange(payload.generatedAt, payload.windowHours);
    const filename = `threat-digest-${mskFilenameDate(payload.generatedAt)}.pdf`;
    const ctx: PageCtx = { num: 1, dateLabel };

    this.drawCover(doc, dateLabel, windowRange, payload);
    this.turnPage(doc, ctx, "Главное за сутки", "Оперативный exploit-intel отчёт · кратко и по делу");
    this.drawDailyHighlights(doc, payload);
    this.turnPage(doc, ctx, "Критичное за сутки", "P0 / P1 события и причины приоритета");
    this.drawCriticalEvents(doc, payload);
    this.turnPage(doc, ctx, "Сводка за 24 часа", dateLabel);
    this.drawExecutiveSummary(doc, payload);
    this.turnPage(doc, ctx, "Ландшафт сигналов", "По типам · почасовая активность");
    this.drawSignalLandscape(doc, payload);
    this.turnPage(doc, ctx, "Карта угроз по вендорам", "Срез за 24 часа · топ по объёму сигналов");
    this.drawVendorAnalytics(doc, payload);
    this.drawFactSheets(doc, ctx, payload);
    this.drawHotCves(doc, ctx, payload);
    if (payload.newVckev.length || payload.epssSpikeLeaders.length || payload.watchlistCves.length) {
      this.turnPage(doc, ctx, "Особое внимание", "VCK · EPSS · Watchlist");
      this.drawSpecialSections(doc, payload);
    }
    this.finalizePage(doc, ctx);

    doc.end();
    const buffer = await done;
    return { buffer, filename };
  }

  private registerFonts(doc: PdfDoc) {
    doc.registerFont("sans", FONTS.regular);
    doc.registerFont("sans-bold", FONTS.bold);
    doc.registerFont("sans-oblique", FONTS.oblique);
    doc.font("sans");
  }

  private drawCover(doc: PdfDoc, dateLabel: string, windowRange: string, payload: ThreatDigestPayload) {
    doc.rect(0, 0, doc.page.width, doc.page.height).fill(COLORS.bg);
    doc.rect(0, 0, doc.page.width, 8).fill(COLORS.accent);
    doc.circle(doc.page.width - 80, 100, 120).fillOpacity(0.08).fill(COLORS.accent).fillOpacity(1);
    doc.circle(60, doc.page.height - 100, 90).fillOpacity(0.06).fill(COLORS.info).fillOpacity(1);

    doc.fillColor(COLORS.text).font("sans-bold").fontSize(26).text("КИБЕРРАЗВЕДКА", 48, 110);
    doc.fontSize(15).fillColor(COLORS.accent).text("Суточный digest эксплойт-сигналов", 48, 148);
    doc.moveDown(1.2);
    doc.font("sans").fontSize(11).fillColor(COLORS.muted).text(`Период: ${pluralHours(payload.windowHours)}`, 48, 188);
    doc.text(`Окно: ${windowRange}`, 48);
    doc.text(`Сформирован: ${dateLabel} МСК`, 48);

    const p = payload.pulse;
    const highlights: Array<[string, string]> = [
      [`${p.signals}`, "Сигналов эксплойтов"],
      [`${p.hotCves}`, "Hot CVE"],
      [`${p.newSignals}`, "Новых сигналов"],
      [`${p.vckevOnly}`, "Только VCK"],
      [`${p.epssSpikes}`, "Всплески EPSS"],
      [`${p.watchlistHits}`, "Watchlist"]
    ];
    let x = 48;
    let y = 270;
    highlights.forEach(([val, label], i) => {
      if (i === 3) {
        x = 48;
        y += 92;
      }
      doc.roundedRect(x, y, 158, 72, 8).fill(COLORS.card);
      doc.fillColor(COLORS.accent).font("sans-bold").fontSize(24).text(val, x + 14, y + 14, { width: 130 });
      doc.fillColor(COLORS.muted).font("sans").fontSize(9).text(label, x + 14, y + 46, { width: 130 });
      x += 172;
    });

    doc.fillColor(COLORS.muted).fontSize(9).text("Vuln Intel Platform · Конфиденциально", 48, doc.page.height - 64);
  }

  private finalizePage(doc: PdfDoc, ctx: PageCtx) {
    if (ctx.num <= 1) return;
    const footer = `Vuln Intel Platform · ${ctx.dateLabel} · стр. ${ctx.num}`;
    doc.save();
    doc.fillColor(COLORS.muted).font("sans").fontSize(8);
    const w = doc.widthOfString(footer);
    doc.text(footer, (doc.page.width - w) / 2, doc.page.height - 36, { lineBreak: false });
    doc.restore();
  }

  private turnPage(doc: PdfDoc, ctx: PageCtx, title: string, subtitle: string) {
    this.finalizePage(doc, ctx);
    doc.addPage();
    ctx.num += 1;
    this.sectionHeader(doc, title, subtitle);
  }

  private drawExecutiveSummary(doc: PdfDoc, payload: ThreatDigestPayload) {
    const p = payload.pulse;
    const rows: Array<[string, string | number]> = [
      ["Всего сигналов эксплойтов", p.signals],
      ["Уникальных CVE с активностью", p.distinctCves],
      ["Новых сигналов (первое появление)", p.newSignals],
      ["Обновлённых сигналов", p.updatedSignals],
      ["Hot CVE (threat score ≥ 55)", p.hotCves],
      ["Экспозиция только VCK", p.vckevOnly],
      ["Кандидаты на всплеск EPSS", p.epssSpikes],
      ["Пересечение с CISA KEV", p.cisaKev],
      ["Признаки публичного эксплойта", p.withPublicExploit],
      ["Признаки PoC", p.withPoc],
      ["Новые VulnCheck KEV за 24ч", p.newVckev24h],
      ["Срабатывания watchlist", p.watchlistHits],
      ["CVE опубликовано в NVD за 24ч", p.cvesPublished24h]
    ];

    let y = 112;
    rows.forEach(([label, val], i) => {
      if (i % 2 === 0) doc.rect(48, y - 4, doc.page.width - 96, 24).fill(COLORS.cardLight);
      doc.fillColor(COLORS.ink).font("sans").fontSize(10).text(label, 56, y, { width: 340 });
      doc.font("sans-bold").text(String(val), 400, y, { width: 120, align: "right" });
      y += 26;
    });

    doc.fillColor(COLORS.muted).font("sans-oblique").fontSize(9).text(
      "Рейтинг hot CVE учитывает вес сигналов, статус VCK-only, всплеск EPSS, KEV, risk score и уровень EPSS.",
      48,
      y + 18,
      { width: doc.page.width - 96 }
    );
  }

  private drawDailyHighlights(doc: PdfDoc, payload: ThreatDigestPayload) {
    const p = payload.pulse;
    const critical = payload.criticalEvents ?? [];
    const p0 = critical.filter((c) => c.priority === "P0").length;
    const p1 = critical.filter((c) => c.priority === "P1").length;
    const topVendor = payload.vendors[0]?.vendor ?? null;
    const topVendorSignals = payload.vendors[0]?.signal_count ?? 0;

    doc.fillColor(COLORS.ink).font("sans-bold").fontSize(12).text("Ключевые показатели", 48, 110);
    const cards: Array<{ k: string; v: string; color: string }> = [
      { k: "Сигналов", v: String(p.signals), color: COLORS.accent },
      { k: "Hot CVE", v: String(p.hotCves), color: COLORS.warn },
      { k: "P0", v: String(p0), color: COLORS.danger },
      { k: "P1", v: String(p1), color: COLORS.purple },
      { k: "KEV", v: String(p.cisaKev), color: COLORS.info },
      { k: "Эксплойт", v: String(p.withPublicExploit), color: COLORS.danger }
    ];
    let x = 48;
    let y = 134;
    for (const [i, c] of cards.entries()) {
      doc.roundedRect(x, y, 156, 56, 8).fill(COLORS.cardLight);
      doc.fillColor(c.color).font("sans-bold").fontSize(20).text(c.v, x + 12, y + 12);
      doc.fillColor(COLORS.muted).font("sans").fontSize(9).text(c.k, x + 12, y + 34);
      x += 168;
      if ((i + 1) % 3 === 0) {
        x = 48;
        y += 70;
      }
    }

    let by = 290;
    doc.fillColor(COLORS.ink).font("sans-bold").fontSize(12).text("Что изменилось за 24 часа", 48, by);
    by += 20;
    const bullets: string[] = [];
    if (p.newSignals > 0) bullets.push(`Новых сигналов: ${p.newSignals} (первое появление).`);
    if (p.updatedSignals > 0) bullets.push(`Обновлённых сигналов: ${p.updatedSignals} (повтор/эволюция активности).`);
    if (p.newVckev24h > 0) bullets.push(`Новых записей VulnCheck KEV: ${p.newVckev24h}.`);
    if (p.epssSpikes > 0) bullets.push(`Всплесков EPSS: ${p.epssSpikes} (рост вероятности эксплуатации).`);
    if (topVendor) bullets.push(`Наибольшая доля сигналов у вендора: ${topVendor} (${topVendorSignals}).`);
    if (bullets.length === 0) bullets.push("Существенных всплесков не обнаружено (по текущим сигналам).");

    doc.fillColor(COLORS.ink).font("sans").fontSize(10);
    for (const b of bullets.slice(0, 8)) {
      doc.text(`• ${b}`, 56, by, { width: doc.page.width - 112 });
      by += 18;
    }

    const t = payload.trends;
    if (t) {
      by += 10;
      doc.fillColor(COLORS.ink).font("sans-bold").fontSize(12).text("Тренды (по CVSS векторам hot CVE)", 48, by);
      by += 18;
      const av = t.attackVector.slice(0, 3).map((r) => `${r.label}: ${r.count}`).join(" · ");
      const pr = t.privilegesRequired.slice(0, 3).map((r) => `${r.label}: ${r.count}`).join(" · ");
      const ui = t.userInteraction.slice(0, 3).map((r) => `${r.label}: ${r.count}`).join(" · ");
      doc.fillColor(COLORS.muted).font("sans").fontSize(9);
      doc.text(`Attack Vector: ${av || "—"}`, 56, by, { width: doc.page.width - 112 });
      by += 14;
      doc.text(`Privileges Required: ${pr || "—"}`, 56, by, { width: doc.page.width - 112 });
      by += 14;
      doc.text(`User Interaction: ${ui || "—"}`, 56, by, { width: doc.page.width - 112 });
    }
  }

  private drawCriticalEvents(doc: PdfDoc, payload: ThreatDigestPayload) {
    const items = (payload.criticalEvents ?? []).slice(0, 12);
    if (items.length === 0) {
      doc.fillColor(COLORS.muted).font("sans").fontSize(11).text("Критических событий за период не выделено.", 48, 120);
      return;
    }

    let y = 110;
    doc.fillColor(COLORS.ink).font("sans-bold").fontSize(11).text("Список событий", 48, y);
    y += 18;
    const rowH = 72;
    const bottom = doc.page.height - 60;

    items.forEach((it, idx) => {
      if (y + rowH > bottom) return;
      const priColor = it.priority === "P0" ? COLORS.danger : it.priority === "P1" ? COLORS.warn : COLORS.accent;
      doc.roundedRect(48, y, doc.page.width - 96, 64, 6).lineWidth(1).strokeColor(COLORS.line).stroke();
      doc.rect(48, y, 6, 64).fill(priColor);

      doc.fillColor(COLORS.ink).font("sans-bold").fontSize(11).text(`${idx + 1}. ${it.cve_id}`, 62, y + 8);
      doc.fillColor(priColor).text(it.priority, 510, y + 8, { width: 40, align: "right" });

      doc.fillColor(COLORS.muted).font("sans").fontSize(8).text(it.why, 62, y + 24, { width: 470 });

      const summary = buildThreatDigestFallbackSummaryRu(it);
      if (summary) {
        doc.fillColor(COLORS.ink).font("sans").fontSize(9).text(summary, 62, y + 38, {
          width: doc.page.width - 120,
          height: 24,
          ellipsis: true
        });
      }

      if (it.vendor) {
        doc.fillColor("#475569")
          .font("sans")
          .fontSize(8)
          .text(`${it.vendor}${it.product ? ` / ${it.product}` : ""}`, 62, y + 56, { width: 460 });
      }

      y += 72;
    });

    doc.fillColor(COLORS.muted)
      .font("sans-oblique")
      .fontSize(9)
      .text(
        "P0: подтверждённый KEV/эксплойт-готовность с высоким приоритетом. P1: высокая вероятность эксплуатации или явные PoC/сигналы без подтверждённой эксплуатации.",
        48,
        doc.page.height - 78,
        { width: doc.page.width - 96 }
      );
  }

  private drawSignalLandscape(doc: PdfDoc, payload: ThreatDigestPayload) {
    const typeSlices = payload.byType.slice(0, 8).map((r, i) => ({
      label: signalLabelRu(r.signal_type),
      value: r.count,
      color: VENDOR_PALETTE[i % VENDOR_PALETTE.length] ?? COLORS.accent
    }));
    const typeOther = payload.byType.slice(8).reduce((a, r) => a + r.count, 0);
    if (typeOther > 0) typeSlices.push({ label: "Прочие", value: typeOther, color: COLORS.muted });

    this.drawDonutChart(doc, 155, 230, 72, typeSlices, "По типам сигналов");
    this.drawDonutLegend(doc, 260, 168, typeSlices, 280);

    let y = 330;
    const max = Math.max(...payload.byType.map((r) => r.count), 1);
    doc.fillColor(COLORS.ink).font("sans-bold").fontSize(11).text("Топ типов сигналов", 48, y);
    y += 22;
    for (const row of payload.byType.slice(0, 8)) {
      const label = signalLabelRu(row.signal_type);
      const barW = Math.max(16, ((doc.page.width - 240) * row.count) / max);
      doc.fillColor(COLORS.muted).font("sans").fontSize(9).text(label, 48, y + 2, { width: 130 });
      doc.roundedRect(190, y, barW, 14, 3).fill(COLORS.accent);
      doc.fillColor(COLORS.ink).font("sans-bold").fontSize(9).text(String(row.count), 198 + barW, y + 2);
      y += 20;
    }

    y += 16;
    doc.fillColor(COLORS.ink).font("sans-bold").fontSize(11).text("Почасовая активность (24ч)", 48, y);
    y += 20;
    this.drawHourlyAreaChart(doc, 48, y, doc.page.width - 96, 90, payload.hourly);
  }

  private drawVendorAnalytics(doc: PdfDoc, payload: ThreatDigestPayload) {
    const vendors = payload.vendors.slice(0, 10);
    if (!vendors.length) {
      doc.fillColor(COLORS.muted).font("sans").fontSize(11).text("Нет данных по вендорам за период.", 48, 120);
      return;
    }

    const slices: ChartSlice[] = vendors.slice(0, 8).map((v, i) => ({
      label: v.vendor,
      value: v.signal_count,
      color: VENDOR_PALETTE[i % VENDOR_PALETTE.length] ?? COLORS.accent
    }));
    const otherSignals = vendors.slice(8).reduce((a, v) => a + v.signal_count, 0);
    if (otherSignals > 0) slices.push({ label: "Прочие", value: otherSignals, color: COLORS.muted });

    this.drawDonutChart(doc, 400, 210, 88, slices, "Доля сигналов");
    this.drawDonutLegend(doc, 48, 108, slices, 220);

    const chartY = 320;
    doc.fillColor(COLORS.ink).font("sans-bold").fontSize(11).text("Сравнение вендоров: сигналы · CVE · hot", 48, chartY);
    doc.font("sans").fontSize(8).fillColor(COLORS.muted).text("■ сигналы   ■ CVE   ■ hot", 48, chartY + 16);

    const maxVal = Math.max(...vendors.map((v) => Math.max(v.signal_count, v.cve_count, v.hot_count)), 1);
    let y = chartY + 36;
    for (const [i, row] of vendors.entries()) {
      if (y > doc.page.height - 70) break;
      const color = VENDOR_PALETTE[i % VENDOR_PALETTE.length] ?? COLORS.accent;
      doc.fillColor(COLORS.ink).font("sans-bold").fontSize(9).text(row.vendor, 48, y, { width: 110 });
      const barBase = 168;
      const barMaxW = doc.page.width - barBase - 60;
      const sigW = Math.max(4, (barMaxW * row.signal_count) / maxVal);
      const cveW = Math.max(4, (barMaxW * row.cve_count) / maxVal);
      const hotW = Math.max(2, (barMaxW * row.hot_count) / maxVal);

      doc.roundedRect(barBase, y, sigW, 8, 2).fill(color);
      doc.roundedRect(barBase, y + 10, cveW, 8, 2).fill(COLORS.info);
      doc.roundedRect(barBase, y + 20, hotW, 8, 2).fill(row.hot_count > 0 ? COLORS.danger : COLORS.line);

      doc.fillColor(COLORS.muted).font("sans").fontSize(8).text(
        `${row.signal_count} / ${row.cve_count} / ${row.hot_count}`,
        doc.page.width - 108,
        y + 6,
        { width: 60, align: "right" }
      );
      y += 34;
    }

    this.drawVendorBubbleMap(doc, 48, doc.page.height - 155, doc.page.width - 96, 70, vendors.slice(0, 12));
  }

  private drawHotCves(doc: PdfDoc, ctx: PageCtx, payload: ThreatDigestPayload) {
    const rows = payload.hotCves.slice(0, 20);
    if (!rows.length) return;

    this.turnPage(doc, ctx, "Портфель hot CVE", "Ранжирование по композитному threat score");

    const rowH = 66;
    const bottom = doc.page.height - 48;
    let y = 108;
    rows.forEach((row, idx) => {
      if (y + rowH > bottom) {
        this.turnPage(doc, ctx, "Портфель hot CVE (продолжение)", "");
        y = 108;
      }

      const scoreColor = row.threat_score >= 75 ? COLORS.danger : row.threat_score >= 55 ? COLORS.warn : COLORS.accent;
      doc.roundedRect(48, y, doc.page.width - 96, 58, 4).lineWidth(1).strokeColor(COLORS.line).stroke();
      doc.rect(48, y, 6, 58).fill(scoreColor);

      doc.fillColor(COLORS.ink).font("sans-bold").fontSize(11).text(`${idx + 1}. ${row.cve_id}`, 62, y + 8);
      doc.fillColor(scoreColor).text(`THREAT ${row.threat_score}`, 420, y + 8, { width: 100, align: "right" });

      const tags: string[] = [];
      if (row.cisa_kev) tags.push("CISA KEV");
      if (row.vckev_only) tags.push("VCK-only");
      if (row.epss_spike) tags.push("EPSS spike");
      if (row.has_public_exploit) tags.push("Эксплойт");
      else if (row.has_poc) tags.push("PoC");

      doc.fillColor(COLORS.muted).font("sans").fontSize(8).text(tags.join(" · ") || "—", 62, y + 24, { width: 360 });
      const epss = typeof row.epss === "number" ? `${(row.epss * 100).toFixed(1)}%` : "—";
      const delta =
        typeof row.epss_delta_7d === "number"
          ? ` (${row.epss_delta_7d > 0 ? "+" : ""}${(row.epss_delta_7d * 100).toFixed(1)} п.п.)`
          : "";
      doc.text(
        `CVSS ${row.cvss_base ?? "—"} · EPSS ${epss}${delta} · Risk ${row.risk_score ?? "—"} · ${row.signal_count} сигн.`,
        62,
        y + 38,
        { width: 460 }
      );
      if (row.vendor) {
        doc.fillColor("#475569").text(`${row.vendor}${row.product ? ` / ${row.product}` : ""}`, 62, y + 48, { width: 460 });
      }
      const sum = buildThreatDigestFallbackSummaryRu(row);
      if (sum) {
        doc.fillColor(COLORS.muted).font("sans").fontSize(8).text(sum, 62, y + 56, {
          width: doc.page.width - 124,
          height: 10,
          ellipsis: true
        });
      }
      y += 66;
    });
  }

  private drawFactSheets(doc: PdfDoc, ctx: PageCtx, payload: ThreatDigestPayload) {
    const rows = payload.hotCves.slice(0, 12);
    if (!rows.length) return;

    this.turnPage(doc, ctx, "Факт-листы: top уязвимости", "Короткая фактура · источники · векторы · что делать");

    const bottom = doc.page.height - 54;
    let y = 108;
    const cardH = 170;

    for (const row of rows) {
      if (y + cardH > bottom) {
        this.turnPage(doc, ctx, "Факт-листы (продолжение)", "");
        y = 108;
      }

      doc.roundedRect(48, y, doc.page.width - 96, cardH - 10, 8).fill(COLORS.cardLight);
      const headY = y + 12;

      const pri = row.cisa_kev || row.vckev_only || row.has_public_exploit ? "P0" : row.epss_spike || row.has_poc ? "P1" : "P2";
      const priColor = pri === "P0" ? COLORS.danger : pri === "P1" ? COLORS.warn : COLORS.accent;

      doc.fillColor(COLORS.ink).font("sans-bold").fontSize(12).text(row.cve_id, 60, headY);
      doc.fillColor(priColor).font("sans-bold").fontSize(10).text(pri, doc.page.width - 120, headY, { width: 60, align: "right" });
      doc.fillColor(COLORS.muted)
        .font("sans")
        .fontSize(8)
        .text(`${row.vendor ?? "—"}${row.product ? ` / ${row.product}` : ""}`, 60, headY + 16, { width: 360 });

      const epss = typeof row.epss === "number" ? `${(row.epss * 100).toFixed(1)}%` : "—";
      const cvss = row.cvss_base ?? "—";
      const v = [
        `THREAT ${row.threat_score}`,
        `CVSS ${cvss}`,
        `EPSS ${epss}`,
        row.cisa_kev ? "CISA KEV" : null,
        row.vckev_only ? "VCK-only" : null,
        row.has_public_exploit ? "Эксплойт" : row.has_poc ? "PoC" : null,
        row.epss_spike ? "EPSS spike" : null
      ]
        .filter(Boolean)
        .join(" · ");
      doc.fillColor(COLORS.muted).font("sans").fontSize(8).text(v, 60, headY + 30, { width: doc.page.width - 140 });

      const sum = buildThreatDigestFallbackSummaryRu(row);
      if (sum) {
        doc.fillColor(COLORS.ink).font("sans").fontSize(9).text(sum, 60, headY + 46, {
          width: doc.page.width - 120,
          height: 32,
          ellipsis: true
        });
      }

      const vec = [
        row.cvss_av ? `AV:${String(row.cvss_av).toUpperCase()}` : null,
        row.cvss_pr ? `PR:${String(row.cvss_pr).toUpperCase()}` : null,
        row.cvss_ui ? `UI:${String(row.cvss_ui).toUpperCase()}` : null,
        row.cvss_ac ? `AC:${String(row.cvss_ac).toUpperCase()}` : null,
        row.vuln_class ? String(row.vuln_class) : null
      ]
        .filter(Boolean)
        .join(" · ");
      if (vec) {
        doc.fillColor(COLORS.muted).font("sans").fontSize(8).text(`Векторы: ${vec}`, 60, headY + 82, {
          width: doc.page.width - 120
        });
      }

      // Sources
      const sources = (row.sources ?? []).slice(0, 4);
      const colGap = 14;
      const colLeftX = 60;
      const colRightX = Math.floor(doc.page.width / 2) + colGap;
      const colW = Math.floor(doc.page.width / 2) - 48 - colGap;

      doc
        .fillColor(COLORS.ink)
        .font("sans-bold")
        .fontSize(9)
        .text("Источники/рефы:", colLeftX, headY + 98, { width: colW });
      let sy = headY + 112;
      doc.fillColor(COLORS.muted).font("sans").fontSize(7.5);
      if (!sources.length) {
        doc.text("—", colLeftX, sy, { width: colW });
        sy += 12;
      } else {
        for (const s of sources) {
          const label = signalLabelRu(s.signal_type);
          const title = (s.title ?? "").trim();
          const base = title ? `${label}: ${title}` : `${label}: ${s.source}`;
          doc.text(`• ${base}`, colLeftX + 6, sy, { width: colW - 6, ellipsis: true });
          sy += 11;
        }
      }

      // Actions
      const actions = (row.remediation ?? row.next_steps ?? []).slice(0, 3);
      doc
        .fillColor(COLORS.ink)
        .font("sans-bold")
        .fontSize(9)
        .text("Что делать:", colRightX, headY + 98, { width: colW });
      let ay = headY + 112;
      doc.fillColor(COLORS.muted).font("sans").fontSize(7.5);
      if (!actions.length) {
        const generic = [
          "Проверить затронутые версии и наличие обновлений/патчей у вендора.",
          "Ограничить доступ (ACL/VPN/WAF), если AV:NETWORK.",
          "Проверить IoC/логи на попытки эксплуатации по публичным рефам."
        ];
        for (const g of generic) {
          doc.text(`• ${g}`, colRightX, ay, { width: colW, ellipsis: true });
          ay += 11;
        }
      } else {
        for (const a of actions) {
          doc.text(`• ${a}`, colRightX, ay, { width: colW, ellipsis: true });
          ay += 11;
        }
      }

      y += cardH;
    }
  }

  private drawSpecialSections(doc: PdfDoc, payload: ThreatDigestPayload) {
    let y = 110;

    if (payload.newVckev.length) {
      doc.fillColor(COLORS.ink).font("sans-bold").fontSize(11).text("Новые VulnCheck KEV за 24ч", 48, y);
      y += 18;
      for (const row of payload.newVckev.slice(0, 8)) {
        doc.font("sans").fontSize(9).text(
          `• ${row.cve_id} — CVSS ${row.cvss_base ?? "—"}, EPSS ${typeof row.epss === "number" ? `${(row.epss * 100).toFixed(1)}%` : "—"}${row.vckev_only ? ", только VCK" : ""}`,
          56,
          y,
          { width: doc.page.width - 104 }
        );
        y += 16;
      }
      y += 10;
    }

    if (payload.epssSpikeLeaders.length) {
      doc.font("sans-bold").fontSize(11).text("Лидеры всплеска EPSS", 48, y);
      y += 18;
      for (const row of payload.epssSpikeLeaders.slice(0, 8)) {
        const delta =
          typeof row.epss_delta_7d === "number"
            ? `${row.epss_delta_7d > 0 ? "+" : ""}${(row.epss_delta_7d * 100).toFixed(1)} п.п.`
            : "—";
        doc.font("sans").fontSize(9).text(
          `• ${row.cve_id} — EPSS ${typeof row.epss === "number" ? `${(row.epss * 100).toFixed(1)}%` : "—"} (${delta}), CVSS ${row.cvss_base ?? "—"}`,
          56,
          y
        );
        y += 16;
      }
      y += 10;
    }

    if (payload.watchlistCves.length) {
      doc.font("sans-bold").fontSize(11).text("Срабатывания watchlist", 48, y);
      y += 18;
      for (const row of payload.watchlistCves.slice(0, 8)) {
        doc.font("sans").fontSize(9).text(
          `• ${row.cve_id} [${row.threat_score}] — ${row.label}${row.vendor ? ` · ${row.vendor}` : ""}`,
          56,
          y
        );
        y += 16;
      }
    }
  }

  private drawDonutChart(doc: PdfDoc, cx: number, cy: number, outerR: number, slices: ChartSlice[], title: string) {
    const innerR = outerR * 0.52;
    const total = slices.reduce((a, s) => a + s.value, 0) || 1;

    doc.fillColor(COLORS.ink).font("sans-bold").fontSize(10).text(title, cx - outerR, cy - outerR - 22, {
      width: outerR * 2,
      align: "center"
    });

    let angle = -Math.PI / 2;
    for (const slice of slices) {
      const sweep = (slice.value / total) * Math.PI * 2;
      if (sweep <= 0) continue;
      this.drawDonutSegment(doc, cx, cy, innerR, outerR, angle, angle + sweep, slice.color);
      angle += sweep;
    }

    doc.circle(cx, cy, innerR - 1).fill(COLORS.white);
    doc.fillColor(COLORS.ink).font("sans-bold").fontSize(14).text(String(total), cx - 30, cy - 10, { width: 60, align: "center" });
    doc.font("sans").fontSize(7).fillColor(COLORS.muted).text("всего", cx - 30, cy + 6, { width: 60, align: "center" });
  }

  private drawDonutSegment(
    doc: PdfDoc,
    cx: number,
    cy: number,
    innerR: number,
    outerR: number,
    start: number,
    end: number,
    color: string
  ) {
    const oStart = polar(cx, cy, outerR, start);
    const oEnd = polar(cx, cy, outerR, end);
    const iEnd = polar(cx, cy, innerR, end);
    const iStart = polar(cx, cy, innerR, start);
    const large = end - start > Math.PI ? 1 : 0;
    doc
      .path(
        `M ${oStart.x} ${oStart.y} A ${outerR} ${outerR} 0 ${large} 1 ${oEnd.x} ${oEnd.y} L ${iEnd.x} ${iEnd.y} A ${innerR} ${innerR} 0 ${large} 0 ${iStart.x} ${iStart.y} Z`
      )
      .fill(color);
  }

  private drawDonutLegend(doc: PdfDoc, x: number, y: number, slices: ChartSlice[], maxWidth: number) {
    const total = slices.reduce((a, s) => a + s.value, 0) || 1;
    let ly = y;
    for (const slice of slices) {
      const pct = ((slice.value / total) * 100).toFixed(1);
      doc.rect(x, ly + 2, 10, 10).fill(slice.color);
      doc.fillColor(COLORS.ink).font("sans").fontSize(8).text(
        `${slice.label} — ${slice.value} (${pct}%)`,
        x + 16,
        ly,
        { width: maxWidth - 16 }
      );
      ly += 14;
    }
  }

  private drawHourlyAreaChart(
    doc: PdfDoc,
    x: number,
    y: number,
    w: number,
    h: number,
    hourly: Array<{ hour: string; count: number }>
  ) {
    const data = hourly.length ? hourly : [{ hour: "—", count: 0 }];
    const max = Math.max(...data.map((d) => d.count), 1);
    const slotW = w / data.length;

    doc.roundedRect(x, y, w, h, 6).fill(COLORS.cardLight);
    doc.moveTo(x, y + h).lineTo(x + w, y + h).strokeColor(COLORS.line).lineWidth(0.5).stroke();

    data.forEach((pt, i) => {
      const bh = Math.max(2, (h - 16) * (pt.count / max));
      const bx = x + i * slotW + 2;
      const bw = Math.max(slotW - 4, 3);
      const grad = pt.count === max ? COLORS.danger : pt.count > max * 0.6 ? COLORS.warn : COLORS.accent;
      doc.roundedRect(bx, y + h - 8 - bh, bw, bh, 2).fill(grad);
      if (i % 2 === 0 || data.length <= 12) {
        doc.fillColor(COLORS.muted).font("sans").fontSize(6).text(pt.hour, bx, y + h - 4, { width: bw, align: "center" });
      }
    });

    doc.fillColor(COLORS.muted).font("sans").fontSize(8).text(`Пик: ${max} сигн./ч`, x + w - 80, y - 12, { width: 80, align: "right" });
  }

  private drawVendorBubbleMap(
    doc: PdfDoc,
    x: number,
    y: number,
    w: number,
    h: number,
    vendors: Array<{ vendor: string; signal_count: number; cve_count: number; hot_count: number }>
  ) {
    if (!vendors.length) return;
    doc.fillColor(COLORS.ink).font("sans-bold").fontSize(10).text("Heatmap вендоров (размер = сигналы, цвет = hot)", x, y - 14);
    doc.roundedRect(x, y, w, h, 8).fill(COLORS.cardLight);

    const maxSig = Math.max(...vendors.map((v) => v.signal_count), 1);
    const maxHot = Math.max(...vendors.map((v) => v.hot_count), 1);
    const cols = Math.min(4, vendors.length);
    const cellW = w / cols;
    const rows = Math.ceil(vendors.length / cols);
    const cellH = h / rows;

    vendors.forEach((v, i) => {
      const col = i % cols;
      const row = Math.floor(i / cols);
      const cx = x + col * cellW + cellW / 2;
      const cy = y + row * cellH + cellH / 2;
      const r = 8 + (22 * v.signal_count) / maxSig;
      const hotRatio = v.hot_count / maxHot;
      const fill =
        hotRatio >= 0.7 ? COLORS.danger : hotRatio >= 0.35 ? COLORS.warn : VENDOR_PALETTE[i % VENDOR_PALETTE.length] ?? COLORS.accent;

      doc.circle(cx, cy, r).fillOpacity(0.85).fill(fill).fillOpacity(1);
      doc.fillColor(COLORS.white).font("sans-bold").fontSize(Math.max(6, Math.min(8, r / 2))).text(
        v.vendor.length > 12 ? `${v.vendor.slice(0, 11)}…` : v.vendor,
        cx - r,
        cy - 4,
        { width: r * 2, align: "center" }
      );
      doc.font("sans").fontSize(6).text(String(v.signal_count), cx - r, cy + 5, { width: r * 2, align: "center" });
    });
  }

  private sectionHeader(doc: PdfDoc, title: string, subtitle: string) {
    doc.rect(0, 0, doc.page.width, 64).fill(COLORS.bg);
    doc.rect(0, 64, doc.page.width, 3).fill(COLORS.accent);
    doc.fillColor(COLORS.text).font("sans-bold").fontSize(18).text(title, 48, 22);
    if (subtitle) doc.fillColor(COLORS.muted).font("sans").fontSize(10).text(subtitle, 48, 44);
  }
}

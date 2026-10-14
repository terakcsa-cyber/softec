"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api-fetch";

const MONTH_OPTIONS = [
  "Январь", "Февраль", "Март", "Апрель", "Май", "Июнь",
  "Июль", "Август", "Сентябрь", "Октябрь", "Ноябрь", "Декабрь"
];

type MetricLine = { label: string; value: string };
type MonthCve = {
  cveId: string; vendor: string; product: string; cvss: string; epss: string;
  kev: string; publishedDay: string; signal: string; description: string;
};
type MonthPreview = {
  year: number; month: number; monthTitle: string; title: string;
  windowLabel: string; periodLabel: string; issuedAt: string; issuedLabel: string;
  status: string; note: string; coverage: string; sourcesNote: string;
  tiles: MetricLine[]; metrics: MetricLine[]; exploit: MetricLine[];
  days: Array<{ label: string; published: string; critical: string }>;
  vendors: Array<{ vendor: string; count: string }>;
  products: Array<{ product: string; vendor: string; count: string }>;
  kevRows: Array<{ cveId: string; dateAdded: string; product: string; cvss: string; epss: string }>;
  cves: MonthCve[];
  narrative: { status: string; lead: string; summary: string; cases: string; close: string; text: string };
};

export function MonthlyDigestPanel() {
  const [year, setYear] = useState(2026);
  const [month, setMonth] = useState(9);
  const [busy, setBusy] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<MonthPreview | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setBusy(true);
    setError(null);
    setPreview(null);
    void (async () => {
      try {
        const res = await apiFetch("/api/stats/monthly-digest/preview", {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify({ year, month }),
          signal: controller.signal
        });
        if (!res.ok) { setError("Дайджест не собрался."); return; }
        const parsed = parseMonthPreview(await res.json());
        if (!parsed) { setError("Дайджест не собрался."); return; }
        setPreview(parsed);
      } catch (err) {
        if (controller.signal.aborted) return;
        if (err instanceof DOMException && err.name === "AbortError") return;
        setError("Дайджест не собрался.");
      } finally {
        if (!controller.signal.aborted) setBusy(false);
      }
    })();
    return () => controller.abort();
  }, [year, month]);

  async function download() {
    if (!preview || busy || downloading) return;
    setDownloading(true);
    setError(null);
    try {
      const res = await apiFetch("/api/stats/monthly-digest/pdf", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/pdf" },
        body: JSON.stringify({
          year: preview.year,
          month: preview.month,
          issuedAt: preview.issuedAt,
          narrative: preview.narrative
        })
      });
      if (!res.ok) { setError("PDF не скачался."); return; }
      const blob = await res.blob();
      const filename = filenameFromDisposition(res.headers.get("content-disposition"))
        ?? `vulncontrol-digest-${preview.year}-${String(preview.month).padStart(2, "0")}.pdf`;
      saveBlob(blob, filename);
    } catch {
      setError("PDF не скачался.");
    } finally {
      setDownloading(false);
    }
  }

  return (
    <div className="grid items-start gap-3 xl:grid-cols-[minmax(280px,340px)_minmax(0,1fr)]">
      <aside className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-3">
        <h2 className="text-[14px] font-semibold">Ежемесячный дайджест</h2>
        <p className="mt-1 text-[12px] leading-relaxed text-[var(--vc-muted)]">
          Календарный месяц каталога. Предпросмотр собирается сам. PDF скачивается отдельно и повторяет этот лист.
        </p>
        <label className="mt-3 block text-[11px] text-[var(--vc-muted)]">
          Месяц
          <select aria-label="Месяц дайджеста" value={month} onChange={(event) => setMonth(Number(event.target.value))} className="mt-1 h-9 w-full rounded-lg border border-[var(--vc-border)] bg-[var(--vc-inset)] px-2 text-[13px] text-[var(--vc-text)]">
            {MONTH_OPTIONS.map((label, index) => <option key={label} value={index + 1}>{label}</option>)}
          </select>
        </label>
        <label className="mt-2 block text-[11px] text-[var(--vc-muted)]">
          Год
          <select aria-label="Год дайджеста" value={year} onChange={(event) => setYear(Number(event.target.value))} className="mt-1 h-9 w-full rounded-lg border border-[var(--vc-border)] bg-[var(--vc-inset)] px-2 text-[13px] text-[var(--vc-text)]">
            {[2024, 2025, 2026].map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </label>
        <button type="button" disabled={busy || downloading || !preview} onClick={() => void download()} className="mt-3 h-9 w-full rounded-lg bg-[var(--vc-primary)] text-[13px] font-medium text-white disabled:opacity-40">
          {downloading ? "Готовлю PDF…" : "Скачать PDF"}
        </button>
        <p className="mt-2 text-[11px] leading-relaxed text-[var(--vc-muted)]">
          Смена месяца только обновляет предпросмотр. Файл не скачивается, пока не нажата кнопка.
        </p>
        {error ? <p className="mt-1 text-[11px] text-[var(--vc-danger-text)]">{error}</p> : null}
      </aside>
      <article aria-label="Предпросмотр ежемесячного дайджеста" className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-4">
        <p className="text-[10px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">Предпросмотр дайджеста</p>
        {busy && !preview ? <p className="mt-3 text-[13px] text-[var(--vc-muted)]">Собираю месяц из каталога…</p> : null}
        {preview ? <MonthSheet preview={preview} /> : null}
      </article>
    </div>
  );
}

function MonthSheet({ preview }: { preview: MonthPreview }) {
  const story = [preview.narrative.lead, preview.narrative.summary, preview.narrative.cases, preview.narrative.close].map((part) => part.trim()).filter(Boolean);
  return (
    <div className="mt-3">
      <h1 className="text-[18px] font-semibold leading-tight">{preview.title}</h1>
      <p className="mt-1 text-[12px] text-[var(--vc-muted)]">{preview.monthTitle} · {preview.periodLabel} · Окно: {preview.windowLabel}</p>
      <p className="mt-1 text-[12px] text-[var(--vc-muted)]">Подготовлено {preview.issuedLabel}</p>
      <ul className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3">
        {preview.tiles.map((tile) => (
          <li key={tile.label} className="rounded-lg border border-[var(--vc-border)] px-2.5 py-2">
            <p className="text-[10px] uppercase tracking-wide text-[var(--vc-muted)]">{tile.label}</p>
            <p className="mt-0.5 text-[16px] font-semibold tabular-nums">{tile.value}</p>
          </li>
        ))}
      </ul>
      <section className="mt-4 border-t border-[var(--vc-border)] pt-3">
        <h2 className="text-[14px] font-semibold">Рассказ</h2>
        {story.length ? story.map((part) => <p key={part.slice(0, 80)} className="mt-2 whitespace-pre-wrap text-[13px] leading-relaxed">{part}</p>) : <p className="mt-2 text-[13px] leading-relaxed">{preview.note}</p>}
      </section>
      <p className="mt-3 text-[12px] leading-relaxed text-[var(--vc-muted)]">{preview.sourcesNote}</p>
      <MetricBlock title="Сводка месяца" rows={preview.metrics} />
      <MetricBlock title="Эксплойт и EPSS" rows={preview.exploit} />
      <section className="mt-4 border-t border-[var(--vc-border)] pt-3">
        <h2 className="text-[14px] font-semibold">Публикации по дням</h2>
        {preview.days.length ? preview.days.map((day) => (
          <p key={day.label} className="mt-1 flex justify-between text-[12px]"><span className="text-[var(--vc-muted)]">{day.label}</span><span className="tabular-nums">{day.published} · CVSS ≥ 9: {day.critical}</span></p>
        )) : <p className="mt-2 text-[12px] text-[var(--vc-muted)]">Нет публикаций.</p>}
      </section>
      <SimpleTable title="Вендоры" columns={["Вендор", "CVE"]} rows={preview.vendors.map((row) => [row.vendor, row.count])} />
      <SimpleTable title="Продукты" columns={["Продукт", "Вендор", "CVE"]} rows={preview.products.map((row) => [row.product, row.vendor, row.count])} />
      <SimpleTable title="CISA KEV месяца" columns={["CVE", "Дата", "Продукт", "CVSS", "EPSS"]} rows={preview.kevRows.map((row) => [row.cveId, row.dateAdded, row.product, row.cvss, row.epss])} />
      <section className="mt-4 border-t border-[var(--vc-border)] pt-3">
        <h2 className="text-[14px] font-semibold">Заметные CVE</h2>
        {preview.cves.length ? preview.cves.map((row) => (
          <article key={row.cveId} className="mt-2 text-[12px] leading-relaxed">
            <p className="font-semibold">{row.cveId}</p>
            <p className="text-[var(--vc-muted)]">{[row.publishedDay, row.vendor, row.product].filter(Boolean).join(" · ")}{` · CVSS ${row.cvss} · EPSS ${row.epss}${row.kev === "KEV" ? " · KEV" : ""}`}{row.signal ? ` · ${row.signal}` : ""}</p>
            {row.description ? <p className="mt-1">{row.description}</p> : null}
          </article>
        )) : <p className="mt-2 text-[12px] text-[var(--vc-muted)]">Нет строк.</p>}
      </section>
      <p className="mt-4 text-[11px] leading-relaxed text-[var(--vc-muted)]">{preview.coverage}</p>
    </div>
  );
}

function MetricBlock({ title, rows }: { title: string; rows: MetricLine[] }) {
  return (
    <section className="mt-4 border-t border-[var(--vc-border)] pt-3">
      <h2 className="text-[14px] font-semibold">{title}</h2>
      {rows.length ? (
        <ul className="mt-2 divide-y divide-[var(--vc-border)]">
          {rows.map((row) => (
            <li key={row.label} className="flex items-center justify-between gap-3 py-1.5 text-[12px]">
              <span className="text-[var(--vc-muted)]">{row.label}</span>
              <span className="font-semibold tabular-nums">{row.value}</span>
            </li>
          ))}
        </ul>
      ) : <p className="mt-2 text-[12px] text-[var(--vc-muted)]">Нет строк.</p>}
    </section>
  );
}

function SimpleTable({ title, columns, rows }: { title: string; columns: string[]; rows: string[][] }) {
  return (
    <section className="mt-4 border-t border-[var(--vc-border)] pt-3">
      <h2 className="text-[14px] font-semibold">{title}</h2>
      {rows.length ? (
        <div className="mt-2 overflow-x-auto">
          <table className="w-full min-w-[520px] text-left text-[12px]">
            <thead><tr className="text-[10px] uppercase tracking-wide text-[var(--vc-muted)]">{columns.map((column) => <th key={column} className="px-2 py-1.5 font-medium">{column}</th>)}</tr></thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={`${row[0]}-${index}`} className="border-t border-[var(--vc-border)]">
                  {row.map((cell, cellIndex) => <td key={`${columns[cellIndex]}-${cellIndex}`} className="px-2 py-1.5 align-top">{cell}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : <p className="mt-2 text-[12px] text-[var(--vc-muted)]">Нет строк.</p>}
    </section>
  );
}

function parseMonthPreview(value: unknown): MonthPreview | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  const figures = row.figures;
  if (!figures || typeof figures !== "object" || Array.isArray(figures)) return null;
  if (typeof (figures as { published?: unknown }).published !== "number") return null;
  const narrative = row.narrative;
  if (!narrative || typeof narrative !== "object" || Array.isArray(narrative)) return null;
  const story = narrative as Record<string, unknown>;
  if (typeof story.text !== "string" || typeof story.lead !== "string" || typeof story.status !== "string") return null;
  if (typeof row.monthTitle !== "string" || typeof row.year !== "number" || typeof row.month !== "number") return null;
  return {
    year: row.year, month: row.month, monthTitle: row.monthTitle,
    title: typeof row.title === "string" ? row.title : row.monthTitle,
    windowLabel: typeof row.windowLabel === "string" ? row.windowLabel : "",
    periodLabel: typeof row.periodLabel === "string" ? row.periodLabel : "",
    issuedAt: typeof row.issuedAt === "string" ? row.issuedAt : "",
    issuedLabel: typeof row.issuedLabel === "string" ? row.issuedLabel : "",
    status: typeof row.status === "string" ? row.status : story.status,
    note: typeof row.note === "string" ? row.note : story.lead,
    coverage: typeof row.coverage === "string" ? row.coverage : "",
    sourcesNote: typeof row.sourcesNote === "string" ? row.sourcesNote : "",
    tiles: metricLines(row.tiles), metrics: metricLines(row.metrics), exploit: metricLines(row.exploit),
    days: objectRows(row.days).flatMap((item) => typeof item.label === "string" ? [{ label: item.label, published: textOf(item.published), critical: textOf(item.critical) }] : []),
    vendors: objectRows(row.vendors).flatMap((item) => typeof item.vendor === "string" ? [{ vendor: item.vendor, count: textOf(item.count) }] : []),
    products: objectRows(row.products).flatMap((item) => typeof item.product === "string" ? [{ product: item.product, vendor: textOf(item.vendor) || "—", count: textOf(item.count) }] : []),
    kevRows: objectRows(row.kevRows).flatMap((item) => typeof item.cveId === "string" ? [{ cveId: item.cveId, dateAdded: textOf(item.dateAdded), product: textOf(item.product) || "—", cvss: textOf(item.cvss) || "—", epss: textOf(item.epss) || "—" }] : []),
    cves: objectRows(row.cves).flatMap((item) => typeof item.cveId === "string" ? [{ cveId: item.cveId, vendor: textOf(item.vendor), product: textOf(item.product), cvss: textOf(item.cvss) || "—", epss: textOf(item.epss) || "—", kev: textOf(item.kev), publishedDay: textOf(item.publishedDay), signal: textOf(item.signal), description: textOf(item.description) }] : []),
    narrative: { status: story.status, lead: story.lead, summary: textOf(story.summary), cases: textOf(story.cases), close: textOf(story.close), text: story.text }
  };
}

function metricLines(value: unknown): MetricLine[] {
  return objectRows(value).flatMap((item) => typeof item.label === "string" ? [{ label: item.label, value: textOf(item.value) }] : []);
}
function objectRows(value: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object" && !Array.isArray(item));
}
function textOf(value: unknown): string {
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}
function filenameFromDisposition(header: string | null) {
  if (!header) return null;
  const name = /filename="([^"]+)"/.exec(header)?.[1]?.trim();
  if (!name || !name.endsWith(".pdf") || name.includes("/") || name.includes("\\")) return null;
  return name;
}
function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1500);
}

"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api-fetch";

const MONTH_OPTIONS = [
  "Январь", "Февраль", "Март", "Апрель", "Май", "Июнь",
  "Июль", "Август", "Сентябрь", "Октябрь", "Ноябрь", "Декабрь"
];

type DigestTable = { columns: string[]; rows: string[][] };
type DigestChart = {
  id: string;
  slide: string;
  title: string;
  kind: "bars" | "compare";
  bars: Array<{ label: string; value: number }>;
};
type DigestSection = {
  title: string;
  headline?: string;
  paragraphs: string[];
  bullets: string[];
  table: DigestTable | null;
};
type DigestDocument = {
  focus: string;
  lead: string;
  audience: string;
  kpis: Array<{ value: string; label: string }>;
  sections: DigestSection[];
  closing: string;
};

type MonthPreview = {
  monthLabel: string;
  monthTitle: string;
  period: string;
  status: string;
  searched: boolean;
  text: string;
  document: DigestDocument | null;
  charts: DigestChart[];
  sources: string[];
  note: string;
};

type SavedDigest = {
  id: string;
  monthLabel: string;
  filename: string;
  downloadedAt: string;
};

export function MonthlyDigestPanel() {
  const [year, setYear] = useState(2026);
  const [month, setMonth] = useState(9);
  const [phase, setPhase] = useState<"idle" | "collect" | "pdf">("idle");
  const busy = phase !== "idle";
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<MonthPreview | null>(null);
  const [history, setHistory] = useState<SavedDigest[]>([]);
  const [historyReady, setHistoryReady] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);

  async function loadHistory() {
    try {
      const res = await apiFetch("/api/stats/monthly-digest/history", {
        headers: { accept: "application/json" }
      });
      if (!res.ok) {
        setHistoryError("История скачиваний не загрузилась.");
        return;
      }
      const data = (await res.json()) as { items?: unknown };
      const items = Array.isArray(data.items) ? data.items.flatMap(parseSavedDigest).slice(0, 5) : [];
      setHistory(items);
      setHistoryError(null);
    } catch {
      setHistoryError("История скачиваний не загрузилась.");
    } finally {
      setHistoryReady(true);
    }
  }

  useEffect(() => {
    void loadHistory();
  }, []);

  async function collect() {
    setPhase("collect");
    setError(null);
    setPreview(null);
    try {
      const res = await apiFetch("/api/stats/monthly-digest/preview", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ year, month })
      });
      if (!res.ok) {
        setError("Дайджест не собрался.");
        return;
      }
      const data = (await res.json()) as Partial<MonthPreview>;
      if (typeof data.text !== "string" || !data.text.trim()) {
        setError("Дайджест не собрался.");
        return;
      }
      setPreview({
        monthLabel: data.monthLabel || "",
        monthTitle: data.monthTitle || data.monthLabel || "",
        period: data.period || "",
        status: data.status || "failed",
        searched: Boolean(data.searched),
        text: data.text,
        document: isDocument(data.document) ? data.document : null,
        charts: Array.isArray(data.charts) ? data.charts.filter(isChart) : [],
        sources: Array.isArray(data.sources) ? data.sources.filter((item) => typeof item === "string") : [],
        note: data.note || ""
      });
    } catch {
      setError("Дайджест не собрался.");
    } finally {
      setPhase("idle");
    }
  }

  async function download() {
    if (!preview?.text || preview.status !== "generated" || busy) return;
    setPhase("pdf");
    setError(null);
    try {
      const res = await apiFetch("/api/stats/monthly-digest/pdf", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/pdf" },
        body: JSON.stringify({
          year,
          month,
          text: preview.text,
          document: preview.document,
          charts: preview.charts,
          sources: preview.sources
        })
      });
      if (!res.ok) {
        setError("PDF не скачался.");
        return;
      }
      const blob = await res.blob();
      const filename = filenameFromDisposition(res.headers.get("content-disposition")) ?? `vulncontrol-digest-${year}-${String(month).padStart(2, "0")}.pdf`;
      saveBlob(blob, filename);
      await loadHistory();
    } catch {
      setError("PDF не скачался.");
    } finally {
      setPhase("idle");
    }
  }

  async function downloadSaved(item: SavedDigest) {
    if (busy) return;
    setPhase("pdf");
    setError(null);
    try {
      const res = await apiFetch(`/api/stats/monthly-digest/history/${encodeURIComponent(item.id)}`, {
        headers: { accept: "application/pdf" }
      });
      if (!res.ok) {
        setError("Сохранённый PDF не скачался.");
        return;
      }
      const blob = await res.blob();
      const filename = filenameFromDisposition(res.headers.get("content-disposition")) ?? item.filename;
      saveBlob(blob, filename);
    } catch {
      setError("Сохранённый PDF не скачался.");
    } finally {
      setPhase("idle");
    }
  }

  return (
    <div className="space-y-3">
    <div className="grid items-start gap-3 xl:grid-cols-[minmax(280px,340px)_minmax(0,1fr)]">
      <aside className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-3">
        <h2 className="text-[14px] font-semibold">Ежемесячный дайджест</h2>
        <p className="mt-1 text-[12px] leading-relaxed text-[var(--vc-muted)]">
          DeepSeek ищет в открытом интернете; платформа дополнительно снимает CISA KEV, NVD, EPSS и бюллетени. PDF — слайды 16:9 с графиками по фидам. Каталог VulnControl не используется.
        </p>
        <label className="mt-3 block text-[11px] text-[var(--vc-muted)]">
          Месяц
          <select
            aria-label="Месяц дайджеста"
            value={month}
            onChange={(event) => { setMonth(Number(event.target.value)); setPreview(null); }}
            className="mt-1 h-9 w-full rounded-lg border border-[var(--vc-border)] bg-[var(--vc-inset)] px-2 text-[13px] text-[var(--vc-text)]"
          >
            {MONTH_OPTIONS.map((label, index) => <option key={label} value={index + 1}>{label}</option>)}
          </select>
        </label>
        <label className="mt-2 block text-[11px] text-[var(--vc-muted)]">
          Год
          <select
            aria-label="Год дайджеста"
            value={year}
            onChange={(event) => { setYear(Number(event.target.value)); setPreview(null); }}
            className="mt-1 h-9 w-full rounded-lg border border-[var(--vc-border)] bg-[var(--vc-inset)] px-2 text-[13px] text-[var(--vc-text)]"
          >
            {[2024, 2025, 2026].map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </label>
        <button type="button" disabled={busy} onClick={() => void collect()} className="mt-3 h-9 w-full rounded-lg bg-[var(--vc-primary)] text-[13px] font-medium text-white disabled:opacity-40">
          {phase === "collect" ? "Собираю…" : "Собрать предпросмотр"}
        </button>
        <button type="button" disabled={busy || !preview || preview.status !== "generated"} onClick={() => void download()} className="mt-2 h-8 w-full rounded-lg border border-[var(--vc-border)] text-[12px] text-[var(--vc-muted)] disabled:opacity-40">
          {phase === "pdf" ? "Скачиваю…" : "Скачать PDF"}
        </button>
        <p className="mt-2 text-[11px] leading-relaxed text-[var(--vc-muted)]">
          Сначала предпросмотр слайдов. PDF собирается из них без второго запроса в модель.
        </p>
        {error ? <p className="mt-1 text-[11px] text-[var(--vc-danger-text)]">{error}</p> : null}
      </aside>
      <article aria-label="Предпросмотр ежемесячного дайджеста" className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-4">
        <p className="text-[10px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">Предпросмотр дайджеста</p>
        {preview ? (
          <div className="mt-3">
            <p className="text-[12px] leading-relaxed text-[var(--vc-muted)]">{preview.note}</p>
            {preview.sources.length ? <p className="mt-1 text-[12px] text-[var(--vc-muted)]">Источники: {preview.sources.join(", ")}.</p> : null}
            <div className="mt-4">
              {preview.document ? <DigestPaper preview={preview} /> : <div className="whitespace-pre-wrap text-[13px] leading-relaxed">{preview.text}</div>}
            </div>
          </div>
        ) : (
          <p className="mt-3 text-[13px] text-[var(--vc-muted)]">Выберите месяц и соберите предпросмотр. Пока кнопка не нажата, DeepSeek не вызывается.</p>
        )}
      </article>
    </div>
    <section aria-label="История скачанных дайджестов" className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-3">
      <h2 className="text-[14px] font-semibold">Последние скачивания</h2>
      <p className="mt-1 text-[12px] leading-relaxed text-[var(--vc-muted)]">Хранятся пять последних PDF. Повторное скачивание берёт сохранённый файл и не вызывает DeepSeek.</p>
      {historyError ? <p className="mt-2 text-[12px] text-[var(--vc-danger-text)]">{historyError}</p> : null}
      {historyReady && history.length === 0 && !historyError ? (
        <p className="mt-2 text-[12px] text-[var(--vc-muted)]">Пока нет скачанных дайджестов.</p>
      ) : null}
      {history.length > 0 ? (
        <ul className="mt-2 divide-y divide-[var(--vc-border)]">
          {history.map((item) => (
            <li key={item.id} className="flex items-center justify-between gap-3 py-2">
              <div>
                <p className="text-[13px] font-medium">{item.monthLabel}</p>
                <p className="text-[11px] text-[var(--vc-muted)]">{formatDownloaded(item.downloadedAt)}</p>
              </div>
              <button type="button" disabled={busy} onClick={() => void downloadSaved(item)} className="h-8 shrink-0 rounded-lg border border-[var(--vc-border)] px-3 text-[12px] text-[var(--vc-muted)] disabled:opacity-40">
                Скачать файл
              </button>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
    </div>
  );
}

function formatBriefNumber(value: string) {
  const trimmed = value.trim();
  if (!/^\d{4,}$/.test(trimmed)) return value;
  return new Intl.NumberFormat("ru-RU").format(Number(trimmed));
}

function DigestPaper({ preview }: { preview: MonthPreview }) {
  const doc = preview.document;
  if (!doc) return null;
  const slideCount = 1 + doc.sections.length + (doc.closing ? 1 : 0);
  return (
    <div className="space-y-3">
      <p className="text-[11px] text-[var(--vc-muted)]">
        Предпросмотр слайдов презентации 16:9 · {slideCount} слайд{slideCount === 1 ? "" : slideCount < 5 ? "а" : "ов"}
      </p>
      <div className="overflow-hidden rounded-lg border border-[#E4E8EE] bg-[#0E1C36] text-white" style={{ aspectRatio: "16 / 9" }}>
        <div className="flex h-full flex-col justify-between p-6">
          <div>
            <p className="text-[10px] tracking-[0.14em] text-[#C4A35A]">VULNERABILITY THREAT INTELLIGENCE</p>
            <h1 className="mt-2 text-[22px] font-semibold">Ежемесячный обзор ландшафта уязвимостей</h1>
            <p className="mt-1 text-[16px]">{preview.monthTitle}</p>
            {doc.focus ? <p className="mt-3 max-w-3xl text-[12px] leading-5 text-[#D5DCE6]">{doc.focus}</p> : null}
          </div>
          <div>
            {doc.kpis.length ? (
              <div className="mb-3 grid gap-2" style={{ gridTemplateColumns: `repeat(${doc.kpis.length}, minmax(0, 1fr))` }}>
                {doc.kpis.map((item) => (
                  <div key={`${item.value}-${item.label}`} className="rounded-md bg-white/10 px-3 py-2">
                    <div className="text-[18px] font-semibold text-[#C4A35A]">{formatBriefNumber(item.value)}</div>
                    <div className="text-[11px] leading-4 text-[#D5DCE6]">{item.label}</div>
                  </div>
                ))}
              </div>
            ) : null}
            <p className="line-clamp-3 text-[12px] leading-5 text-[#E8EEF6]">{doc.lead}</p>
            {preview.period ? <p className="mt-2 text-[11px] text-[#9AA8BA]">Период: {preview.period}</p> : null}
          </div>
        </div>
      </div>
      {doc.sections.map((section, index) => {
        const chart = preview.charts.find((item) => item.slide === section.title);
        return (
        <section
          key={section.title}
          className="overflow-hidden rounded-lg border border-[#E4E8EE] bg-white text-[#142033]"
          style={{ aspectRatio: "16 / 9" }}
        >
          <div className="flex h-full flex-col p-5">
            <p className="text-[10px] font-semibold uppercase tracking-wide text-[#C4A35A]">{section.title}</p>
            <h2 className="mt-1 text-[18px] font-semibold text-[#0E1C36]">{section.headline || section.title}</h2>
            <p className="mt-1 text-[10px] text-[#5C6B7A]">Слайд {index + 2}</p>
            <div className={`mt-3 min-h-0 flex-1 overflow-hidden ${chart ? "grid gap-3 sm:grid-cols-[1.1fr_0.9fr]" : ""}`}>
              <div>
                {section.paragraphs.map((paragraph, paragraphIndex) => (
                  <p key={`${section.title}-${paragraphIndex}`} className="mt-1 text-[12px] leading-5">{paragraph}</p>
                ))}
                {section.bullets.length ? (
                  <ul className={`mt-2 grid gap-1 text-[12px] leading-5 ${chart ? "" : "sm:grid-cols-2"}`}>
                    {section.bullets.map((bullet) => <li key={bullet}>• {bullet}</li>)}
                  </ul>
                ) : null}
                {section.table ? (
                  <div className="mt-2 overflow-x-auto">
                    <table className="w-full border-collapse text-left text-[11px]">
                      <thead>
                        <tr className="bg-[#0E1C36] text-white">
                          {section.table.columns.map((column) => <th key={column} className="px-2 py-1 font-medium">{column}</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {section.table.rows.slice(0, 5).map((row) => (
                          <tr key={row.join("|")} className="odd:bg-[#F7F8FB]">
                            {row.map((cell, cellIndex) => <td key={`${row[0]}-${cellIndex}`} className="px-2 py-1 align-top">{cell}</td>)}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : null}
              </div>
              {chart ? <PreviewChart chart={chart} /> : null}
            </div>
          </div>
        </section>
        );
      })}
      {doc.closing ? (
        <div className="overflow-hidden rounded-lg border border-[#E4E8EE] bg-white text-[#142033]" style={{ aspectRatio: "16 / 9" }}>
          <div className="flex h-full flex-col justify-center p-6">
            <p className="text-[10px] font-semibold uppercase tracking-wide text-[#C4A35A]">Выводы для руководства</p>
            <p className="mt-3 border-l-2 border-[#C4A35A] pl-3 text-[14px] leading-6">{doc.closing}</p>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function isDocument(value: unknown): value is DigestDocument {
  if (!value || typeof value !== "object") return false;
  const row = value as DigestDocument;
  return typeof row.lead === "string" && Array.isArray(row.sections);
}

function isChart(value: unknown): value is DigestChart {
  if (!value || typeof value !== "object") return false;
  const row = value as DigestChart;
  return typeof row.id === "string" && typeof row.slide === "string" && Array.isArray(row.bars);
}

function PreviewChart({ chart }: { chart: DigestChart }) {
  const max = Math.max(...chart.bars.map((bar) => bar.value), 1);
  return (
    <div className="rounded-md bg-[#F7F8FB] p-3">
      <p className="text-[11px] font-semibold text-[#0E1C36]">{chart.title}</p>
      <div className="mt-3 flex h-36 items-end gap-2">
        {chart.bars.slice(0, 8).map((bar, index) => (
          <div key={`${bar.label}-${index}`} className="flex min-w-0 flex-1 flex-col items-center justify-end gap-1">
            <span className="text-[10px] font-semibold tabular-nums text-[#0E1C36]">{formatBriefNumber(String(bar.value))}</span>
            <div
              className="w-full rounded-t-sm"
              style={{
                height: `${Math.max(8, (bar.value / max) * 100)}%`,
                background: index === 0 ? "#0E1C36" : "#C4A35A"
              }}
            />
            <span className="w-full truncate text-center text-[9px] text-[#5C6B7A]">{bar.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

const SAVED_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function parseSavedDigest(raw: unknown): SavedDigest[] {
  if (!raw || typeof raw !== "object") return [];
  const row = raw as Record<string, unknown>;
  const id = typeof row.id === "string" ? row.id : "";
  const monthLabel = typeof row.monthLabel === "string" ? row.monthLabel.trim() : "";
  const filename = typeof row.filename === "string" ? row.filename.trim() : "";
  const downloadedAt = typeof row.downloadedAt === "string" ? row.downloadedAt : "";
  if (!SAVED_ID.test(id) || !monthLabel || !filename.endsWith(".pdf") || filename.includes("/") || filename.includes("\\")) return [];
  if (Number.isNaN(Date.parse(downloadedAt))) return [];
  return [{ id, monthLabel, filename, downloadedAt }];
}

function formatDownloaded(iso: string) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return new Intl.DateTimeFormat("ru-RU", {
    day: "numeric",
    month: "long",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

function filenameFromDisposition(header: string | null) {
  if (!header) return null;
  const match = /filename="([^"]+)"/.exec(header);
  const name = match?.[1]?.trim();
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

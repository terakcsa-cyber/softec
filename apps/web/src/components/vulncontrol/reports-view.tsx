"use client";

import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api-fetch";
import { cn } from "@/components/ui/cn";
import { useVc } from "./vc-context";
import { MonthlyDigestPanel } from "./monthly-digest-panel";
import { VcSelect } from "./vc-pop";
import {
  formatDate,
  formatInt,
  knownCatalogTotal,
  taskStatusLabel,
  useAnalyticsSeries,
  useCatalogSummary,
  useCveList,
  useExploitRadar,
  useVendorWindow,
  useVulnTasks,
  windowHoursFor,
  type AnalyticsDay,
  type CatalogSummary,
  type ExploitRadar,
  type LiveCve,
  type LiveTask,
  type VendorWindow
} from "@/lib/vulncontrol/live";
import type { Severity, VcRange } from "@/lib/vulncontrol/types";

const CVE_LIMIT = 50;
const TASK_LIMIT = 200;

const RANGES: Array<[VcRange, string]> = [
  ["7d", "Последние 7 дней"],
  ["30d", "Последние 30 дней"],
  ["90d", "Последние 90 дней"],
  ["all", "Всё время"]
];

const SEVERITY: Array<[Severity | "all", string]> = [
  ["all", "Все уровни CVSS"],
  ["critical", "CVSS ≥ 9"],
  ["high", "CVSS 7–8.9"],
  ["medium", "CVSS 4–6.9"],
  ["low", "CVSS < 4"]
];

const SECTIONS = [
  { id: "summary", label: "Сводка каталога", hint: "Всего, CVSS, KEV, EPSS ≥ 0.7, публикации за 24 часа" },
  { id: "trend", label: "Тренд публикаций", hint: "Ряд аналитики: публикации, CVSS ≥ 9 и новые KEV по дням" },
  { id: "exploit", label: "Exploit intel", hint: "Снимок радара: эксплойт, PoC, скачок EPSS, VulnCheck KEV" },
  { id: "vendors", label: "Вендоры и продукты", hint: "Топ публикаций окна. API не шире 30 дней" },
  { id: "cves", label: "Выборка CVE", hint: "Страница API по фильтрам. Не весь каталог" },
  { id: "tasks", label: "Задачи", hint: "Список рабочего стола, как его отдал API" }
] as const;

type SectionId = (typeof SECTIONS)[number]["id"];

type Metric = { label: string; value: string; color?: string };
type Bar = { label: string; value: number; display: string };
type Table = { columns: string[]; rows: string[][] };
type ReportSection = {
  id: SectionId;
  title: string;
  note: string;
  status: "loading" | "error" | "empty" | "ready";
  metrics: Metric[];
  bars: Bar[];
  tables: Table[];
};

const CVE_COLUMNS = ["CVE", "Риск", "CVSS", "EPSS", "KEV", "Вендор", "Продукт", "Опубликовано"];
const TASK_COLUMNS = ["Задача", "Статус", "Приоритет", "Исполнитель", "Срок", "Продукт", "Оценка"];

const REASON: Record<string, string> = {
  vckev_only: "VulnCheck KEV, не CISA",
  epss_spike: "Скачок EPSS",
  has_public_exploit: "Публичный эксплойт",
  has_poc: "PoC"
};

export function ReportsView() {
  const { query } = useVc();
  const [title, setTitle] = useState(defaultTitle);
  const [range, setRange] = useState<VcRange>(query.range);
  const [pinned, setPinned] = useState(false);
  const [on, setOn] = useState<Record<SectionId, boolean>>({
    summary: true,
    trend: true,
    exploit: true,
    vendors: true,
    cves: true,
    tasks: true
  });
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [kevOnly, setKevOnly] = useState(false);
  const [cveText, setCveText] = useState("");
  const [cveQueryText, setCveQueryText] = useState("");
  const [releasing, setReleasing] = useState(false);
  const [releaseError, setReleaseError] = useState<string | null>(null);

  useEffect(() => {
    if (!pinned) setRange(query.range);
  }, [pinned, query.range]);

  useEffect(() => {
    const timer = window.setTimeout(() => setCveQueryText(cveText.trim()), 300);
    return () => window.clearTimeout(timer);
  }, [cveText]);

  const summary = useCatalogSummary();
  const analytics = useAnalyticsSeries();
  const radar = useExploitRadar();
  const vendors = useVendorWindow(range === "7d" ? "7d" : "30d");
  const cveQuery = {
    q: cveQueryText,
    severity,
    tab: kevOnly ? ("kev" as const) : ("all" as const),
    vendor: "all" as const,
    product: "all" as const,
    status: "all" as const,
    kevAddedDays: null,
    publishedDays: null,
    exploitSignal: "all" as const
  };
  const cves = useCveList(cveQuery, { limit: CVE_LIMIT });
  const tasks = useVulnTasks();

  const cveTextPending = cveText.trim() !== cveQueryText;
  const cveBusy = cves.isLoading || cves.isFetching || cveTextPending;
  const catalogTotal = knownCatalogTotal(cveQuery, summary.data);
  const vendorDays = vendors.data ? Math.round(vendors.data.windowHours / 24) : Math.round(windowHoursFor(range) / 24);
  const windowLabel = RANGES.find((item) => item[0] === range)?.[1] ?? "Последние 30 дней";
  const coverage = coverageText(range, vendorDays);
  const contentKey = [
    title.trim(),
    range,
    ...SECTIONS.map((item) => (on[item.id] ? "1" : "0")),
    severity,
    kevOnly ? "kev" : "all",
    cveQueryText,
    summary.dataUpdatedAt,
    analytics.dataUpdatedAt,
    radar.dataUpdatedAt,
    vendors.dataUpdatedAt,
    cves.dataUpdatedAt,
    tasks.dataUpdatedAt
  ].join("|");
  const [issuedAt, setIssuedAt] = useState(() => new Date().toISOString());
  useEffect(() => {
    setIssuedAt(new Date().toISOString());
  }, [contentKey]);

  const cveFilterLabel = filterLabel(severity, kevOnly, cveQueryText);
  const model = useMemo(() => {
    const sections = assemble({
      on,
      range,
      vendorDays,
      cveFilterLabel,
      catalogTotal,
      summary: { data: summary.data, isLoading: summary.isLoading, isError: summary.isError },
      analytics: { data: analytics.data?.days, isLoading: analytics.isLoading, isError: analytics.isError },
      radar: { data: radar.data, isLoading: radar.isLoading, isError: radar.isError },
      vendors: { data: vendors.data, isLoading: vendors.isLoading, isError: vendors.isError },
      cves: {
        items: cveBusy ? null : (cves.data?.items ?? []),
        isLoading: cveBusy,
        isError: !cveBusy && cves.isError
      },
      tasks: {
        items: tasks.isLoading ? null : (tasks.data?.items ?? []),
        isLoading: tasks.isLoading,
        isError: tasks.isError && !tasks.isLoading
      }
    });
    const cveSection = sections.find((section) => section.id === "cves" && section.status === "ready");
    const cveTable = cveSection?.tables[0];
    return {
      title: title.trim() || defaultTitle(),
      issuedAt,
      issuedLabel: formatStamp(issuedAt),
      windowLabel,
      coverage,
      sections,
      cveCsv: cveTable ? toCsv(cveTable.columns, cveTable.rows) : null,
      cveCount: on.cves ? (cveBusy ? null : (cves.data?.items.length ?? 0)) : null
    };
  }, [
    on,
    range,
    vendorDays,
    cveFilterLabel,
    catalogTotal,
    summary.data,
    summary.isLoading,
    summary.isError,
    analytics.data?.days,
    analytics.isLoading,
    analytics.isError,
    radar.data,
    radar.isLoading,
    radar.isError,
    vendors.data,
    vendors.isLoading,
    vendors.isError,
    cveBusy,
    cves.data?.items,
    cves.isError,
    tasks.isLoading,
    tasks.data?.items,
    tasks.isError,
    title,
    issuedAt,
    windowLabel,
    coverage
  ]);

  const anyOn = SECTIONS.some((item) => on[item.id]);
  const waiting = model.sections.some((section) => section.status === "loading");
  const releaseDisabled = !anyOn || waiting || !title.trim();
  const included = model.sections.map((section) => section.title);

  function toggle(id: SectionId) {
    setOn((current) => ({ ...current, [id]: !current[id] }));
  }

  function releaseHtml() {
    if (releaseDisabled || releasing) return;
    const html = renderHtml(model, themeBlock());
    const stamp = fileStamp(model.issuedAt);
    saveBlob(new Blob([html], { type: "text/html;charset=utf-8" }), `vulncontrol-otchet-${stamp}.html`);
    if (model.cveCsv) {
      window.setTimeout(() => {
        saveBlob(new Blob([model.cveCsv!], { type: "text/csv;charset=utf-8" }), `vulncontrol-otchet-${stamp}-cve.csv`);
      }, 250);
    }
  }

  async function releasePdf() {
    if (releaseDisabled || releasing) return;
    setReleasing(true);
    setReleaseError(null);
    try {
      const res = await apiFetch("/api/stats/period-digest/pdf", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/pdf" },
        body: JSON.stringify(pdfPayload(model, on.cves ? narrativeNotes(cves.data?.items) : []))
      });
      if (!res.ok) {
        setReleaseError("PDF не выпущен. Предпросмотр по-прежнему из каталога.");
        return;
      }
      const blob = await res.blob();
      const filename =
        filenameFromDisposition(res.headers.get("content-disposition")) ??
        `vulncontrol-digest-${fileStamp(model.issuedAt)}.pdf`;
      saveBlob(blob, filename);
    } catch {
      setReleaseError("PDF не выпущен. Предпросмотр по-прежнему из каталога.");
    } finally {
      setReleasing(false);
    }
  }

  const [desk, setDesk] = useState<"builder" | "month">("builder");

  return (
    <div className="space-y-3">
      <div role="tablist" aria-label="Разделы отчётов" className="flex flex-wrap gap-2">
        <button type="button" role="tab" aria-selected={desk === "builder"} onClick={() => setDesk("builder")} className={cn("rounded-lg border px-3 py-1.5 text-[12px]", desk === "builder" ? "border-[var(--vc-primary)] bg-[color-mix(in_srgb,var(--vc-primary)_14%,transparent)]" : "border-[var(--vc-border)] text-[var(--vc-muted)]")}>Конструктор</button>
        <button type="button" role="tab" aria-selected={desk === "month"} onClick={() => setDesk("month")} className={cn("rounded-lg border px-3 py-1.5 text-[12px]", desk === "month" ? "border-[var(--vc-primary)] bg-[color-mix(in_srgb,var(--vc-primary)_14%,transparent)]" : "border-[var(--vc-border)] text-[var(--vc-muted)]")}>Ежемесячный дайджест</button>
      </div>
      {desk === "month" ? <MonthlyDigestPanel /> : (
    <div className="grid items-start gap-3 xl:grid-cols-[minmax(320px,390px)_minmax(0,1fr)]">
      <aside className="space-y-3 xl:sticky xl:top-0 xl:max-h-[calc(100dvh-4.75rem)] xl:overflow-y-auto xl:pr-1">
        <section className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-3">
          <Step n="1" title="Название" />
          <input
            value={title}
            onChange={(event) => setTitle(event.target.value)}
            aria-label="Название отчёта"
            className="mt-2 h-9 w-full rounded-lg border border-[var(--vc-border)] bg-[var(--vc-inset)] px-2.5 text-[13px] outline-none focus:border-[var(--vc-primary)]"
          />
        </section>

        <section className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-3">
          <Step n="2" title="За какой период" />
          <div className="mt-2 grid grid-cols-2 gap-1.5">
            {RANGES.map(([id, label]) => (
              <button
                key={id}
                type="button"
                onClick={() => {
                  setPinned(true);
                  setRange(id);
                }}
                className={cn(
                  "rounded-lg border px-2 py-1.5 text-left text-[12px]",
                  range === id
                    ? "border-[var(--vc-primary)] bg-[color-mix(in_srgb,var(--vc-primary)_14%,transparent)] text-[var(--vc-text)]"
                    : "border-[var(--vc-border)] text-[var(--vc-muted)] hover:bg-[var(--vc-hover)]"
                )}
              >
                {label}
              </button>
            ))}
          </div>
          <p className="mt-2 text-[11px] leading-relaxed text-[var(--vc-muted)]">
            {range === query.range ? "Совпадает с периодом в шапке." : `В шапке сейчас «${RANGES.find((item) => item[0] === query.range)?.[1] ?? ""}». Окно отчёта задаётся здесь.`}
          </p>
          <p className="mt-1 text-[11px] leading-relaxed text-[var(--vc-muted)]">{coverage}</p>
        </section>

        <section className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-3">
          <Step n="3" title="Что включено" />
          <div className="mt-2 space-y-1.5">
            {SECTIONS.map((item) => {
              const active = on[item.id];
              return (
                <button
                  key={item.id}
                  type="button"
                  aria-pressed={active}
                  onClick={() => toggle(item.id)}
                  className={cn(
                    "flex w-full items-start gap-2 rounded-lg border px-2.5 py-2 text-left",
                    active
                      ? "border-[var(--vc-primary)] bg-[color-mix(in_srgb,var(--vc-primary)_10%,transparent)]"
                      : "border-[var(--vc-border)] hover:bg-[var(--vc-hover)]"
                  )}
                >
                  <span
                    className={cn(
                      "mt-0.5 h-3.5 w-3.5 shrink-0 rounded-[4px] border",
                      active ? "border-[var(--vc-primary)] bg-[var(--vc-primary)]" : "border-[var(--vc-muted)]"
                    )}
                    aria-hidden
                  />
                  <span className="min-w-0">
                    <span className="block text-[12px] font-medium">{item.label}</span>
                    <span className="block text-[11px] leading-snug text-[var(--vc-muted)]">{item.hint}</span>
                  </span>
                </button>
              );
            })}
          </div>
        </section>

        {on.cves ? (
          <section className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-3">
            <Step n="4" title="Фильтр выборки CVE" />
            <div className="mt-2 space-y-2">
              <div className="block text-[11px] text-[var(--vc-muted)]">
                Уровень CVSS
                <VcSelect
                  ariaLabel="Уровень CVSS"
                  value={severity}
                  onChange={(value) => setSeverity(value as Severity | "all")}
                  options={SEVERITY.map(([id, label]) => [id, label])}
                  className="mt-1 h-9 w-full bg-[var(--vc-inset)]"
                />
              </div>
              <button
                type="button"
                aria-pressed={kevOnly}
                onClick={() => setKevOnly((value) => !value)}
                className={cn(
                  "flex w-full items-center gap-2 rounded-lg border px-2.5 py-2 text-left text-[12px]",
                  kevOnly ? "border-[var(--vc-kev)] text-[var(--vc-text)]" : "border-[var(--vc-border)] text-[var(--vc-muted)]"
                )}
              >
                <span className={cn("h-3.5 w-3.5 rounded-[4px] border", kevOnly ? "border-[var(--vc-kev)] bg-[var(--vc-kev)]" : "border-[var(--vc-muted)]")} />
                Только CISA KEV
              </button>
              <label className="block text-[11px] text-[var(--vc-muted)]">
                Текст
                <input
                  value={cveText}
                  onChange={(event) => setCveText(event.target.value)}
                  placeholder="CVE, продукт или описание"
                  className="mt-1 h-9 w-full rounded-lg border border-[var(--vc-border)] bg-[var(--vc-inset)] px-2.5 text-[12px] text-[var(--vc-text)] outline-none placeholder:text-[var(--vc-faint)]"
                />
              </label>
            </div>
          </section>
        ) : null}

        <section className="sticky bottom-0 rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-3">
          <Step n={on.cves ? "5" : "4"} title="Сколько попадёт в выпуск" />
          <p className="mt-2 text-[12px] leading-relaxed">
            {anyOn ? included.join(", ") : "Ни один раздел не включён."}
          </p>
          {on.cves ? (
            <p className="mt-1 text-[12px] text-[var(--vc-muted)]">
              {model.cveCount == null
                ? "Считаю строки выборки…"
                : `Строк CVE в выпуске: ${formatInt(model.cveCount)}. Запрошено не больше ${CVE_LIMIT}, это страница API, не весь каталог.`}
              {catalogTotal != null ? ` По фильтру в каталоге ${formatInt(catalogTotal)}.` : ""}
            </p>
          ) : null}
          <button
            type="button"
            disabled={releaseDisabled || releasing}
            onClick={() => void releasePdf()}
            className="mt-3 h-9 w-full rounded-lg bg-[var(--vc-primary)] text-[13px] font-medium text-white disabled:opacity-40"
          >
            {releasing ? "Выпускаю PDF…" : "Выпустить"}
          </button>
          <button
            type="button"
            disabled={releaseDisabled || releasing}
            onClick={releaseHtml}
            className="mt-2 h-8 w-full rounded-lg border border-[var(--vc-border)] text-[12px] text-[var(--vc-muted)] hover:bg-[var(--vc-hover)] disabled:opacity-40"
          >
            HTML и CSV
          </button>
          <p className="mt-2 text-[11px] leading-relaxed text-[var(--vc-muted)]">
            {waiting
              ? "Жду данные выбранных разделов."
              : "Основной файл — PDF-дайджест: цифры каталога и пояснение рядом. Рассказ пишет DeepSeek один раз при выпуске, если в настройках задан ключ дайджеста."}
            {on.cves ? " HTML и CSV — дополнительная выгрузка тех же строк." : ""}
          </p>
          {releaseError ? <p className="mt-1 text-[11px] text-[var(--vc-danger-text)]">{releaseError}</p> : null}
        </section>
      </aside>

      <article aria-label="Предпросмотр отчёта" className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-4">
        <p className="text-[10px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">Предпросмотр выпуска</p>
        <ReportSheet model={model} />
      </article>
    </div>
      )}
    </div>
  );
}


function Step({ n, title }: { n: string; title: string }) {
  return (
    <div className="flex items-baseline gap-2">
      <span className="text-[10px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">Шаг {n}</span>
      <h2 className="text-[13px] font-semibold">{title}</h2>
    </div>
  );
}

function ReportSheet({ model }: { model: ReportModel }) {
  return (
    <div>
      <h1 className="mt-1 text-[18px] font-semibold leading-tight">{model.title}</h1>
      <p className="mt-1 text-[12px] text-[var(--vc-muted)]">
        Сформирован {model.issuedLabel} · Окно: {model.windowLabel}
      </p>
      <p className="mt-2 text-[12px] leading-relaxed text-[var(--vc-muted)]">{model.coverage}</p>
      {model.sections.length === 0 ? (
        <p className="mt-4 text-[13px] text-[var(--vc-muted)]">Включите раздел слева — он появится здесь.</p>
      ) : (
        <div className="mt-4 space-y-4">
          {model.sections.map((section) => (
            <SectionBlock key={section.id} section={section} />
          ))}
        </div>
      )}
    </div>
  );
}

function SectionBlock({ section }: { section: ReportSection }) {
  return (
    <section className="border-t border-[var(--vc-border)] pt-3">
      <h2 className="text-[14px] font-semibold">{section.title}</h2>
      <p className="mt-1 text-[11px] leading-relaxed text-[var(--vc-muted)]">{section.note}</p>
      {section.status === "loading" ? <p className="mt-2 text-[12px] text-[var(--vc-muted)]">Загрузка…</p> : null}
      {section.status === "error" ? <p className="mt-2 text-[12px] text-[var(--vc-danger-text)]">Раздел не загрузился. В выпуске не будет выдуманных чисел.</p> : null}
      {section.status === "empty" ? <p className="mt-2 text-[12px] text-[var(--vc-muted)]">Нет строк.</p> : null}
      {section.status === "ready" ? (
        <>
          {section.metrics.length ? (
            <ul className="mt-2 divide-y divide-[var(--vc-border)]">
              {section.metrics.map((metric) => (
                <li key={metric.label} className="flex items-center justify-between gap-3 py-1.5 text-[12px]">
                  <span className="text-[var(--vc-muted)]">{metric.label}</span>
                  <span className="font-semibold tabular-nums" style={{ color: metric.color ?? "var(--vc-text)" }}>{metric.value}</span>
                </li>
              ))}
            </ul>
          ) : null}
          {section.bars.length ? <Bars rows={section.bars} /> : null}
          {section.tables.map((table) => (
            <div key={table.columns.join("|")} className="mt-2 overflow-x-auto">
              <table className="w-full min-w-[640px] text-left text-[12px]">
                <thead>
                  <tr className="text-[10px] uppercase tracking-wide text-[var(--vc-muted)]">
                    {table.columns.map((column) => (
                      <th key={column} className="px-2 py-1.5 font-medium">{column}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {table.rows.map((row, index) => (
                    <tr key={`${row[0]}-${index}`} className="border-t border-[var(--vc-border)]">
                      {row.map((cell, cellIndex) => (
                        <td key={`${table.columns[cellIndex]}-${cellIndex}`} className="px-2 py-1.5 align-top">{cell}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </>
      ) : null}
    </section>
  );
}

function Bars({ rows }: { rows: Bar[] }) {
  const max = Math.max(1, ...rows.map((row) => row.value));
  return (
    <ul className="mt-2 space-y-1">
      {rows.map((row) => (
        <li key={row.label} className="grid grid-cols-[3.2rem_minmax(0,1fr)_3.2rem] items-center gap-2 text-[11px]">
          <span className="tabular-nums text-[var(--vc-muted)]">{row.label}</span>
          <span className="h-1.5 overflow-hidden rounded-full bg-[var(--vc-track)]">
            <span className="block h-1.5 rounded-full bg-[var(--vc-primary)]" style={{ width: `${(row.value / max) * 100}%` }} />
          </span>
          <span className="text-right tabular-nums">{row.display}</span>
        </li>
      ))}
    </ul>
  );
}

type ReportModel = {
  title: string;
  issuedAt: string;
  issuedLabel: string;
  windowLabel: string;
  coverage: string;
  sections: ReportSection[];
  cveCsv: string | null;
  cveCount: number | null;
};

function assemble(input: {
  on: Record<SectionId, boolean>;
  range: VcRange;
  vendorDays: number;
  cveFilterLabel: string;
  catalogTotal: number | null;
  summary: { data?: CatalogSummary; isLoading: boolean; isError: boolean };
  analytics: { data?: AnalyticsDay[]; isLoading: boolean; isError: boolean };
  radar: { data?: ExploitRadar; isLoading: boolean; isError: boolean };
  vendors: { data?: VendorWindow; isLoading: boolean; isError: boolean };
  cves: { items: LiveCve[] | null; isLoading: boolean; isError: boolean };
  tasks: { items: LiveTask[] | null; isLoading: boolean; isError: boolean };
}): ReportSection[] {
  const sections: ReportSection[] = [];
  if (input.on.summary) sections.push(summarySection(input.summary));
  if (input.on.trend) sections.push(trendSection(input.analytics, input.range));
  if (input.on.exploit) sections.push(exploitSection(input.radar));
  if (input.on.vendors) sections.push(vendorSection(input.vendors, input.vendorDays));
  if (input.on.cves) sections.push(cveSection(input.cves, input.cveFilterLabel, input.catalogTotal));
  if (input.on.tasks) sections.push(taskSection(input.tasks));
  return sections;
}

function summarySection(source: { data?: CatalogSummary; isLoading: boolean; isError: boolean }): ReportSection {
  const base = section("summary", "Сводка каталога", "Снимок всего каталога. Выбранный период эти числа не режет. Публикации — за последние 24 часа.");
  if (!source.data) return { ...base, status: source.isError ? "error" : "loading" };
  const severity = source.data.severity;
  const metrics: Metric[] = [
    { label: "Всего CVE", value: formatInt(source.data.totalCves) },
    { label: "CVSS ≥ 9", value: formatInt(severity?.critical), color: "var(--vc-critical)" },
    { label: "CVSS 7–8.9", value: formatInt(severity?.high), color: "var(--vc-high)" },
    { label: "CVSS 4–6.9", value: formatInt(severity?.medium), color: "var(--vc-medium)" },
    { label: "CVSS < 4", value: formatInt(severity?.low), color: "var(--vc-low)" },
    { label: "Без CVSS", value: formatInt(severity?.unscored), color: "var(--vc-slate)" },
    { label: "CISA KEV", value: formatInt(source.data.kevCount), color: "var(--vc-kev)" },
    { label: "EPSS ≥ 0.7", value: formatInt(source.data.highEpssCount), color: "var(--vc-epss)" }
  ];
  if (typeof source.data.cvesPublishedLast24hCount === "number") {
    metrics.push({ label: "Публикации за 24 часа", value: formatInt(source.data.cvesPublishedLast24hCount) });
  }
  return { ...base, status: "ready", metrics };
}

function trendSection(source: { data?: AnalyticsDay[]; isLoading: boolean; isError: boolean }, range: VcRange): ReportSection {
  const days = range === "7d" ? (source.data ?? []).slice(-7) : (source.data ?? []);
  const span = days.length ? `${dayLabel(days[0]!.day)}–${dayLabel(days[days.length - 1]!.day)}` : "";
  const limitNote = range === "7d"
    ? "Последние 7 дней ряда аналитики."
    : "Ряд аналитики покрывает 30 дней. Более длинное окно API не отдаёт.";
  const base = section("trend", "Тренд публикаций", `${limitNote} Суммы ниже — по показанным дням, без сравнения с прошлым окном.${span ? ` Дни: ${span}.` : ""}`);
  if (!source.data) return { ...base, status: source.isError ? "error" : "loading" };
  if (!days.length) return { ...base, status: "empty" };
  const published = days.reduce((sum, day) => sum + day.published, 0);
  const critical = days.reduce((sum, day) => sum + day.critical, 0);
  const kev = days.reduce((sum, day) => sum + day.kev, 0);
  return {
    ...base,
    status: "ready",
    metrics: [
      { label: "Публикации", value: formatInt(published), color: "var(--vc-primary)" },
      { label: "CVSS ≥ 9", value: formatInt(critical), color: "var(--vc-critical)" },
      { label: "Новые CISA KEV", value: formatInt(kev), color: "var(--vc-kev)" }
    ],
    bars: days.map((day) => ({ label: dayLabel(day.day), value: day.published, display: formatInt(day.published) }))
  };
}

function exploitSection(source: { data?: ExploitRadar; isLoading: boolean; isError: boolean }): ReportSection {
  const base = section("exploit", "Exploit intel", "Снимок на момент выпуска. Счётчики пересекаются и не являются долями одного целого. «Новые VulnCheck KEV» — за 7 дней, остальные — по накопленному intel.");
  if (!source.data) return { ...base, status: source.isError ? "error" : "loading" };
  const data = source.data;
  const highlights = highlightRows(data);
  return {
    ...base,
    status: "ready",
    metrics: [
      { label: "Публичный эксплойт", value: formatInt(data.withPublicExploit) },
      { label: "Есть PoC", value: formatInt(data.withPoc) },
      { label: "Скачок EPSS", value: formatInt(data.epssSpikes) },
      { label: "VulnCheck KEV, не CISA", value: formatInt(data.vckevOnly) },
      { label: "Новые VulnCheck KEV, 7 дней", value: formatInt(data.newVckev7d) },
      { label: "Строк intel", value: formatInt(data.intelRows) }
    ],
    tables: highlights.length
      ? [{ columns: ["CVE", "CVSS", "EPSS", "Сигнал"], rows: highlights }]
      : []
  };
}

function vendorSection(source: { data?: VendorWindow; isLoading: boolean; isError: boolean }, vendorDays: number): ReportSection {
  const base = section("vendors", "Вендоры и продукты", `Публикации за ${vendorDays} дн. Это окно ответа API, не длиннее 30 дней.`);
  if (!source.data) return { ...base, status: source.isError ? "error" : "loading" };
  const data = source.data;
  const vendors = data.vendors.filter((row) => row.vendor);
  const products = data.products.filter((row) => row.product);
  if (!vendors.length && !products.length) return { ...base, status: "empty" };
  return {
    ...base,
    status: "ready",
    metrics: [{ label: "CVE в окне", value: formatInt(data.sampledCves) }],
    tables: [
      ...(vendors.length ? [{ columns: ["Вендор", "CVE"], rows: vendors.map((row) => [row.vendor, formatInt(row.count)]) }] : []),
      ...(products.length ? [{ columns: ["Продукт", "Вендор", "CVE"], rows: products.map((row) => [row.product, row.vendor || "—", formatInt(row.count)]) }] : [])
    ]
  };
}

function cveSection(
  source: { items: LiveCve[] | null; isLoading: boolean; isError: boolean },
  filter: string,
  catalogTotal: number | null
): ReportSection {
  const catalog = catalogTotal == null ? "" : ` По этому фильтру в каталоге ${formatInt(catalogTotal)}.`;
  const base = section(
    "cves",
    "Выборка CVE",
    `${filter} В выпуске только строки этой страницы API (не больше ${CVE_LIMIT}), без отсечения по дате публикации.${catalog}`
  );
  if (source.isLoading || source.items == null) return { ...base, status: "loading" };
  if (source.isError) return { ...base, status: "error" };
  if (!source.items.length) return { ...base, status: "empty", note: `${base.note} Ответ API пуст.` };
  return {
    ...base,
    status: "ready",
    note: `${base.note} Строк в выпуске: ${formatInt(source.items.length)}.`,
    tables: [{ columns: CVE_COLUMNS, rows: source.items.map(cveCells) }]
  };
}

function taskSection(source: { items: LiveTask[] | null; isLoading: boolean; isError: boolean }): ReportSection {
  const base = section("tasks", "Задачи", `Список рабочего стола. Период отчёта его не фильтрует. В ответе API не больше ${TASK_LIMIT} строк. Статусы в отчёте только для чтения.`);
  if (source.isLoading || source.items == null) return { ...base, status: "loading" };
  if (source.isError) return { ...base, status: "error" };
  if (!source.items.length) return { ...base, status: "empty" };
  return {
    ...base,
    status: "ready",
    note: `${base.note} Строк в выпуске: ${formatInt(source.items.length)}.`,
    tables: [{ columns: TASK_COLUMNS, rows: source.items.map(taskCells) }]
  };
}

function section(id: SectionId, title: string, note: string): ReportSection {
  return { id, title, note, status: "ready", metrics: [], bars: [], tables: [] };
}

function cveCells(row: LiveCve) {
  return [
    row.cve_id,
    row.risk_score == null ? "—" : formatInt(row.risk_score),
    row.cvss_base == null ? "—" : formatScore(row.cvss_base),
    row.epss == null ? "—" : formatScore(row.epss),
    row.exploit_known ? "KEV" : "—",
    row.vp_vendor || "—",
    row.vp_product || "—",
    formatDate(row.published_at)
  ];
}

function taskCells(task: LiveTask) {
  const priority = priorityLabel(task.priority_local);
  const product = [task.product_display, task.vendor_display].filter(Boolean).join(" · ");
  return [
    task.title || "—",
    taskStatusLabel(task.status),
    priority ?? "—",
    task.owner || "—",
    formatDate(task.due_date),
    product || "—",
    task.score_final == null || !Number.isFinite(task.score_final) ? "—" : formatInt(task.score_final)
  ];
}

function highlightRows(data: ExploitRadar) {
  const raw = (data as ExploitRadar & { highlights?: unknown }).highlights;
  if (!Array.isArray(raw)) return [];
  const rows: string[][] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const row = item as Record<string, unknown>;
    if (typeof row.cve_id !== "string" || !row.cve_id) continue;
    const reason = typeof row.radar_reason === "string" ? (REASON[row.radar_reason] ?? row.radar_reason) : "—";
    rows.push([
      row.cve_id,
      typeof row.cvss_base === "number" ? formatScore(row.cvss_base) : "—",
      typeof row.epss === "number" ? formatScore(row.epss) : "—",
      reason || "—"
    ]);
  }
  return rows;
}

function priorityLabel(priority: string | null) {
  const value = String(priority || "").toLowerCase();
  if (value === "critical") return "Критический";
  if (value === "high") return "Высокий";
  if (value === "medium") return "Средний";
  if (value === "low") return "Низкий";
  return null;
}

function filterLabel(severity: Severity | "all", kevOnly: boolean, text: string) {
  const level = SEVERITY.find((item) => item[0] === severity)?.[1] ?? "Все уровни CVSS";
  const kev = kevOnly ? "только CISA KEV" : "KEV не обязателен";
  const needle = text ? `, текст «${text}»` : "";
  return `Фильтр: ${level}, ${kev}${needle}.`;
}

function coverageText(range: VcRange, vendorDays: number) {
  const trend = range === "7d"
    ? "Тренд публикаций — последние 7 дней ряда аналитики."
    : "Тренд публикаций — ряд аналитики за 30 дней" + (range === "30d" ? "." : "; окно шире API не отдаёт.");
  const vendors = range === "90d" || range === "all"
    ? `Вендоры и продукты — публикации за ${vendorDays} дн., потолок API 30 дней.`
    : `Вендоры и продукты — публикации за ${vendorDays} дн.`;
  return `Сводка каталога и exploit intel — снимок всего каталога. ${trend} ${vendors} Выборка CVE — по фильтрам конструктора, не по дате публикации. Задачи — список рабочего стола.`;
}

function defaultTitle(now = new Date()) {
  const day = new Intl.DateTimeFormat("ru-RU", { day: "numeric", month: "long", year: "numeric" }).format(now);
  return `Отчёт VulnControl от ${day}`;
}

function formatStamp(iso: string) {
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

function fileStamp(iso: string) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "report";
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${date.getFullYear()}-${month}-${day}`;
}

function dayLabel(day: string) {
  const [, month, date] = day.split("-");
  if (!month || !date) return day;
  return `${date}.${month}`;
}

function formatScore(value: number) {
  return new Intl.NumberFormat("ru-RU", { maximumFractionDigits: 4 }).format(value);
}

function renderHtml(model: ReportModel, theme: string) {
  const sections = model.sections.map(sectionHtml).join("");
  return `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(model.title)}</title>
<style>
${theme}
body{margin:0;background:var(--vc-bg);color:var(--vc-text);font:13px/1.45 ui-sans-serif,system-ui,sans-serif}
main{max-width:920px;margin:24px auto;padding:20px 22px;background:var(--vc-surface);border:1px solid var(--vc-border);border-radius:12px}
h1{margin:8px 0 0;font-size:20px}
h2{margin:0;font-size:15px}
.kicker{margin:0;font-size:10px;letter-spacing:.04em;text-transform:uppercase;color:var(--vc-muted)}
.meta,.note{color:var(--vc-muted);font-size:12px}
section{margin-top:18px;padding-top:12px;border-top:1px solid var(--vc-border)}
ul{list-style:none;margin:8px 0 0;padding:0}
li.metric{display:flex;justify-content:space-between;gap:12px;padding:6px 0;border-bottom:1px solid var(--vc-border)}
li.metric span{color:var(--vc-muted)}
li.metric b{font-variant-numeric:tabular-nums}
.bar{display:grid;grid-template-columns:3.2rem 1fr 3.2rem;gap:8px;align-items:center;margin-top:4px;font-size:11px}
.track{height:6px;border-radius:999px;background:var(--vc-track);overflow:hidden}
.fill{display:block;height:6px;background:var(--vc-primary)}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:12px}
th{text-align:left;font-size:10px;letter-spacing:.04em;text-transform:uppercase;color:var(--vc-muted);padding:6px}
td{padding:6px;border-top:1px solid var(--vc-border);vertical-align:top}
.empty{color:var(--vc-muted)}
.fail{color:var(--vc-danger-text,#ff8a9a)}
</style>
</head>
<body>
<main>
<p class="kicker">VulnControl · выпуск отчёта</p>
<h1>${esc(model.title)}</h1>
<p class="meta">Сформирован ${esc(model.issuedLabel)} · Окно: ${esc(model.windowLabel)}</p>
<p class="note">${esc(model.coverage)}</p>
${sections || `<p class="empty">Разделы не выбраны.</p>`}
</main>
</body>
</html>`;
}

function sectionHtml(section: ReportSection) {
  const head = `<section><h2>${esc(section.title)}</h2><p class="note">${esc(section.note)}</p>`;
  if (section.status === "loading") return `${head}<p class="empty">Загрузка…</p></section>`;
  if (section.status === "error") return `${head}<p class="fail">Раздел не загрузился. В выпуске не будет выдуманных чисел.</p></section>`;
  if (section.status === "empty") return `${head}<p class="empty">Нет строк.</p></section>`;
  const metrics = section.metrics.length
    ? `<ul>${section.metrics.map((metric) => `<li class="metric"><span>${esc(metric.label)}</span><b${metric.color ? ` style="color:${esc(metric.color)}"` : ""}>${esc(metric.value)}</b></li>`).join("")}</ul>`
    : "";
  const max = Math.max(1, ...section.bars.map((row) => row.value));
  const bars = section.bars.length
    ? section.bars.map((row) => `<div class="bar"><span>${esc(row.label)}</span><span class="track"><span class="fill" style="width:${(row.value / max) * 100}%"></span></span><b>${esc(row.display)}</b></div>`).join("")
    : "";
  const tables = section.tables.map((table) => {
    const headCells = table.columns.map((column) => `<th>${esc(column)}</th>`).join("");
    const body = table.rows.map((row) => `<tr>${row.map((cell) => `<td>${esc(cell)}</td>`).join("")}</tr>`).join("");
    return `<table><thead><tr>${headCells}</tr></thead><tbody>${body}</tbody></table>`;
  }).join("");
  return `${head}${metrics}${bars}${tables}</section>`;
}

function themeBlock() {
  const root = document.querySelector(".vc-shell") ?? document.documentElement;
  const style = getComputedStyle(root);
  const keys = [
    "--vc-bg", "--vc-surface", "--vc-text", "--vc-muted", "--vc-border", "--vc-critical",
    "--vc-high", "--vc-medium", "--vc-low", "--vc-kev", "--vc-primary", "--vc-inset",
    "--vc-success", "--vc-slate", "--vc-track", "--vc-epss", "--vc-danger-text"
  ];
  const decls = keys.map((key) => `${key}:${style.getPropertyValue(key).trim()}`).filter((part) => !part.endsWith(":")).join(";");
  return `:root{${decls}}`;
}

function toCsv(columns: string[], rows: string[][]) {
  const lines = [columns, ...rows].map((row) => row.map(csvCell).join(","));
  return `\uFEFF${lines.join("\n")}`;
}

function csvCell(value: string) {
  return `"${value.replaceAll('"', '""')}"`;
}

function esc(value: string) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function narrativeNotes(items: LiveCve[] | undefined) {
  if (!items) return [];
  const notes: Array<{ cveId: string; description: string; vendor: string; product: string; cvss: string; epss: string; kev: string }> = [];
  for (const row of items) {
    if (notes.length >= 8) break;
    if (!/^CVE-\d{4}-\d{4,7}$/i.test(row.cve_id)) continue;
    const description = (row.short_ru || row.short_description || "").replace(/\s+/g, " ").trim().slice(0, 420);
    notes.push({
      cveId: row.cve_id,
      description,
      vendor: row.vp_vendor || "",
      product: row.vp_product || "",
      cvss: row.cvss_base == null ? "" : formatScore(row.cvss_base),
      epss: row.epss == null ? "" : formatScore(row.epss),
      kev: row.exploit_known ? "KEV" : ""
    });
  }
  return notes;
}

function pdfPayload(model: ReportModel, cveNotes: Array<{ cveId: string; description: string }>) {
  return {
    title: model.title,
    windowLabel: model.windowLabel,
    issuedAt: model.issuedAt,
    issuedLabel: model.issuedLabel,
    coverage: model.coverage,
    cveNotes,
    sections: model.sections.map((section) => ({
      id: section.id,
      title: section.title,
      note: section.note,
      status: section.status,
      metrics: section.metrics.map((metric) => ({ label: metric.label, value: metric.value })),
      bars: section.bars.map((bar) => ({ label: bar.label, display: bar.display })),
      tables: section.tables
    }))
  };
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

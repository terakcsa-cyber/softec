"use client";

import { useMemo, useState } from "react";
import {
  ChevronDown,
  Clock,
  Crosshair,
  Filter,
  Flame,
  Library,
  Loader2,
  RefreshCw,
  ShieldAlert,
  Sparkles
} from "lucide-react";
import { cn } from "../ui/cn";
import { AiSummaryPanel } from "./ai-summary-panel";
import { BduCard, type BduListItem } from "./bdu-card";
import { CveCard } from "./cve-card";
import { ExploitIntelBadges } from "./exploit-intel-badges";
import { VulnClassBadge } from "./vuln-class-badge";
import { VulnClassFilter } from "./vuln-class-filter";
import { VulnSearchBar, type VulnSearchHints } from "./vuln-search-bar";
import { EXPLOIT_RADAR_FILTER_LABELS, type ExploitRadarFilter } from "@/lib/exploit-intel-client";
import type { VulnClassId } from "@/lib/vuln-class";

export type VulnModuleView = "critical_v2" | "critical" | "latest" | "last24h" | "kev" | "exploit" | "all";
export type VulnModuleSort = "rank" | "fresh" | "risk" | "epss" | "cvss" | "exploit" | "priority";
export type VulnPreviewRef = { kind: "cve" | "bdu"; id: string };

export type VulnCveListItem = {
  cve_id: string;
  published_at: string | null;
  modified_at: string | null;
  risk_score: number | null;
  epss?: number | null;
  cvss_base?: number | null;
  vp_vendor?: string | null;
  vp_product?: string | null;
  short_description?: string | null;
  short_ru?: string | null;
  exploit_known?: boolean;
  vuln_class?: string | null;
  ai_ready?: boolean;
  bdu_ids?: string[] | null;
  task_open_count?: number | null;
  vulncheck_kev?: boolean;
  vckev_only?: boolean;
  has_poc?: boolean;
  has_public_exploit?: boolean;
  epss_spike?: boolean;
  epss_delta_7d?: number | null;
};

export type VulnListEntry =
  | { kind: "cve"; item: VulnCveListItem }
  | { kind: "bdu"; item: BduListItem };

const NAV: Array<{
  id: Exclude<VulnModuleView, "critical">;
  label: string;
  description: string;
  icon: typeof ShieldAlert;
}> = [
  { id: "critical_v2", label: "Критичные", description: "Приоритет и риск", icon: ShieldAlert },
  { id: "last24h", label: "За 24 часа", description: "Свежие публикации", icon: Clock },
  { id: "latest", label: "Свежие", description: "По дате NVD", icon: Sparkles },
  { id: "kev", label: "KEV", description: "Известная эксплуатация", icon: Flame },
  { id: "exploit", label: "Exploit intel", description: "PoC, spike, VulnCheck", icon: Crosshair },
  { id: "all", label: "Каталог", description: "Поиск по всей базе", icon: Library }
];

export function vulnPreviewKey(ref: VulnPreviewRef): string {
  return `${ref.kind}:${ref.id}`;
}

export function vulnPreviewFromEntry(entry: VulnListEntry): VulnPreviewRef {
  return entry.kind === "cve" ? { kind: "cve", id: entry.item.cve_id } : { kind: "bdu", id: entry.item.bduId };
}

export function findVulnPreviewIndex(entries: VulnListEntry[], ref: VulnPreviewRef | null): number {
  if (!ref) return -1;
  return entries.findIndex((entry) => {
    const id = entry.kind === "cve" ? entry.item.cve_id : entry.item.bduId;
    return entry.kind === ref.kind && id === ref.id;
  });
}

export function VulnsModulePanel({
  view,
  onViewChange,
  q,
  onQChange,
  sort,
  onSortChange,
  kevOnly,
  onKevOnlyChange,
  attentionOnly,
  onAttentionOnlyChange,
  minCvss,
  onMinCvssChange,
  minEpss,
  onMinEpssChange,
  vulnClasses,
  onVulnClassesChange,
  vendorFilter,
  productFilter,
  onClearVendorProduct,
  exploitFilter,
  onClearExploitFilter,
  hints,
  hintsLoading,
  listLoading,
  refreshing,
  onRefresh,
  bulkMode,
  onToggleBulk,
  onExportCsv,
  onOpenSavedViews,
  entries,
  qDebounced,
  activePreview,
  onSelectPreview,
  onOpenFullCard,
  selectedIds,
  onToggleChecked,
  previewData,
  previewLoading,
  previewError
}: {
  view: VulnModuleView;
  onViewChange: (view: VulnModuleView) => void;
  q: string;
  onQChange: (q: string) => void;
  sort: VulnModuleSort;
  onSortChange: (sort: VulnModuleSort) => void;
  kevOnly: boolean;
  onKevOnlyChange: (next: boolean) => void;
  attentionOnly: boolean;
  onAttentionOnlyChange: (next: boolean) => void;
  minCvss: number | null;
  onMinCvssChange: (next: number | null) => void;
  minEpss: number | null;
  onMinEpssChange: (next: number | null) => void;
  vulnClasses: VulnClassId[];
  onVulnClassesChange: (next: VulnClassId[]) => void;
  vendorFilter: string | null;
  productFilter: string | null;
  onClearVendorProduct: () => void;
  exploitFilter: ExploitRadarFilter | null;
  onClearExploitFilter: () => void;
  hints: VulnSearchHints;
  hintsLoading: boolean;
  listLoading: boolean;
  refreshing: boolean;
  onRefresh: () => void;
  bulkMode: boolean;
  onToggleBulk: () => void;
  onExportCsv: () => void;
  onOpenSavedViews: () => void;
  entries: VulnListEntry[];
  qDebounced: string;
  activePreview: VulnPreviewRef | null;
  onSelectPreview: (ref: VulnPreviewRef) => void;
  onOpenFullCard: (ref: VulnPreviewRef) => void;
  selectedIds: Record<string, true>;
  onToggleChecked: (cveId: string, next: boolean) => void;
  previewData: unknown | null;
  previewLoading: boolean;
  previewError: boolean;
}) {
  const [filtersOpen, setFiltersOpen] = useState(false);
  const activeNav = NAV.find((item) => item.id === view || (item.id === "critical_v2" && view === "critical")) ?? NAV[0]!;
  const extraFilterCount =
    (minCvss != null ? 1 : 0) +
    (minEpss != null ? 1 : 0) +
    (vulnClasses.length > 0 ? 1 : 0) +
    (vendorFilter ? 1 : 0) +
    (productFilter ? 1 : 0) +
    (exploitFilter ? 1 : 0);

  const inspectorEntry = useMemo(() => {
    if (!activePreview) return null;
    return (
      entries.find((entry) => {
        const id = entry.kind === "cve" ? entry.item.cve_id : entry.item.bduId;
        return entry.kind === activePreview.kind && id === activePreview.id;
      }) ?? null
    );
  }, [activePreview, entries]);

  return (
    <div className="glass flex flex-col rounded-2xl lg:sticky lg:top-4 lg:max-h-[calc(100vh-5.5rem)] lg:overflow-hidden">
      <div className="shrink-0 border-b border-slate-200 px-5 py-4 dark:border-border sm:px-6">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="text-sm font-semibold tracking-tight text-fg/95">Уязвимости</div>
            <p className="mt-1 text-xs text-muted">
              Раздел слева, список в центре. Клик открывает инспектор справа, Enter или «Открыть» — полную карточку.
            </p>
          </div>
          <button
            type="button"
            title="Обновить список"
            onClick={onRefresh}
            disabled={refreshing}
            className={cn(
              "inline-flex shrink-0 items-center gap-1.5 rounded-xl border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-[11px] text-fg/90",
              "hover:bg-slate-100 dark:border-border dark:bg-black/20 dark:hover:bg-black/35",
              refreshing && "cursor-wait opacity-80"
            )}
          >
            {refreshing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
            Обновить
          </button>
        </div>
      </div>

      <div className="grid min-h-0 flex-1 lg:grid-cols-[200px_minmax(0,1fr)_minmax(300px,380px)] lg:overflow-hidden">
        <nav
          aria-label="Разделы уязвимостей"
          className="border-b border-slate-200 p-3 dark:border-border lg:border-b-0 lg:border-r"
        >
          <div className="flex gap-1 overflow-x-auto pb-1 lg:flex-col lg:overflow-visible lg:pb-0">
            {NAV.map((item) => {
              const Icon = item.icon;
              const selected = item.id === activeNav.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => onViewChange(item.id)}
                  className={cn(
                    "flex min-w-[9.5rem] shrink-0 items-start gap-2.5 rounded-xl border px-3 py-2.5 text-left transition lg:min-w-0 lg:w-full",
                    selected
                      ? "border-accent/35 bg-accent/10 text-fg/95"
                      : "border-transparent text-fg/80 hover:border-slate-200 hover:bg-slate-50 dark:hover:border-border dark:hover:bg-white/[0.04]"
                  )}
                >
                  <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", selected ? "text-accent" : "text-muted")} aria-hidden />
                  <span className="min-w-0">
                    <span className="block text-[12px] font-medium leading-tight">{item.label}</span>
                    <span className="mt-0.5 hidden text-[10px] leading-snug text-muted lg:block">{item.description}</span>
                  </span>
                </button>
              );
            })}
          </div>
          <p className="mt-3 hidden px-1 text-[10px] leading-relaxed text-muted lg:block">
            ↑↓ листать список, Enter — карточка.
          </p>
        </nav>

        <section className="flex min-h-[28rem] min-w-0 flex-col border-b border-slate-200 p-4 dark:border-border lg:min-h-0 lg:border-b-0 lg:border-r">
          <div className="mb-3 shrink-0">
            <h2 className="text-sm font-medium text-fg/95">{activeNav.label}</h2>
            <p className="mt-0.5 text-[11px] text-muted">
              {listLoading ? "Загрузка…" : `${entries.length} записей`}
              {qDebounced.trim() ? ` · поиск «${qDebounced.trim()}»` : null}
            </p>
          </div>

          <VulnSearchBar
            value={q}
            onChange={onQChange}
            hints={hints}
            hintsLoading={hintsLoading}
            listLoading={listLoading}
            onClearFilters={() => {
              onClearVendorProduct();
              onVulnClassesChange([]);
            }}
          />

          <div className="mb-3 flex flex-wrap items-center gap-2">
            <select
              value={sort}
              onChange={(e) => onSortChange(e.target.value as VulnModuleSort)}
              className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-xs text-fg/90 dark:border-border dark:bg-black/20"
              title="Сортировка"
            >
              <option value="rank">Ранг</option>
              <option value="priority">Приоритет</option>
              <option value="risk">Риск</option>
              <option value="epss">EPSS</option>
              <option value="cvss">CVSS</option>
              <option value="exploit">Exploit spike</option>
              <option value="fresh">Свежесть</option>
            </select>
            <button
              type="button"
              onClick={() => {
                const next = !kevOnly;
                onKevOnlyChange(next);
                if (next) onViewChange("kev");
              }}
              className={cn(
                "rounded-full border px-2 py-0.5 text-[11px]",
                kevOnly
                  ? "border-danger/30 bg-danger/15 text-danger"
                  : "border-slate-200 bg-slate-50 text-muted dark:border-border dark:bg-black/20"
              )}
              title="Только KEV"
            >
              KEV
            </button>
            <button
              type="button"
              onClick={() => onAttentionOnlyChange(!attentionOnly)}
              className={cn(
                "rounded-lg border px-2 py-1 text-xs",
                attentionOnly
                  ? "border-warn/30 bg-warn/15 text-warn"
                  : "border-slate-200 bg-slate-50 text-fg/90 hover:bg-slate-200/80 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
              )}
              title="Только высокий/критический приоритет"
            >
              Внимание
            </button>
            <button
              type="button"
              onClick={onToggleBulk}
              className={cn(
                "rounded-lg border px-2 py-1 text-xs",
                bulkMode
                  ? "border-accent/30 bg-accent/10 text-fg/90"
                  : "border-slate-200 bg-slate-50 text-fg/90 hover:bg-slate-200/80 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
              )}
            >
              Массово
            </button>
            <button
              type="button"
              onClick={onExportCsv}
              className="rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-xs text-fg/90 hover:bg-slate-200/80 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
            >
              CSV
            </button>
            <button
              type="button"
              onClick={onOpenSavedViews}
              className="rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-xs text-fg/90 hover:bg-slate-200/80 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
            >
              Виды
            </button>
            <button
              type="button"
              onClick={() => setFiltersOpen((v) => !v)}
              className={cn(
                "inline-flex items-center gap-1 rounded-lg border px-2 py-1 text-xs",
                filtersOpen || extraFilterCount > 0
                  ? "border-accent/30 bg-accent/10 text-fg/90"
                  : "border-slate-200 bg-slate-50 text-fg/90 hover:bg-slate-200/80 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
              )}
            >
              <Filter className="h-3 w-3" />
              Фильтры
              {extraFilterCount > 0 ? (
                <span className="rounded-full bg-accent/20 px-1.5 text-[10px] tabular-nums">{extraFilterCount}</span>
              ) : null}
              <ChevronDown className={cn("h-3 w-3 transition", filtersOpen && "rotate-180")} />
            </button>
            {exploitFilter ? (
              <button
                type="button"
                onClick={onClearExploitFilter}
                className="rounded-full border border-accent/35 bg-accent/10 px-2 py-0.5 text-[11px] text-accent"
                title={EXPLOIT_RADAR_FILTER_LABELS[exploitFilter].hint}
              >
                {EXPLOIT_RADAR_FILTER_LABELS[exploitFilter].title} ×
              </button>
            ) : null}
          </div>

          {filtersOpen ? (
            <div className="mb-3 space-y-2 rounded-xl border border-slate-200/90 bg-slate-50/80 p-3 dark:border-white/[0.06] dark:bg-black/15">
              <div className="flex flex-wrap items-center gap-2 text-[11px]">
                <div className="flex items-center gap-1 rounded-full border border-slate-200 bg-white px-2 py-1 dark:border-border dark:bg-black/20">
                  <span className="text-muted">CVSS</span>
                  {(
                    [
                      [null, "выкл"],
                      [8, "≥8"],
                      [9, "≥9"]
                    ] as const
                  ).map(([value, label]) => (
                    <button
                      key={label}
                      type="button"
                      onClick={() => onMinCvssChange(value)}
                      className={cn(
                        "rounded-full px-2 py-0.5",
                        minCvss === value ? "bg-accent/15 text-fg/90" : "hover:bg-slate-200/80 dark:hover:bg-white/5"
                      )}
                    >
                      {label}
                    </button>
                  ))}
                </div>
                <div className="flex items-center gap-1 rounded-full border border-slate-200 bg-white px-2 py-1 dark:border-border dark:bg-black/20">
                  <span className="text-muted">EPSS</span>
                  {(
                    [
                      [null, "выкл"],
                      [0.2, "≥0.20"],
                      [0.5, "≥0.50"]
                    ] as const
                  ).map(([value, label]) => (
                    <button
                      key={label}
                      type="button"
                      onClick={() => onMinEpssChange(value)}
                      className={cn(
                        "rounded-full px-2 py-0.5",
                        minEpss === value ? "bg-accent/15 text-fg/90" : "hover:bg-slate-200/80 dark:hover:bg-white/5"
                      )}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
              <VulnClassFilter value={vulnClasses} onChange={onVulnClassesChange} compact />
              {vendorFilter || productFilter ? (
                <div className="flex flex-wrap items-center gap-2 text-[11px]">
                  {vendorFilter ? (
                    <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 text-fg/85 dark:border-white/10 dark:bg-white/5">
                      вендор <span className="font-medium">{vendorFilter}</span>
                    </span>
                  ) : null}
                  {productFilter ? (
                    <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 text-fg/85 dark:border-white/10 dark:bg-white/5">
                      продукт <span className="font-medium">{productFilter}</span>
                    </span>
                  ) : null}
                  <button
                    type="button"
                    className="rounded-full border border-slate-200 bg-slate-100 px-2 py-0.5 text-fg/80 hover:bg-slate-200/80 dark:border-white/10 dark:bg-black/20"
                    onClick={onClearVendorProduct}
                  >
                    Сбросить
                  </button>
                </div>
              ) : null}
            </div>
          ) : extraFilterCount > 0 ? (
            <div className="mb-3 flex flex-wrap items-center gap-1.5 text-[11px]">
              {minCvss != null ? (
                <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 dark:border-white/10 dark:bg-white/5">
                  CVSS ≥{minCvss}
                </span>
              ) : null}
              {minEpss != null ? (
                <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 dark:border-white/10 dark:bg-white/5">
                  EPSS ≥{minEpss}
                </span>
              ) : null}
              {vulnClasses.length > 0 ? (
                <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 dark:border-white/10 dark:bg-white/5">
                  класс: {vulnClasses.length}
                </span>
              ) : null}
              {vendorFilter ? (
                <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 dark:border-white/10 dark:bg-white/5">
                  {vendorFilter}
                </span>
              ) : null}
              {productFilter ? (
                <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 dark:border-white/10 dark:bg-white/5">
                  {productFilter}
                </span>
              ) : null}
            </div>
          ) : null}

          <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain pr-0.5">
            <div className="space-y-2 pb-1">
              {entries.map((entry) => {
                const previewRef = vulnPreviewFromEntry(entry);
                const previewActive =
                  activePreview != null &&
                  activePreview.kind === previewRef.kind &&
                  activePreview.id === previewRef.id;
                return entry.kind === "bdu" ? (
                  <div
                    key={`bdu-${entry.item.bduId}`}
                    data-vuln-preview-key={vulnPreviewKey(previewRef)}
                    onDoubleClick={() => onOpenFullCard(previewRef)}
                  >
                    <BduCard
                      item={entry.item}
                      selected={false}
                      previewActive={previewActive}
                      onSelect={() => onSelectPreview(previewRef)}
                    />
                  </div>
                ) : (
                  <div
                    key={entry.item.cve_id}
                    data-vuln-preview-key={vulnPreviewKey(previewRef)}
                    onDoubleClick={() => onOpenFullCard(previewRef)}
                  >
                    <CveCard
                      item={entry.item}
                      selected={false}
                      previewActive={previewActive}
                      onSelect={() => onSelectPreview(previewRef)}
                      showCheckbox={bulkMode}
                      checked={Boolean(selectedIds[entry.item.cve_id])}
                      onToggleChecked={(next) => onToggleChecked(entry.item.cve_id, next)}
                    />
                  </div>
                );
              })}
              {entries.length === 0 ? (
                <div className="px-1 py-6 text-sm text-muted">
                  {qDebounced.trim() ? "Ничего не найдено." : "Для этого раздела пока нет записей."}
                </div>
              ) : null}
            </div>
          </div>
        </section>

        <aside className="flex min-h-[24rem] min-w-0 flex-col p-4 sm:p-5 lg:min-h-0">
          <VulnInspector
            entry={inspectorEntry}
            previewData={previewData}
            previewLoading={previewLoading}
            previewError={previewError}
            onOpen={activePreview ? () => onOpenFullCard(activePreview) : undefined}
          />
        </aside>
      </div>
    </div>
  );
}

function VulnInspector({
  entry,
  previewData,
  previewLoading,
  previewError,
  onOpen
}: {
  entry: VulnListEntry | null;
  previewData: unknown | null;
  previewLoading: boolean;
  previewError: boolean;
  onOpen?: () => void;
}) {
  if (!entry) {
    return (
      <div className="flex h-full flex-col justify-center px-1 text-sm text-muted">
        Выберите запись в списке — справа появятся описание и ИИ‑сводка.
      </div>
    );
  }

  const isCve = entry.kind === "cve";
  const title = isCve ? entry.item.cve_id : `BDU:${entry.item.bduId}`;
  const subtitle = isCve
    ? [entry.item.vp_vendor, entry.item.vp_product].filter(Boolean).join(" / ")
    : entry.item.name;
  const blurb = isCve
    ? entry.item.short_ru || entry.item.short_description || null
    : entry.item.name;
  const cvss = isCve
    ? typeof entry.item.cvss_base === "number"
      ? entry.item.cvss_base.toFixed(1)
      : null
    : typeof entry.item.cvssScore === "number"
      ? entry.item.cvssScore.toFixed(1)
      : null;
  const epss =
    isCve && typeof entry.item.epss === "number" ? `${(entry.item.epss * 100).toFixed(2)}%` : null;

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="shrink-0 space-y-3">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <div className="text-[11px] text-muted">Инспектор</div>
            <div className="mt-0.5 flex flex-wrap items-center gap-2">
              <h2 className="font-mono text-sm font-semibold tracking-tight text-fg/95">{title}</h2>
              {isCve ? <VulnClassBadge vulnClass={entry.item.vuln_class} /> : null}
            </div>
            {subtitle ? <p className="mt-1 truncate text-[11px] text-muted">{subtitle}</p> : null}
          </div>
          {onOpen ? (
            <button
              type="button"
              onClick={onOpen}
              className="shrink-0 rounded-lg border border-accent/35 bg-accent/10 px-2.5 py-1 text-[11px] text-fg/90 hover:bg-accent/15"
            >
              Открыть
            </button>
          ) : null}
        </div>

        <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
          {cvss ? (
            <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 tabular-nums dark:border-white/10 dark:bg-white/5">
              CVSS <span className="text-fg/85">{cvss}</span>
            </span>
          ) : null}
          {epss ? (
            <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 tabular-nums dark:border-white/10 dark:bg-white/5">
              EPSS <span className="text-fg/85">{epss}</span>
            </span>
          ) : null}
          {isCve ? <ExploitIntelBadges item={entry.item} /> : null}
          {!isCve && entry.item.hasExploit ? (
            <span className="rounded-full border border-danger/30 bg-danger/15 px-2 py-0.5 text-danger">эксплойт</span>
          ) : null}
        </div>

        {blurb ? (
          <p className="text-[13px] leading-relaxed text-fg/90">{blurb}</p>
        ) : null}
      </div>

      <div className="mt-4 min-h-0 flex-1 overflow-y-auto overscroll-contain pr-0.5">
        <AiSummaryPanel
          data={previewData}
          loading={previewLoading}
          aiPending={false}
          aiStalled={previewError}
          manualEnrichAllowed={false}
          embedded
        />
      </div>
    </div>
  );
}

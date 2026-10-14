"use client";

import { useEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from "react";
import { ChevronDown, Download, MoreHorizontal, Search, Settings2, SlidersHorizontal } from "lucide-react";
import { cn } from "@/components/ui/cn";
import { VC_DATA } from "@/lib/vulncontrol/dataset";
import {
  filterVulns,
  formatNum,
  inventoryCounts,
  patchLabel,
  severityLabel,
  statusLabel,
  tabCounts,
  versionsFor
} from "@/lib/vulncontrol/metrics";
import { mutateVulns, nextTaskId, useVcMutations } from "@/lib/vulncontrol/mutations";
import { riskColor, tint } from "@/lib/vulncontrol/risk";
import type { PatchState, Severity, VcQuery, VcTab, Vulnerability, VulnStatus } from "@/lib/vulncontrol/types";
import { useVc } from "./vc-context";
import { useClampedPoint, useOutsideClose, VcDrop, VcSelect, vcMenuItem } from "./vc-pop";

const TABS: Array<{ id: VcTab; label: string }> = [
  { id: "all", label: "Все" },
  { id: "attention", label: "Требуют внимания" },
  { id: "kev", label: "KEV / Exploited" },
  { id: "epss", label: "Высокий EPSS" },
  { id: "nopatch", label: "Нет исправления" },
  { id: "overdue", label: "Просроченные" }
];

const COLUMNS = [
  ["cve", "CVE / ID"],
  ["risk", "Риск"],
  ["level", "Уровень"],
  ["title", "Название уязвимости"],
  ["product", "Продукт"],
  ["version", "Версия"],
  ["vendor", "Вендор"],
  ["epss", "EPSS"],
  ["kev", "KEV"],
  ["patch", "Патч"],
  ["status", "Статус"],
  ["task", "Задача"]
] as const;

type ColId = (typeof COLUMNS)[number][0];
type SortKey = "cve" | "riskScore" | "severity" | "title" | "product" | "version" | "vendor" | "epss" | "kev" | "patchState" | "status" | "taskId" | "discoveredAt";

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

type InventoryTab = "all" | Severity | "kev" | "epss" | "nopatch" | "overdue";

const INVENTORY_TABS: Array<{ id: InventoryTab; label: string }> = [
  { id: "all", label: "Все" },
  { id: "critical", label: "Критические" },
  { id: "high", label: "Высокие" },
  { id: "medium", label: "Средние" },
  { id: "low", label: "Низкие" },
  { id: "kev", label: "KEV / Exploited" },
  { id: "epss", label: "Высокий EPSS" },
  { id: "nopatch", label: "Нет исправления" },
  { id: "overdue", label: "Просроченные" }
];

export function VulnTable({ title = "Последние обнаруженные уязвимости", variant = "dashboard" }: { title?: string; variant?: "dashboard" | "inventory" }) {
  const { query, setQuery, setSelectedId, openTask, picked, setPicked, flash } = useVc();
  useVcMutations();
  const inventory = variant === "inventory";
  const [sort, setSort] = useState<{ key: SortKey; dir: "asc" | "desc" }>({ key: "discoveredAt", dir: "desc" });
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(inventory ? 12 : 10);
  const [localSelected, setLocalSelected] = useState<Record<string, boolean>>({});
  const selected = inventory ? picked : localSelected;
  const setSelected = inventory ? setPicked : setLocalSelected;
  const [widths, setWidths] = useState<Partial<Record<ColId, number>>>({});
  const [advanced, setAdvanced] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const [visible, setVisible] = useState<Record<ColId, boolean>>({
    cve: true, risk: true, level: true, title: true, product: true, version: true, vendor: true, epss: true, kev: true, patch: true, status: true, task: true
  });
  const [colsOpen, setColsOpen] = useState(false);
  const [menu, setMenu] = useState<{ x: number; y: number; vuln: Vulnerability } | null>(null);
  const exportRef = useRef<HTMLDivElement>(null);
  const colsRef = useRef<HTMLDivElement>(null);
  const [localSearch, setLocalSearch] = useState(query.q);
  const counts = tabCounts(query);
  const invCounts = inventoryCounts(query);
  const versions = versionsFor(query);
  const inventoryTab = currentInventoryTab(query);
  const pickedIds = Object.entries(selected).filter(([, on]) => on).map(([id]) => id);

  useEffect(() => {
    setLocalSearch(query.q);
  }, [query.q]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (localSearch !== query.q) setQuery({ q: localSearch });
    }, inventory ? 220 : 0);
    return () => window.clearTimeout(timer);
  }, [inventory, localSearch, query.q, setQuery]);

  useEffect(() => {
    setPage(1);
  }, [query, sort, pageSize]);

  const rows = useMemo(() => {
    const list = filterVulns(query);
    const dir = sort.dir === "asc" ? 1 : -1;
    return [...list].sort((a, b) => {
      const pick = (row: Vulnerability) => {
        if (sort.key === "severity") return SEVERITY_RANK[row.severity];
        if (sort.key === "kev") return row.kev ? 1 : 0;
        if (sort.key === "taskId") return row.taskId ?? "";
        return row[sort.key];
      };
      const av = pick(a);
      const bv = pick(b);
      if (av < bv) return -1 * dir;
      if (av > bv) return 1 * dir;
      return 0;
    });
  }, [query, sort]);

  const pages = Math.max(1, Math.ceil(rows.length / pageSize));
  const safePage = Math.min(page, pages);
  const start = (safePage - 1) * pageSize;
  const view = rows.slice(start, start + pageSize);
  const pageIds = view.map((row) => row.id);
  const allChecked = pageIds.length > 0 && pageIds.every((id) => selected[id]);

  const toggleSort = (key: SortKey) => {
    setSort((current) => current.key === key ? { key, dir: current.dir === "asc" ? "desc" : "asc" } : { key, dir: "desc" });
  };

  return (
    <section className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)]">
      <div className={cn("border-b border-[var(--vc-border)] px-3", inventory ? "pt-1" : "pt-3")}>
        {inventory ? null : <h3 className="px-1 text-[14px] font-semibold">{title}</h3>}
        <div className={cn("flex gap-1 overflow-x-auto", inventory ? "" : "mt-2")}>
          {inventory ? INVENTORY_TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => applyInventoryTab(tab.id, setQuery)}
              className={cn(
                "whitespace-nowrap border-b-2 px-2.5 py-2 text-[12px]",
                inventoryTab === tab.id ? "border-[var(--vc-primary)] text-[var(--vc-text)]" : "border-transparent text-[var(--vc-muted)] hover:text-[var(--vc-text)]"
              )}
            >
              {tab.label} <span className={cn("ml-1 tabular-nums text-[11px]", inventoryTab === tab.id ? "text-[var(--vc-link)]" : "")}>{formatNum(invCounts[tab.id])}</span>
            </button>
          )) : TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setQuery({ tab: tab.id })}
              className={cn(
                "whitespace-nowrap border-b-2 px-2.5 py-2 text-[12px]",
                query.tab === tab.id ? "border-[var(--vc-primary)] text-[var(--vc-text)]" : "border-transparent text-[var(--vc-muted)] hover:text-[var(--vc-text)]"
              )}
            >
              {tab.label} <span className="ml-1 tabular-nums text-[11px]">{formatNum(counts[tab.id])}</span>
            </button>
          ))}
        </div>
      </div>

      {inventory && pickedIds.length > 0 ? (
        <BulkBar
          count={pickedIds.length}
          onClear={() => setSelected({})}
          onCreate={() => {
            const taskId = nextTaskId();
            mutateVulns(pickedIds, { taskId, assignee: "Security Team", status: "open" });
            flash(`Созданы задачи, первая ${taskId}`);
          }}
          onAssign={(name) => { mutateVulns(pickedIds, { assignee: name }); flash(`Назначено: ${name}`); }}
          onStatus={(status) => { mutateVulns(pickedIds, { status }); flash("Статус обновлён"); }}
          onPriority={(priority) => { mutateVulns(pickedIds, { priority }); flash("Приоритет обновлён"); }}
          onAccept={() => { mutateVulns(pickedIds, { status: "accepted_risk" }); flash("Риск принят"); }}
          onExport={() => exportCsv(rows.filter((row) => selected[row.id]))}
        />
      ) : null}

      <div className="relative flex flex-wrap items-center gap-2 px-3 py-2.5">
        <Select label="Все уровни" value={query.severity} onChange={(severity) => setQuery({ severity: severity as Severity | "all" })} options={[["all", "Все уровни"], ["critical", "Критические"], ["high", "Высокие"], ["medium", "Средние"], ["low", "Низкие"]]} />
        <Select label="Все статусы" value={query.status} onChange={(status) => setQuery({ status: status as VulnStatus | "all" })} options={[["all", "Все статусы"], ["open", "Открыта"], ["in_progress", "В работе"], ["resolved", "Закрыта"], ["accepted_risk", "Принят риск"], ["overdue", "Просрочена"]]} />
        <Select label="Все вендоры" value={query.vendor} onChange={(vendor) => setQuery({ vendor })} options={[["all", "Все вендоры"], ...VC_DATA.vendors.map((vendor) => [vendor.name, vendor.name] as [string, string])]} />
        <Select label="Все продукты" value={query.product} onChange={(product) => setQuery({ product, version: "all" })} options={[["all", "Все продукты"], ...VC_DATA.products.map((product) => [product.name, product.chartName] as [string, string])]} />
        <Select label="Все версии" value={query.version} onChange={(version) => setQuery({ version })} options={[["all", "Все версии"], ...versions.map((version) => [version, version] as [string, string])]} />
        {inventory ? <Select label="Все источники" value={query.source} onChange={(source) => setQuery({ source })} options={[["all", "Все источники"], ...VC_DATA.sources.map((source) => [source.name, source.name] as [string, string])]} /> : null}
        {inventory ? (
          <button type="button" onClick={() => setAdvanced((value) => !value)} className={cn("inline-flex h-8 items-center gap-1.5 rounded-lg border px-2.5 text-[12px]", advanced ? "border-[var(--vc-primary)] text-[var(--vc-text)]" : "border-[var(--vc-border)] text-[var(--vc-muted)] hover:text-[var(--vc-text)]")}>
            <SlidersHorizontal className="h-3.5 w-3.5" /> Дополнительные фильтры
          </button>
        ) : null}
        <label className="ml-auto flex h-8 min-w-[200px] flex-1 items-center gap-2 rounded-lg border border-[var(--vc-border)] bg-[var(--vc-well)] px-2 text-[12px] text-[var(--vc-muted)]">
          <Search className="h-3.5 w-3.5 shrink-0" />
          <input
            value={localSearch}
            onChange={(event) => setLocalSearch(event.target.value)}
            placeholder={inventory ? "Поиск CVE, названия, продукта..." : "Поиск"}
            className="w-full bg-transparent text-[var(--vc-text)] outline-none placeholder:text-[var(--vc-muted)]"
          />
        </label>
        <div ref={exportRef}>
          <button type="button" onClick={() => inventory ? setExportOpen((value) => !value) : exportCsv(Object.values(selected).some(Boolean) ? rows.filter((row) => selected[row.id]) : rows)} className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-[var(--vc-border)] px-2.5 text-[12px] hover:bg-[var(--vc-hover)]">
            <Download className="h-3.5 w-3.5" /> Экспорт {inventory ? <ChevronDown className="h-3 w-3" /> : null}
          </button>
          <VcDrop open={exportOpen} anchorRef={exportRef} onClose={() => setExportOpen(false)} align="end" width={176} className="p-1 text-[12px]">
            <button type="button" className={vcMenuItem} onClick={() => { exportCsv(rows); setExportOpen(false); }}>Все отфильтрованные</button>
            <button type="button" className={vcMenuItem} onClick={() => { exportCsv(rows.filter((row) => selected[row.id])); setExportOpen(false); }}>Только выбранные</button>
          </VcDrop>
        </div>
        <div ref={colsRef}>
          <button type="button" onClick={() => setColsOpen((value) => !value)} className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-[var(--vc-border)] hover:bg-[var(--vc-hover)]" title="Колонки">
            <Settings2 className="h-3.5 w-3.5" />
          </button>
          <VcDrop open={colsOpen} anchorRef={colsRef} onClose={() => setColsOpen(false)} align="end" width={192} maxHeight={360} className="p-2">
            {COLUMNS.map(([id, label]) => (
              <label key={id} className="flex min-w-0 items-center gap-2 px-1 py-1 text-[12px] leading-snug">
                <input type="checkbox" checked={visible[id]} onChange={() => setVisible((current) => ({ ...current, [id]: !current[id] }))} />
                <span className="min-w-0 truncate">{label}</span>
              </label>
            ))}
          </VcDrop>
        </div>
      </div>
      {advanced ? <AdvancedFilters onClose={() => setAdvanced(false)} /> : null}

      {rows.length === 0 ? (
        <div className="px-4 py-16 text-center text-sm text-[var(--vc-muted)]">Нет уязвимостей по текущим фильтрам.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[1180px] border-collapse text-left text-[12px]">
            <thead className="text-[10px] uppercase tracking-wide text-[var(--vc-muted)]">
              <tr className="border-y border-[var(--vc-border)]">
                <th className="w-8 px-3 py-2">
                  <input
                    type="checkbox"
                    checked={allChecked}
                    onChange={() => {
                      setSelected((current) => {
                        const next = { ...current };
                        if (allChecked) pageIds.forEach((id) => delete next[id]);
                        else pageIds.forEach((id) => { next[id] = true; });
                        return next;
                      });
                    }}
                  />
                </th>
                {visible.cve ? <Th id="cve" width={widths.cve} onResize={setWidths} onClick={() => toggleSort("cve")}>CVE / ID</Th> : null}
                {visible.risk ? <Th id="risk" width={widths.risk} onResize={setWidths} onClick={() => toggleSort("riskScore")}>Риск</Th> : null}
                {visible.level ? <Th id="level" width={widths.level} onResize={setWidths} onClick={() => toggleSort("severity")}>Уровень</Th> : null}
                {visible.title ? <Th id="title" width={widths.title} onResize={setWidths} onClick={() => toggleSort("title")}>Название уязвимости</Th> : null}
                {visible.product ? <Th id="product" width={widths.product} onResize={setWidths} onClick={() => toggleSort("product")}>Продукт</Th> : null}
                {visible.version ? <Th id="version" width={widths.version} onResize={setWidths} onClick={() => toggleSort("version")}>Версия</Th> : null}
                {visible.vendor ? <Th id="vendor" width={widths.vendor} onResize={setWidths} onClick={() => toggleSort("vendor")}>Вендор</Th> : null}
                {visible.epss ? <Th id="epss" width={widths.epss} onResize={setWidths} onClick={() => toggleSort("epss")}>EPSS</Th> : null}
                {visible.kev ? <Th id="kev" width={widths.kev} onResize={setWidths} onClick={() => toggleSort("kev")}>KEV</Th> : null}
                {visible.patch ? <Th id="patch" width={widths.patch} onResize={setWidths} onClick={() => toggleSort("patchState")}>Патч</Th> : null}
                {visible.status ? <Th id="status" width={widths.status} onResize={setWidths} onClick={() => toggleSort("status")}>Статус</Th> : null}
                {visible.task ? <Th id="task" width={widths.task} onResize={setWidths} onClick={() => toggleSort("taskId")}>Задача</Th> : null}
                <th className="w-8 px-2" />
              </tr>
            </thead>
            <tbody>
              {view.map((row) => (
                <tr
                  key={row.id}
                  onContextMenu={(event) => {
                    event.preventDefault();
                    setMenu({ x: event.clientX, y: event.clientY, vuln: row });
                  }}
                  className="border-b border-[var(--vc-line)] hover:bg-[var(--vc-hover-row)]"
                >
                  <td className="px-3 py-2">
                    <input type="checkbox" checked={Boolean(selected[row.id])} onChange={() => setSelected((current) => ({ ...current, [row.id]: !current[row.id] }))} />
                  </td>
                  {visible.cve ? (
                    <td className="px-2 py-2">
                      <button type="button" className="font-medium text-[var(--vc-link)] hover:underline" onClick={() => setSelectedId(row.id)}>{row.cve}</button>
                    </td>
                  ) : null}
                  {visible.risk ? (
                    <td className="px-2 py-2">
                      <span className="inline-flex min-w-[34px] justify-center rounded-md px-1.5 py-0.5 text-[12px] font-bold tabular-nums" style={{ color: riskColor(row.riskScore), background: tint(riskColor(row.riskScore), 13) }}>{row.riskScore.toFixed(1)}</span>
                    </td>
                  ) : null}
                  {visible.level ? (
                    <td className="px-2 py-2">
                      <Level severity={row.severity} />
                    </td>
                  ) : null}
                  {visible.title ? <td className="max-w-[280px] truncate px-2 py-2 text-[var(--vc-text)]/90">{row.title}</td> : null}
                  {visible.product ? (
                    <td className="px-2 py-2">
                      <button type="button" className="hover:text-[var(--vc-link)]" onClick={() => setQuery({ product: row.product, tab: "all" })}>{row.product}</button>
                    </td>
                  ) : null}
                  {visible.version ? <td className="px-2 py-2 text-[var(--vc-muted)]">{row.version}</td> : null}
                  {visible.vendor ? (
                    <td className="px-2 py-2">
                      <button type="button" className="hover:text-[var(--vc-link)]" onClick={() => setQuery({ vendor: row.vendor, tab: "all" })}>{row.vendor}</button>
                    </td>
                  ) : null}
                  {visible.epss ? (
                    <td className="px-2 py-2">
                      <span className="rounded px-1.5 py-0.5 text-[11px] font-semibold tabular-nums" style={{ color: row.epss >= 0.7 ? "var(--vc-critical)" : row.epss >= 0.4 ? "var(--vc-high)" : "var(--vc-muted)", background: row.epss >= 0.4 ? tint("var(--vc-high)", 12) : "var(--vc-line)" }}>{row.epss.toFixed(2)}</span>
                    </td>
                  ) : null}
                  {visible.kev ? <td className={cn("px-2 py-2 text-[11px] font-semibold", row.kev ? "text-[var(--vc-critical)]" : "text-[var(--vc-muted)]")}>{row.kev ? "Да" : "Нет"}</td> : null}
                  {visible.patch ? (
                    <td className="px-2 py-2">
                      <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold" style={{ color: row.patchState === "available" ? "var(--vc-success)" : "var(--vc-danger-text)", background: row.patchState === "available" ? tint("var(--vc-success)", 14) : tint("var(--vc-critical)", 12) }}>{patchLabel(row.patchState)}</span>
                    </td>
                  ) : null}
                  {visible.status ? <td className="px-2 py-2"><StatusPill status={row.status} /></td> : null}
                  {visible.task ? (
                    <td className="px-2 py-2">
                      {row.taskId ? (
                        <button type="button" className="text-[var(--vc-link)] hover:underline" onClick={() => openTask(row.taskId!)}>{row.taskId}</button>
                      ) : (
                        <span className="text-[var(--vc-muted)]">—</span>
                      )}
                    </td>
                  ) : null}
                  <td className="px-2 py-2">
                    <button type="button" className="rounded p-1 text-[var(--vc-muted)] hover:bg-[var(--vc-track)] hover:text-[var(--vc-text)]" onClick={(event) => setMenu({ x: event.clientX, y: event.clientY, vuln: row })}>
                      <MoreHorizontal className="h-3.5 w-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-2.5 text-[12px] text-[var(--vc-muted)]">
        <div>
          Показано {rows.length ? start + 1 : 0}–{Math.min(start + pageSize, rows.length)} из {formatNum(rows.length)}
        </div>
        <div className="flex items-center gap-1">
          <Pager page={safePage} pages={pages} onPage={setPage} />
          <label className="ml-2 flex items-center gap-1">
            {inventory ? <span>Строк на странице:</span> : null}
            <VcSelect
              ariaLabel="Строк на странице"
              value={String(pageSize)}
              onChange={(value) => setPageSize(Number(value))}
              options={(inventory ? [12, 25, 50] : [10, 25, 50]).map((size) => [String(size), String(size)] as [string, string])}
              align="end"
              className="h-7 bg-transparent px-1.5"
            />
          </label>
        </div>
      </div>
      {menu ? <RowMenu menu={menu} onClose={() => setMenu(null)} onOpen={() => { setSelectedId(menu.vuln.id); setMenu(null); }} onTask={() => { if (menu.vuln.taskId) openTask(menu.vuln.taskId); setMenu(null); }} onProduct={() => { setQuery({ product: menu.vuln.product }); setMenu(null); }} /> : null}
    </section>
  );
}

function Th({ id, width, onResize, children, onClick }: { id: ColId; width?: number; onResize: (value: Partial<Record<ColId, number>> | ((current: Partial<Record<ColId, number>>) => Partial<Record<ColId, number>>)) => void; children: string; onClick: () => void }) {
  return (
    <th className="relative px-2 py-2 font-medium" style={width ? { width, minWidth: width } : undefined}>
      <button type="button" onClick={onClick} className="hover:text-[var(--vc-text)]">{children}</button>
      <span
        role="separator"
        aria-orientation="vertical"
        className="absolute right-0 top-1 h-[calc(100%-8px)] w-1 cursor-col-resize rounded hover:bg-[#2f6bff]/70"
        onMouseDown={(event) => {
          event.preventDefault();
          event.stopPropagation();
          const startX = event.clientX;
          const startW = width ?? (event.currentTarget.parentElement?.getBoundingClientRect().width ?? 96);
          const move = (ev: MouseEvent) => onResize((current) => ({ ...current, [id]: Math.max(64, startW + ev.clientX - startX) }));
          const up = () => {
            window.removeEventListener("mousemove", move);
            window.removeEventListener("mouseup", up);
          };
          window.addEventListener("mousemove", move);
          window.addEventListener("mouseup", up);
        }}
      />
    </th>
  );
}

function Level({ severity }: { severity: Severity }) {
  const color = severity === "critical" ? "var(--vc-critical)" : severity === "high" ? "var(--vc-high)" : severity === "medium" ? "var(--vc-medium)" : "var(--vc-low)";
  return <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold" style={{ color, background: tint(color, 13) }}>{severityLabel(severity)}</span>;
}

function StatusPill({ status }: { status: VulnStatus }) {
  const map: Record<VulnStatus, string> = {
    open: "var(--vc-info)",
    in_progress: "var(--vc-high)",
    resolved: "var(--vc-success)",
    accepted_risk: "var(--vc-purple)",
    overdue: "var(--vc-critical)"
  };
  const color = map[status];
  return <span className="rounded px-1.5 py-0.5 text-[10px] font-medium" style={{ color, background: tint(color, 13) }}>{statusLabel(status)}</span>;
}

function Select({ label, value, onChange, options }: { label: string; value: string; onChange: (value: string) => void; options: Array<[string, string]> }) {
  return <VcSelect ariaLabel={label} value={value} onChange={onChange} options={options} className="max-w-[160px] bg-[var(--vc-well)]" />;
}

function Pager({ page, pages, onPage }: { page: number; pages: number; onPage: (page: number) => void }) {
  const items = pagerItems(page, pages);
  return (
    <div className="flex items-center gap-1">
      <button type="button" disabled={page <= 1} onClick={() => onPage(page - 1)} className="h-7 w-7 rounded border border-[var(--vc-border)] disabled:opacity-40">‹</button>
      {items.map((item, index) => item === "…" ? (
        <span key={`gap-${index}`} className="px-1">…</span>
      ) : (
        <button key={item} type="button" onClick={() => onPage(item)} className={cn("h-7 min-w-7 rounded px-1.5 tabular-nums", item === page ? "bg-[var(--vc-primary)] text-white" : "hover:bg-[var(--vc-hover)]")}>{item}</button>
      ))}
      <button type="button" disabled={page >= pages} onClick={() => onPage(page + 1)} className="h-7 w-7 rounded border border-[var(--vc-border)] disabled:opacity-40">›</button>
    </div>
  );
}

function pagerItems(page: number, pages: number): Array<number | "…"> {
  if (pages <= 7) return Array.from({ length: pages }, (_, index) => index + 1);
  const raw = [1, 2, 3, 4, 5, pages];
  if (page > 4) raw.splice(1, 3, page - 1, page, page + 1);
  const unique = [...new Set(raw.filter((item) => item >= 1 && item <= pages))].sort((a, b) => a - b);
  const out: Array<number | "…"> = [];
  unique.forEach((item, index) => {
    if (index && item - unique[index - 1]! > 1) out.push("…");
    out.push(item);
  });
  return out;
}

function RowMenu({ menu, onClose, onOpen, onTask, onProduct }: { menu: { x: number; y: number; vuln: Vulnerability }; onClose: () => void; onOpen: () => void; onTask: () => void; onProduct: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const style = useClampedPoint(menu.x, menu.y, ref, 176);
  useOutsideClose(true, [ref], onClose);
  return (
    <div ref={ref} className="vc-pop overflow-y-auto rounded-lg border border-[var(--vc-border)] bg-[var(--vc-surface)] p-1 text-[12px] shadow-2xl" style={style}>
      <button type="button" className={vcMenuItem} onClick={onOpen}>Открыть карточку</button>
      <button type="button" className={vcMenuItem} onClick={onProduct}>Фильтр по продукту</button>
      <button type="button" className={vcMenuItem} onClick={onTask}>Открыть задачу</button>
    </div>
  );
}

function currentInventoryTab(query: { tab: VcTab; severity: Severity | "all" }): InventoryTab {
  if (query.tab === "kev" || query.tab === "epss" || query.tab === "nopatch" || query.tab === "overdue") return query.tab;
  if (query.severity !== "all") return query.severity;
  return "all";
}

function applyInventoryTab(id: InventoryTab, setQuery: (patch: Partial<VcQuery>) => void) {
  if (id === "all") setQuery({ tab: "all", severity: "all" });
  else if (id === "critical" || id === "high" || id === "medium" || id === "low") setQuery({ tab: "all", severity: id });
  else setQuery({ tab: id, severity: "all" });
}

function BulkBar({
  count,
  onClear,
  onCreate,
  onAssign,
  onStatus,
  onPriority,
  onAccept,
  onExport
}: {
  count: number;
  onClear: () => void;
  onCreate: () => void;
  onAssign: (name: string) => void;
  onStatus: (status: VulnStatus) => void;
  onPriority: (priority: Severity) => void;
  onAccept: () => void;
  onExport: () => void;
}) {
  const [menu, setMenu] = useState<"assign" | "status" | "priority" | null>(null);
  const assignRef = useRef<HTMLDivElement>(null);
  const statusRef = useRef<HTMLDivElement>(null);
  const priorityRef = useRef<HTMLDivElement>(null);
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-[var(--vc-border)] bg-[var(--vc-bar)] px-3 py-2 text-[12px]">
      <span className="font-medium">Выбрано: {count}</span>
      <button type="button" onClick={onClear} className="text-[var(--vc-muted)] hover:text-[var(--vc-text)]">Снять</button>
      <button type="button" onClick={onCreate} className="rounded-md bg-[#2f6bff] px-2 py-1 font-medium text-white">Создать задачи</button>
      <div ref={assignRef}>
        <button type="button" onClick={() => setMenu(menu === "assign" ? null : "assign")} className="rounded-md border border-[var(--vc-border)] px-2 py-1 hover:bg-[var(--vc-hover)]">Назначить</button>
        <MenuList open={menu === "assign"} anchorRef={assignRef} onClose={() => setMenu(null)} items={["Security Team", "VM Team", "Марина К.", "Илья С."]} onPick={(name) => { onAssign(name); setMenu(null); }} />
      </div>
      <div ref={statusRef}>
        <button type="button" onClick={() => setMenu(menu === "status" ? null : "status")} className="rounded-md border border-[var(--vc-border)] px-2 py-1 hover:bg-[var(--vc-hover)]">Изменить статус</button>
        <MenuList open={menu === "status"} anchorRef={statusRef} onClose={() => setMenu(null)} items={[["open", "Открыта"], ["in_progress", "В работе"], ["resolved", "Закрыта"], ["accepted_risk", "Принята в риск"], ["overdue", "Просрочена"]]} onPick={(id) => { onStatus(id as VulnStatus); setMenu(null); }} />
      </div>
      <div ref={priorityRef}>
        <button type="button" onClick={() => setMenu(menu === "priority" ? null : "priority")} className="rounded-md border border-[var(--vc-border)] px-2 py-1 hover:bg-[var(--vc-hover)]">Изменить приоритет</button>
        <MenuList open={menu === "priority"} anchorRef={priorityRef} onClose={() => setMenu(null)} items={[["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]]} onPick={(id) => { onPriority(id as Severity); setMenu(null); }} />
      </div>
      <button type="button" onClick={onAccept} className="rounded-md border border-[var(--vc-border)] px-2 py-1 hover:bg-[var(--vc-hover)]">Принять риск</button>
      <button type="button" onClick={onExport} className="rounded-md border border-[var(--vc-border)] px-2 py-1 hover:bg-[var(--vc-hover)]">Экспорт</button>
    </div>
  );
}

function MenuList({ open, anchorRef, onClose, items, onPick }: { open: boolean; anchorRef: RefObject<HTMLDivElement | null>; onClose: () => void; items: Array<string | [string, string]>; onPick: (id: string) => void }) {
  return (
    <VcDrop open={open} anchorRef={anchorRef} onClose={onClose} align="start" width={176} className="p-1">
      {items.map((item) => {
        const [id, label] = Array.isArray(item) ? item : [item, item];
        return <button key={id} type="button" className={vcMenuItem} onClick={() => onPick(id)}>{label}</button>;
      })}
    </VcDrop>
  );
}

function AdvancedFilters({ onClose }: { onClose: () => void }) {
  const { query, setQuery, resetQuery } = useVc();
  return (
    <div className="mx-3 mb-2 grid gap-3 rounded-lg border border-[var(--vc-border)] bg-[var(--vc-inset)] p-3 md:grid-cols-2 xl:grid-cols-4">
      <RangeField label="Risk Score" min={0} max={10} step={0.1} from={query.riskMin} to={query.riskMax} onChange={(riskMin, riskMax) => setQuery({ riskMin, riskMax })} presets={[["Critical", 9, 10], ["High", 7, 8.9], ["Medium", 5, 6.9], ["Low", 0, 4.9]]} />
      <RangeField label="CVSS" min={0} max={10} step={0.1} from={query.cvssMin} to={query.cvssMax} onChange={(cvssMin, cvssMax) => setQuery({ cvssMin, cvssMax })} />
      <div>
        <div className="mb-1 text-[11px] text-[var(--vc-muted)]">EPSS · {query.epssMin ?? 0} — {query.epssMax ?? 1}</div>
        <input type="range" min={0} max={1} step={0.01} value={query.epssMin ?? 0} onChange={(event) => setQuery({ epssMin: Number(event.target.value) })} className="w-full accent-[#2f6bff]" />
        <div className="mt-1 flex flex-wrap gap-1">
          {[["> 0.9", 0.9], ["> 0.7", 0.7], ["> 0.5", 0.5]].map(([label, value]) => (
            <button key={label} type="button" onClick={() => setQuery({ epssMin: Number(value), epssMax: null })} className="rounded border border-[var(--vc-border)] px-1.5 py-0.5 text-[10px] hover:border-[#2f6bff]">{label}</button>
          ))}
        </div>
      </div>
      <Field label="KEV">
        <Select label="KEV" value={query.kev} onChange={(kev) => setQuery({ kev: kev as "all" | "yes" | "no" })} options={[["all", "Все"], ["yes", "KEV"], ["no", "Не KEV"]]} />
      </Field>
      <Field label="Exploit">
        <Select label="Exploit" value={query.exploit} onChange={(exploit) => setQuery({ exploit: exploit as "all" | "exploit" | "poc" | "none" })} options={[["all", "Все"], ["exploit", "Exploit Available"], ["poc", "PoC Available"], ["none", "No Known Exploit"]]} />
      </Field>
      <Field label="Patch">
        <Select label="Patch" value={query.patch} onChange={(patch) => setQuery({ patch: patch as PatchState | "all" })} options={[["all", "Все"], ["available", "Patch Available"], ["none", "No Patch"], ["analysis", "Requires Analysis"], ["na", "Not Applicable"]]} />
      </Field>
      <Field label="Обнаружено с">
        <input type="date" value={query.discoveredFrom} onChange={(event) => setQuery({ discoveredFrom: event.target.value })} className="h-8 w-full rounded-lg border border-[var(--vc-border)] bg-[var(--vc-well)] px-2 text-[12px]" />
      </Field>
      <Field label="Обнаружено по">
        <input type="date" value={query.discoveredTo} onChange={(event) => setQuery({ discoveredTo: event.target.value })} className="h-8 w-full rounded-lg border border-[var(--vc-border)] bg-[var(--vc-well)] px-2 text-[12px]" />
      </Field>
      <Field label="Обновлено с">
        <input type="date" value={query.updatedFrom} onChange={(event) => setQuery({ updatedFrom: event.target.value })} className="h-8 w-full rounded-lg border border-[var(--vc-border)] bg-[var(--vc-well)] px-2 text-[12px]" />
      </Field>
      <Field label="Обновлено по">
        <input type="date" value={query.updatedTo} onChange={(event) => setQuery({ updatedTo: event.target.value })} className="h-8 w-full rounded-lg border border-[var(--vc-border)] bg-[var(--vc-well)] px-2 text-[12px]" />
      </Field>
      <Field label="Remediation SLA">
        <Select label="SLA" value={query.sla} onChange={(sla) => setQuery({ sla: sla as "all" | "breach" | "ok" })} options={[["all", "Все"], ["breach", "Нарушен"], ["ok", "В сроке"]]} />
      </Field>
      <Field label="Принятие риска">
        <Select label="Риск" value={query.riskAccepted} onChange={(riskAccepted) => setQuery({ riskAccepted: riskAccepted as "all" | "yes" | "no" })} options={[["all", "Все"], ["yes", "Принят"], ["no", "Не принят"]]} />
      </Field>
      <div className="flex items-end gap-2">
        <button type="button" onClick={() => { resetQuery(); onClose(); }} className="h-8 rounded-lg border border-[var(--vc-border)] px-2 text-[12px] hover:bg-[var(--vc-hover)]">Сбросить</button>
        <button type="button" onClick={onClose} className="h-8 rounded-lg bg-[#2f6bff] px-2 text-[12px] text-white">Готово</button>
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block text-[11px] text-[var(--vc-muted)]">
      <span className="mb-1 block">{label}</span>
      {children}
    </label>
  );
}

function RangeField({
  label,
  min,
  max,
  step,
  from,
  to,
  onChange,
  presets
}: {
  label: string;
  min: number;
  max: number;
  step: number;
  from: number | null;
  to: number | null;
  onChange: (from: number, to: number) => void;
  presets?: Array<[string, number, number]>;
}) {
  return (
    <div>
      <div className="mb-1 text-[11px] text-[var(--vc-muted)]">{label} · {from ?? min} — {to ?? max}</div>
      <div className="flex gap-2">
        <input type="range" min={min} max={max} step={step} value={from ?? min} onChange={(event) => onChange(Number(event.target.value), to ?? max)} className="w-full accent-[var(--vc-critical)]" />
        <input type="range" min={min} max={max} step={step} value={to ?? max} onChange={(event) => onChange(from ?? min, Number(event.target.value))} className="w-full accent-[#2f6bff]" />
      </div>
      {presets ? (
        <div className="mt-1 flex flex-wrap gap-1">
          {presets.map(([name, start, end]) => (
            <button key={name} type="button" onClick={() => onChange(start, end)} className="rounded border border-[var(--vc-border)] px-1.5 py-0.5 text-[10px] hover:border-[#2f6bff]">{name}</button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function exportCsv(rows: Vulnerability[]) {
  const header = ["CVE", "Risk", "CVSS", "Severity", "Title", "Product", "Version", "Vendor", "EPSS", "KEV", "Patch", "Status", "Task"];
  const lines = rows.map((row) => [row.cve, row.riskScore, row.cvss, row.severity, row.title, row.product, row.version, row.vendor, row.epss, row.kev ? "yes" : "no", row.patchState, row.status, row.taskId ?? ""].map(csvCell).join(","));
  const blob = new Blob([[header.join(","), ...lines].join("\n")], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "vulncontrol-vulnerabilities.csv";
  link.click();
  URL.revokeObjectURL(url);
}

function csvCell(value: string | number) {
  const text = String(value);
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

"use client";

import { useEffect, useState, type ReactNode } from "react";
import Link from "next/link";
import type { Route } from "next";
import { X } from "lucide-react";
import { cvssBand, formatInt, useProductCatalog, useProductDetail, type ProductRow } from "@/lib/vulncontrol/live";
import { formatEpss } from "@/lib/vulncontrol/vuln-model";
import { stashVcPage, vulnerabilityPath, useVc } from "./vc-context";
import { VcSelect } from "./vc-pop";

const PAGE = 25;
const PRODUCT_KEY = "vip:vc-product";

const TABS: Array<{ id: string; label: string; color: string; hint: string }> = [
  { id: "risk70", label: "Риск ≥ 70", color: "#ff8a3d", hint: "Есть CVE с риском каталога не ниже 70" },
  { id: "risk90", label: "Риск ≥ 90", color: "#ff4d5e", hint: "Есть CVE с риском каталога не ниже 90" },
  { id: "kev", label: "KEV", color: "#ff4d5e", hint: "Есть хотя бы одна запись CISA KEV" },
  { id: "exploit", label: "Эксплойт", color: "#ff8a3d", hint: "Есть публичный эксплойт или PoC" },
  { id: "all", label: "Весь каталог", color: "#2f6bff", hint: "Все связки вендор–продукт, по алфавиту" }
];

type ProductPick = { vendorKey: string; productKey: string; vendor: string; product: string };

export function ProductsView() {
  const { query, setQuery } = useVc();
  const [band, setBand] = useState("risk70");
  const [vendor, setVendor] = useState("all");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<ProductPick | null>(null);
  const q = useDebounced(query.q, 250);
  const list = useProductCatalog({ q, vendor, band, limit: PAGE, offset: page * PAGE });
  const rows = list.data?.items ?? [];
  const total = list.data?.total ?? null;
  const catalog = list.data?.catalog ?? null;
  const from = rows.length ? page * PAGE + 1 : 0;
  const to = page * PAGE + rows.length;
  const hasNext = total != null ? to < total : rows.length === PAGE;
  const filtered = band !== "risk70" || vendor !== "all" || q.trim().length >= 2;
  const vendors = list.data?.vendors ?? [];
  const vendorOptions = uniqueVendors(vendors, vendor);
  const tab = TABS.find((item) => item.id === band) ?? TABS[0]!;
  const counts: Record<string, number | undefined> = {
    risk70: catalog?.risk70,
    risk90: catalog?.risk90,
    kev: catalog?.withKev,
    exploit: catalog?.withExploit,
    all: catalog?.products
  };

  useEffect(() => {
    setPage(0);
  }, [band, vendor, q]);

  useEffect(() => {
    try {
      const raw = sessionStorage.getItem(PRODUCT_KEY);
      if (!raw) return;
      const parsed = JSON.parse(raw) as ProductPick;
      if (parsed?.vendorKey && parsed?.productKey) setSelected(parsed);
    } catch {
      sessionStorage.removeItem(PRODUCT_KEY);
    }
  }, []);

  const openProduct = (row: ProductPick) => {
    setSelected(row);
    sessionStorage.setItem(PRODUCT_KEY, JSON.stringify(row));
  };
  const closeProduct = () => {
    setSelected(null);
    sessionStorage.removeItem(PRODUCT_KEY);
  };

  return (
    <div className="space-y-3">
      <div>
        <h1 className="text-[20px] font-semibold tracking-tight">Продукты</h1>
        <p className="text-[12px] text-[var(--vc-muted)]">Каталог продуктов и вендоров из записей CVE: риск, версии, EPSS, KEV, эксплойт и исправление</p>
      </div>
      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="В каталоге" value={catalog ? formatInt(catalog.products) : "…"} hint="связки вендор–продукт" color="var(--vc-primary)" />
        <Stat label="С KEV" value={catalog ? formatInt(catalog.withKev) : "…"} hint="хотя бы один CISA KEV" color="#ff4d5e" />
        <Stat label="Наивысший риск" value={catalog ? formatInt(catalog.highestRisk) : "…"} hint="балл каталога 0–100" color={riskTone(catalog?.highestRisk ?? null)} />
        <Stat label="В этом срезе" value={total == null ? "…" : formatInt(total)} hint={tab.hint} color={tab.color} />
      </div>
      <div className="flex gap-5 overflow-x-auto border-b border-[var(--vc-border)]">
        {TABS.map((item) => {
          const on = band === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setBand(item.id)}
              className={`relative inline-flex shrink-0 items-center gap-2 pb-2.5 text-[13px] ${on ? "font-medium text-[var(--vc-text)]" : "text-[var(--vc-muted)] hover:text-[var(--vc-text)]"}`}
            >
              {item.label}
              <span className="rounded-md px-1.5 py-0.5 text-[11px] font-semibold tabular-nums text-white" style={{ background: item.color }}>
                {counts[item.id] == null ? "…" : formatInt(counts[item.id])}
              </span>
              {on ? <span className="absolute inset-x-0 bottom-0 h-0.5 rounded-full bg-[var(--vc-primary)]" /> : null}
            </button>
          );
        })}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <VcSelect
          ariaLabel="Вендор"
          value={vendorOptions.some((item) => item.vendorKey === vendor) ? vendor : "all"}
          onChange={setVendor}
          options={[["all", "Все вендоры"], ...vendorOptions.map((item) => [item.vendorKey, `${pretty(item.vendor)} · ${formatInt(item.count)}`] as [string, string])]}
          className="max-w-[240px] bg-[var(--vc-bg)]"
        />
        <input
          aria-label="Поиск продукта"
          value={query.q}
          onChange={(event) => setQuery({ q: event.target.value })}
          placeholder="Продукт или вендор, от 2 символов"
          className="h-8 min-w-[220px] flex-1 rounded-lg border border-[var(--vc-border)] bg-[var(--vc-bg)] px-2.5 text-[12px] text-[var(--vc-text)] outline-none placeholder:text-[var(--vc-muted)]"
        />
        {filtered ? (
          <button type="button" className="text-[12px] text-[var(--vc-link)]" onClick={() => { setBand("risk70"); setVendor("all"); setQuery({ q: "" }); }}>
            Сбросить фильтры
          </button>
        ) : null}
      </div>
      <section className="overflow-hidden rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)]">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--vc-border)] px-3 py-2">
          <p className="text-[12px] text-[var(--vc-muted)]">
            {list.isLoading && !rows.length ? "Загрузка каталога…" : list.isError ? "Каталог продуктов не загрузился." : rangeLabel(from, to, total)}
            {list.isFetching && rows.length ? " · обновляю…" : ""}
          </p>
          <p className="text-[11px] text-[var(--vc-muted)]">{tab.hint}</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[860px] border-separate border-spacing-0 text-left text-[12px]">
            <thead className="text-[10px] uppercase tracking-wide text-[var(--vc-muted)]">
              <tr>
                {["Продукт", "Вендор", "Риск", "CVE", "KEV", "EPSS", "Эксплойт"].map((label) => (
                  <th key={label} className="bg-[var(--vc-table-head)] px-3 py-2.5 font-medium">{label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const on = selected?.vendorKey === row.vendorKey && selected?.productKey === row.productKey;
                return (
                  <tr
                    key={`${row.vendorKey}:${row.productKey}`}
                    className={on ? "bg-[var(--vc-selected)] text-white" : "hover:bg-[var(--vc-hover-row)]"}
                  >
                    <td className="border-b border-[var(--vc-line)] px-3 py-2">
                      <button type="button" className={`text-left font-medium hover:underline ${on ? "text-white" : "text-[var(--vc-link)]"}`} onClick={() => openProduct(row)}>
                        {pretty(row.product)}
                      </button>
                    </td>
                    <td className="border-b border-[var(--vc-line)] px-3 py-2">
                      <button type="button" className={`hover:underline ${on ? "text-white" : "text-[var(--vc-muted)] hover:text-[var(--vc-link)]"}`} onClick={() => setVendor(row.vendorKey)}>
                        {pretty(row.vendor)}
                      </button>
                    </td>
                    <td className="border-b border-[var(--vc-line)] px-3 py-2"><RiskChip score={row.maxRisk} /></td>
                    <td className="border-b border-[var(--vc-line)] px-3 py-2 tabular-nums">{formatInt(row.cveCount)}</td>
                    <td className="border-b border-[var(--vc-line)] px-3 py-2">
                      {row.kevCount > 0 ? <span className="rounded bg-[#ff4d5e] px-1.5 py-0.5 text-[10px] font-bold text-white">{formatInt(row.kevCount)}</span> : <span className={on ? "text-white/70" : "text-[var(--vc-muted)]"}>—</span>}
                    </td>
                    <td className={`border-b border-[var(--vc-line)] px-3 py-2 tabular-nums ${on ? "text-white" : "text-[var(--vc-epss)]"}`}>{formatEpss(row.maxEpss)}</td>
                    <td className="border-b border-[var(--vc-line)] px-3 py-2">
                      <ExploitCell row={row} inverted={on} />
                    </td>
                  </tr>
                );
              })}
              {!list.isLoading && !rows.length ? (
                <tr>
                  <td colSpan={7} className="px-3 py-8 text-center text-[var(--vc-muted)]">
                    {list.isError ? "Каталог не загрузился." : "В этом срезе продуктов нет."}
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
        <div className="flex items-center justify-between border-t border-[var(--vc-border)] px-3 py-2 text-[12px] text-[var(--vc-muted)]">
          <span>{rangeLabel(from, to, total)}</span>
          <span className="flex gap-3">
            <button type="button" disabled={page === 0} className="disabled:opacity-40" onClick={() => setPage((value) => Math.max(0, value - 1))}>Назад</button>
            <button type="button" disabled={!hasNext || list.isFetching} className="disabled:opacity-40" onClick={() => setPage((value) => value + 1)}>Дальше</button>
          </span>
        </div>
      </section>
      {selected ? <ProductDrawer pick={selected} onClose={closeProduct} /> : null}
    </div>
  );
}

function ProductDrawer({ pick, onClose }: { pick: ProductPick; onClose: () => void }) {
  const detail = useProductDetail(pick.vendorKey, pick.productKey);
  const card = detail.data?.found ? detail.data : null;

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const openCve = () => {
    sessionStorage.setItem(PRODUCT_KEY, JSON.stringify(pick));
    stashVcPage("products");
  };

  return (
    <div className="fixed inset-0 z-40">
      <button type="button" aria-label="Закрыть просмотр" className="absolute inset-0 bg-black/45" onClick={onClose} />
      <aside className="absolute inset-y-0 right-0 flex w-full flex-col border-l border-[var(--vc-border)] bg-[var(--vc-surface)] text-[var(--vc-text)] shadow-2xl sm:w-[640px]">
        <div className="flex items-start justify-between gap-3 border-b border-[var(--vc-border)] px-4 py-3">
          <div className="min-w-0">
            <button type="button" onClick={onClose} className="text-[12px] text-[var(--vc-link)] hover:underline">← К списку продуктов</button>
            <div className="mt-1 flex flex-wrap items-center gap-2">
              <h2 className="text-[18px] font-semibold">{pretty(card?.product || pick.product)}</h2>
              {card ? <RiskChip score={card.maxRisk} /> : null}
            </div>
            <p className="mt-0.5 text-[12px] text-[var(--vc-muted)]">{pretty(card?.vendor || pick.vendor)}</p>
          </div>
          <button type="button" onClick={onClose} className="rounded p-1 text-[var(--vc-muted)] hover:bg-[var(--vc-hover)]" aria-label="Закрыть">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-4 py-3">
          {detail.isLoading ? <p className="text-[12px] text-[var(--vc-muted)]">Загрузка продукта…</p> : null}
          {detail.isError ? <p className="text-[12px] text-[var(--vc-danger-text)]">Карточка продукта не загрузилась.</p> : null}
          {detail.data && detail.data.found === false ? <p className="text-[12px] text-[var(--vc-muted)]">Этой связки нет в каталоге.</p> : null}
          {card ? (
            <>
              <div className="grid grid-cols-2 gap-2">
                <Stat label="CVE" value={formatInt(card.cveCount)} hint="в каталоге" color="var(--vc-primary)" />
                <Stat label="Риск" value={formatInt(card.maxRisk)} hint="максимум 0–100" color={riskTone(card.maxRisk)} />
                <Stat label="EPSS" value={formatEpss(card.maxEpss)} hint="максимум по CVE" color="var(--vc-epss)" />
                <Stat label="KEV" value={formatInt(card.kevCount)} hint={card.kevCount ? "в каталоге CISA" : "записей KEV нет"} color={card.kevCount ? "#ff4d5e" : "var(--vc-muted)"} />
              </div>
              <div className="flex flex-wrap gap-1.5">
                <Pill tone={card.exploitCount ? "#ff8a3d" : "var(--vc-muted)"}>Публичный эксплойт {card.exploitCount ? formatInt(card.exploitCount) : "нет"}</Pill>
                <Pill tone={card.pocCount ? "#ff8a3d" : "var(--vc-muted)"}>PoC {card.pocCount ? formatInt(card.pocCount) : "нет"}</Pill>
                <Pill tone={card.fixedVersions.length || card.cves.some((row) => row.has_patch) ? "#3dd68c" : "var(--vc-muted)"}>
                  {card.fixedVersions.length || card.cves.some((row) => row.has_patch) ? "Исправление указано" : "Исправление не указано"}
                </Pill>
              </div>
              <section>
                <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">Версии</h3>
                {card.versions.length ? (
                  <div className="flex flex-wrap gap-1.5">
                    {card.versions.map((version) => (
                      <span key={version} className="rounded-md border border-[#ff4d5e]/40 bg-[#ff4d5e]/10 px-2 py-1 font-mono text-[11px] text-[var(--vc-critical-text)]">{version}</span>
                    ))}
                  </div>
                ) : <p className="text-[12px] text-[var(--vc-muted)]">Диапазоны версий в CPE у показанных CVE не указаны.</p>}
                {card.fixedVersions.length ? (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {card.fixedVersions.map((version) => (
                      <span key={version} className="rounded-md border border-[#3dd68c]/40 bg-[#3dd68c]/10 px-2 py-1 font-mono text-[11px] text-[var(--vc-success-text)]">{version}</span>
                    ))}
                  </div>
                ) : null}
                <p className="mt-2 text-[11px] text-[var(--vc-muted)]">
                  {card.shown < card.cveCount
                    ? `Версии и таблица — по ${formatInt(card.shown)} CVE с наибольшим риском из ${formatInt(card.cveCount)}.`
                    : `Показаны все ${formatInt(card.cveCount)} CVE этой связки.`}
                </p>
              </section>
              <section>
                <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">CVE</h3>
                {card.cves.length ? (
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[520px] text-left text-[12px]">
                      <thead className="text-[10px] uppercase text-[var(--vc-muted)]">
                        <tr>
                          {["CVE", "Риск", "CVSS", "EPSS", "Сигналы", "Версия"].map((label) => (
                            <th key={label} className="py-1.5 pr-2 font-medium">{label}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {card.cves.map((row) => {
                          const band = cvssBand(row.cvss_base);
                          return (
                            <tr key={row.cve_id} className="border-t border-[var(--vc-line)]">
                              <td className="py-1.5 pr-2">
                                <Link href={vulnerabilityPath(row.cve_id) as Route} onClick={openCve} className="font-mono font-semibold text-[var(--vc-link)] hover:underline">{row.cve_id}</Link>
                              </td>
                              <td className="py-1.5 pr-2"><RiskChip score={row.risk_score} /></td>
                              <td className="py-1.5 pr-2">
                                {band ? <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold text-white" style={{ background: band.color }}>{row.cvss_base?.toFixed(1)}</span> : <span className="text-[var(--vc-muted)]">—</span>}
                              </td>
                              <td className="py-1.5 pr-2 tabular-nums text-[var(--vc-epss)]">{formatEpss(row.epss)}</td>
                              <td className="py-1.5 pr-2">
                                <div className="flex flex-wrap gap-1">
                                  {row.kev ? <span className="rounded bg-[#ff4d5e] px-1 py-0.5 text-[9px] font-bold text-white">KEV</span> : null}
                                  {row.has_public_exploit ? <span className="rounded bg-[#ff8a3d] px-1 py-0.5 text-[9px] font-bold text-white">Exploit</span> : null}
                                  {row.has_poc && !row.has_public_exploit ? <span className="rounded bg-[#ff8a3d] px-1 py-0.5 text-[9px] font-bold text-white">PoC</span> : null}
                                  {row.has_patch ? <span className="rounded bg-[#3dd68c] px-1 py-0.5 text-[9px] font-bold text-[#06281a]">Патч</span> : null}
                                  {!row.kev && !row.has_public_exploit && !row.has_poc && !row.has_patch ? <span className="text-[var(--vc-muted)]">—</span> : null}
                                </div>
                              </td>
                              <td className="py-1.5 pr-2 font-mono text-[11px] text-[var(--vc-muted)]">{row.version || "—"}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                ) : <p className="text-[12px] text-[var(--vc-muted)]">CVE по этой связке не найдены.</p>}
              </section>
            </>
          ) : null}
        </div>
      </aside>
    </div>
  );
}

function Stat({ label, value, hint, color }: { label: string; value: string; hint?: string; color: string }) {
  return (
    <div className="rounded-xl border bg-[var(--vc-surface)] px-3 py-2.5" style={{ borderColor: `color-mix(in srgb, ${color} 50%, var(--vc-border))` }}>
      <div className="text-[10px] font-semibold uppercase tracking-wide" style={{ color }}>{label}</div>
      <div className="mt-1 text-[22px] font-semibold tabular-nums leading-none" style={{ color }}>{value}</div>
      {hint ? <div className="mt-1 text-[10px] leading-4 text-[var(--vc-muted)]">{hint}</div> : null}
    </div>
  );
}

function Pill({ children, tone }: { children: ReactNode; tone: string }) {
  return (
    <span className="rounded-md px-2 py-0.5 text-[11px] font-medium" style={{ color: tone, background: `color-mix(in srgb, ${tone} 14%, transparent)` }}>
      {children}
    </span>
  );
}

function RiskChip({ score }: { score: number | null }) {
  if (score == null) return <span className="text-[var(--vc-muted)]">—</span>;
  return (
    <span className="inline-flex min-w-[2.4rem] justify-center rounded-md px-1.5 py-0.5 text-[12px] font-bold tabular-nums text-white" style={{ background: riskTone(score) }}>
      {formatInt(score)}
    </span>
  );
}

function ExploitCell({ row, inverted }: { row: ProductRow; inverted: boolean }) {
  if (row.exploitCount > 0) return <span className="rounded bg-[#ff8a3d] px-1.5 py-0.5 text-[10px] font-bold text-white">{formatInt(row.exploitCount)}</span>;
  if (row.pocCount > 0) return <span className="rounded bg-[#ff8a3d] px-1.5 py-0.5 text-[10px] font-bold text-white">PoC {formatInt(row.pocCount)}</span>;
  return <span className={inverted ? "text-white/70" : "text-[var(--vc-muted)]"}>—</span>;
}

function riskTone(score: number | null) {
  if (score == null || !Number.isFinite(score)) return "var(--vc-muted)";
  if (score >= 90) return "#ff4d5e";
  if (score >= 70) return "#ff8a3d";
  if (score >= 40) return "#f5c451";
  return "#3dd68c";
}

function pretty(value: string) {
  return value.replaceAll("_", " ");
}

function rangeLabel(from: number, to: number, total: number | null) {
  if (!from) return total != null ? `0 из ${formatInt(total)}` : "0 записей";
  return total != null ? `${formatInt(from)}–${formatInt(to)} из ${formatInt(total)}` : `${formatInt(from)}–${formatInt(to)}`;
}

function uniqueVendors(rows: Array<{ vendorKey: string; vendor: string; count: number }>, active: string) {
  const map = new Map(rows.map((row) => [row.vendorKey, row]));
  if (active !== "all" && !map.has(active)) map.set(active, { vendorKey: active, vendor: active, count: 0 });
  return [...map.values()];
}

function useDebounced(value: string, ms: number) {
  const [current, setCurrent] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setCurrent(value), ms);
    return () => window.clearTimeout(timer);
  }, [value, ms]);
  return current;
}

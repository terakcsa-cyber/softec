"use client";

import { useEffect, useState } from "react";
import { useVc } from "./vc-context";
import { cvssBand, formatDate, formatInt, knownCatalogTotal, useCatalogSummary, useCveList } from "@/lib/vulncontrol/live";

const PAGE = 25;

const LEVEL: Record<string, string> = {
  critical: "Критическая",
  high: "Высокая",
  medium: "Средняя",
  low: "Низкая"
};

export function LiveCveTable({ caption, registry = false }: { caption?: string; registry?: boolean }) {
  const { query, setQuery, resetQuery, setSelectedId, selectedId, setPage: setVcPage } = useVc();
  const summary = useCatalogSummary();
  const [page, setPage] = useState(0);
  const filterKey = `${query.q}|${query.severity}|${query.tab}|${query.vendor}|${query.product}|${query.status}|${query.kevAddedDays ?? ""}|${query.publishedDays ?? ""}|${query.exploitSignal}`;
  useEffect(() => {
    setPage(0);
  }, [filterKey]);

  const known = registry ? knownCatalogTotal(query, summary.data) : null;
  const list = useCveList(query, {
    limit: registry ? PAGE : 12,
    offset: registry ? page * PAGE : 0,
    includeTotal: registry && known == null && !query.q.trim()
  });
  const rows = dedupeRows(list.data?.items ?? []);
  const total = known ?? list.data?.total ?? null;
  const from = rows.length ? page * PAGE + 1 : 0;
  const to = page * PAGE + rows.length;
  const filtered = Boolean(
    query.q.trim()
    || query.severity !== "all"
    || query.tab !== "all"
    || query.vendor !== "all"
    || query.product !== "all"
    || query.status !== "all"
    || query.kevAddedDays != null
    || query.publishedDays != null
    || query.exploitSignal !== "all"
  );
  const hasNext = total != null ? to < total : rows.length === (registry ? PAGE : 12);

  return (
    <section className="overflow-hidden rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)]">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--vc-border)] px-3 py-2">
        <p className="text-[12px] text-[var(--vc-muted)]">
          {list.isLoading && !rows.length ? "Загрузка реестра…" : list.isError ? "Реестр не загрузился." : rangeLabel(from, to, total)}
          {caption ? ` · ${caption}` : ""}
        </p>
        {filtered ? (
          <button type="button" className="text-[12px] text-[var(--vc-link)]" onClick={resetQuery}>
            Сбросить фильтры
          </button>
        ) : null}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[1080px] border-separate border-spacing-0 text-left text-[12px]">
          <thead className="text-[10px] uppercase tracking-wide text-[var(--vc-muted)]">
            <tr>
              {["CVE / ID", "Риск", "Уровень", "Название уязвимости", "БДУ", "Продукт", "Версия", "Вендор", "Публикация"].map((label) => (
                <th key={label} className="bg-[var(--vc-table-head)] px-3 py-2.5 font-medium">{label}</th>
              ))}
            </tr>
          </thead>
          <tbody key={`${filterKey}:${page}`}>
            {rows.map((row) => {
              const band = cvssBand(row.cvss_base);
              const selected = row.cve_id === selectedId;
              const title = row.short_ru || row.short_description || "";
              const line = selected ? "border-white/10" : "border-[var(--vc-line-mid)]";
              const bduIds = (row.bdu_ids ?? []).filter(Boolean);
              return (
                <tr key={row.cve_id} className={selected ? "bg-[var(--vc-selected)] text-white" : "hover:bg-[var(--vc-hover-row)]"}>
                  <td className={`border-b ${line} px-3 py-2`}>
                    <button
                      type="button"
                      className={`whitespace-nowrap font-mono text-[12px] font-semibold hover:underline ${selected ? "text-white" : "text-[var(--vc-link)]"}`}
                      onClick={() => setSelectedId(row.cve_id)}
                    >
                      {row.cve_id}
                    </button>
                    {row.exploit_known ? <span className="ml-1.5 rounded bg-[#ff4d5e] px-1 py-0.5 text-[9px] font-bold text-white">KEV</span> : null}
                  </td>
                  <td className={`border-b ${line} px-3 py-2`}>
                    <span
                      className="inline-flex min-w-[2.4rem] justify-center rounded-md px-1.5 py-0.5 text-[12px] font-bold tabular-nums text-white"
                      style={{ background: riskTone(row.risk_score) }}
                    >
                      {row.risk_score == null ? "—" : formatInt(row.risk_score)}
                    </span>
                  </td>
                  <td className={`border-b ${line} px-3 py-2`}>
                    {band ? (
                      <span className="rounded-md px-2 py-0.5 text-[11px] font-semibold text-white" style={{ background: band.color }}>
                        {LEVEL[band.key]}
                      </span>
                    ) : <span className={selected ? "text-white/70" : "text-[var(--vc-muted)]"}>—</span>}
                  </td>
                  <td className={`max-w-[320px] truncate border-b ${line} px-3 py-2`} title={title}>{title || "—"}</td>
                  <td className={`border-b ${line} px-3 py-2`}>
                    {bduIds.length ? (
                      <div className="flex flex-wrap gap-1">
                        {bduIds.slice(0, 2).map((bduId) => (
                          <button
                            key={bduId}
                            type="button"
                            className={`rounded border px-1.5 py-0.5 font-mono text-[10px] hover:underline ${selected ? "border-white/30 text-white" : "border-[var(--vc-border)] text-[var(--vc-link)]"}`}
                            onClick={() => {
                              try {
                                sessionStorage.setItem("vip:vc-bdu", bduId);
                              } catch {
                                // ignore
                              }
                              setVcPage("bdu");
                            }}
                          >
                            {bduId}
                          </button>
                        ))}
                        {bduIds.length > 2 ? <span className={selected ? "text-white/70" : "text-[var(--vc-muted)]"}>+{bduIds.length - 2}</span> : null}
                      </div>
                    ) : (
                      <span className={selected ? "text-white/70" : "text-[var(--vc-muted)]"}>—</span>
                    )}
                  </td>
                  <td className={`border-b ${line} px-3 py-2`}>
                    {row.vp_product ? (
                      <button type="button" className={`text-left hover:underline ${selected ? "text-white" : "hover:text-[var(--vc-link)]"}`} onClick={() => setQuery({ product: row.vp_product!, severity: "all", tab: "all" })}>
                        {row.vp_product}
                      </button>
                    ) : "—"}
                  </td>
                  <td className={`border-b ${line} px-3 py-2 tabular-nums ${selected ? "text-white/90" : "text-[var(--vc-muted)]"}`}>{row.affected_version || "—"}</td>
                  <td className={`border-b ${line} px-3 py-2`}>
                    {row.vp_vendor ? (
                      <button type="button" className={`hover:underline ${selected ? "text-white" : "text-[var(--vc-muted)] hover:text-[var(--vc-link)]"}`} onClick={() => setQuery({ vendor: row.vp_vendor!, severity: "all", tab: "all" })}>
                        {row.vp_vendor}
                      </button>
                    ) : "—"}
                  </td>
                  <td className={`whitespace-nowrap border-b ${line} px-3 py-2 tabular-nums ${selected ? "text-white/90" : "text-[var(--vc-muted)]"}`}>
                    {formatDate(row.published_at)}
                  </td>
                </tr>
              );
            })}
            {!list.isLoading && !rows.length ? (
              <tr>
                <td colSpan={9} className="px-3 py-8 text-center text-[var(--vc-muted)]">Нет записей по этому фильтру</td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
      {registry ? (
        <div className="flex items-center justify-between border-t border-[var(--vc-border)] px-3 py-2 text-[12px] text-[var(--vc-muted)]">
          <span>{rangeLabel(from, to, total)}</span>
          <span className="flex gap-3">
            <button type="button" disabled={page === 0} className="disabled:opacity-40" onClick={() => setPage((value) => Math.max(0, value - 1))}>Назад</button>
            <button type="button" disabled={!hasNext || list.isFetching} className="disabled:opacity-40" onClick={() => setPage((value) => value + 1)}>Дальше</button>
          </span>
        </div>
      ) : null}
    </section>
  );
}

function dedupeRows<T extends { cve_id: string }>(items: T[]) {
  const seen = new Set<string>();
  return items.filter((row) => {
    if (seen.has(row.cve_id)) return false;
    seen.add(row.cve_id);
    return true;
  });
}

function rangeLabel(from: number, to: number, total: number | null) {
  if (!from) return total != null ? `0 из ${formatInt(total)}` : "0 записей";
  return total != null ? `${formatInt(from)}–${formatInt(to)} из ${formatInt(total)}` : `${formatInt(from)}–${formatInt(to)}`;
}

function riskTone(score: number | null) {
  if (score == null || !Number.isFinite(score)) return "var(--vc-slate)";
  if (score >= 90) return "var(--vc-critical)";
  if (score >= 70) return "var(--vc-high)";
  if (score >= 40) return "var(--vc-medium)";
  return "var(--vc-success)";
}

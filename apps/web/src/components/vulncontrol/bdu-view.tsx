"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { ExternalLink, X } from "lucide-react";
import {
  formatInt,
  useBduDetail,
  useBduList,
  useCatalogSummary
} from "@/lib/vulncontrol/live";
import { stashVcPage, vulnerabilityPath, useVc } from "./vc-context";

const PAGE = 25;
const BDU_KEY = "vip:vc-bdu";

const FILTERS: Array<{ id: "all" | "linked" | "unlinked" | "urgent" | "day"; label: string; hint: string }> = [
  { id: "all", label: "Весь каталог", hint: "Записи реестра БДУ ФСТЭК" },
  { id: "linked", label: "С CVE", hint: "Есть маппинг на CVE в платформе" },
  { id: "unlinked", label: "Без CVE", hint: "Пока без связки cve_bdu_link / cve_ids" },
  { id: "urgent", label: "Срочные", hint: "Эксплойт, высокий CVSS или связанный EPSS/KEV" },
  { id: "day", label: "За 24 часа", hint: "Публикация / обновление в окне внимания" }
];

export function BduView() {
  const { query, setPage } = useVc();
  const summary = useCatalogSummary();
  const [filter, setFilter] = useState<(typeof FILTERS)[number]["id"]>("all");
  const [page, setListPage] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const q = useDebounced(query.q, 250);
  const list = useBduList({ q, filter, limit: PAGE, offset: page * PAGE });
  const detail = useBduDetail(selectedId);
  const rows = list.data?.items ?? [];
  const from = rows.length ? page * PAGE + 1 : 0;
  const to = page * PAGE + rows.length;
  const hasNext = rows.length === PAGE;
  const tab = FILTERS.find((item) => item.id === filter) ?? FILTERS[0]!;
  const totalBdu = summary.data?.totalBduCount;
  const linkCount = summary.data?.cveBduLinkCount;

  useEffect(() => {
    setListPage(0);
  }, [filter, q]);

  useEffect(() => {
    try {
      const raw = sessionStorage.getItem(BDU_KEY);
      if (raw) setSelectedId(raw);
    } catch {
      sessionStorage.removeItem(BDU_KEY);
    }
  }, []);

  const openBdu = (id: string) => {
    setSelectedId(id);
    sessionStorage.setItem(BDU_KEY, id);
  };
  const closeBdu = () => {
    setSelectedId(null);
    sessionStorage.removeItem(BDU_KEY);
  };

  return (
    <div className="space-y-3">
      <div>
        <h1 className="text-[20px] font-semibold tracking-tight">БДУ ФСТЭК</h1>
        <p className="text-[12px] text-[var(--vc-muted)]">
          Каталог записей БДУ и маппинг на CVE из `cve_bdu_link` и полей реестра. Пустое поле остаётся пустым.
        </p>
      </div>

      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Записей БДУ" value={totalBdu == null ? "…" : formatInt(totalBdu)} hint="таблица bdu_vuln" color="var(--vc-primary)" />
        <Stat label="Связок CVE↔БДУ" value={linkCount == null ? "…" : formatInt(linkCount)} hint="cve_bdu_link" color="#3dd68c" />
        <Stat label="В срезе" value={formatInt(rows.length)} hint={tab.hint} color="#ff8a3d" />
        <Stat
          label="Открыть CVE"
          value="реестр"
          hint="перейти к уязвимостям"
          color="#2f6bff"
          onClick={() => setPage("vulns")}
        />
      </div>

      <div className="flex gap-5 overflow-x-auto border-b border-[var(--vc-border)]">
        {FILTERS.map((item) => {
          const on = filter === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setFilter(item.id)}
              className={`relative shrink-0 pb-2.5 text-[13px] ${on ? "font-medium text-[var(--vc-text)]" : "text-[var(--vc-muted)] hover:text-[var(--vc-text)]"}`}
            >
              {item.label}
              {on ? <span className="absolute inset-x-0 -bottom-px h-0.5 rounded-full bg-[var(--vc-primary)]" /> : null}
            </button>
          );
        })}
      </div>

      <div className={`grid gap-3 ${selectedId ? "xl:grid-cols-[1.2fr_0.8fr]" : ""}`}>
        <section className="overflow-hidden rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)]">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--vc-border)] px-3 py-2 text-[12px] text-[var(--vc-muted)]">
            <span>
              {list.isLoading && !rows.length
                ? "Загрузка каталога БДУ…"
                : list.isError
                  ? "Каталог БДУ не загрузился."
                  : `${formatInt(from)}–${formatInt(to)}${hasNext ? "+" : ""} · ${tab.label}`}
            </span>
            {q.trim() ? <span>Поиск: {q.trim()}</span> : null}
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] border-separate border-spacing-0 text-left text-[12px]">
              <thead className="text-[10px] uppercase tracking-wide text-[var(--vc-muted)]">
                <tr>
                  {["БДУ", "CVSS", "Название", "CVE (маппинг)", "Эксплойт", "Исправление", "Дата"].map((label) => (
                    <th key={label} className="bg-[var(--vc-table-head)] px-3 py-2.5 font-medium">{label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const selected = row.bduId === selectedId;
                  const line = selected ? "border-white/10" : "border-[var(--vc-line-mid)]";
                  const mapped = uniqueIds([...(row.linkedCveIds ?? []), ...(row.cveIds ?? [])]);
                  return (
                    <tr key={row.bduId} className={selected ? "bg-[var(--vc-selected)] text-white" : "hover:bg-[var(--vc-hover-row)]"}>
                      <td className={`border-b ${line} px-3 py-2`}>
                        <button
                          type="button"
                          className={`font-mono text-[12px] font-semibold hover:underline ${selected ? "text-white" : "text-[var(--vc-link)]"}`}
                          onClick={() => openBdu(row.bduId)}
                        >
                          {row.bduId}
                        </button>
                      </td>
                      <td className={`border-b ${line} px-3 py-2 tabular-nums`}>
                        {row.cvssScore == null ? "—" : row.cvssScore.toFixed(1)}
                      </td>
                      <td className={`max-w-[280px] truncate border-b ${line} px-3 py-2`} title={row.name}>
                        {row.name || "—"}
                      </td>
                      <td className={`border-b ${line} px-3 py-2`}>
                        {mapped.length ? (
                          <div className="flex flex-wrap gap-1">
                            {mapped.slice(0, 3).map((cveId) => (
                              <Link
                                key={cveId}
                                href={vulnerabilityPath(cveId)}
                                onClick={() => stashVcPage("bdu")}
                                className={`font-mono text-[11px] hover:underline ${selected ? "text-white" : "text-[var(--vc-link)]"}`}
                              >
                                {cveId}
                              </Link>
                            ))}
                            {mapped.length > 3 ? <span className={selected ? "text-white/70" : "text-[var(--vc-muted)]"}>+{mapped.length - 3}</span> : null}
                          </div>
                        ) : (
                          <span className={selected ? "text-white/70" : "text-[var(--vc-muted)]"}>нет</span>
                        )}
                      </td>
                      <td className={`border-b ${line} px-3 py-2`}>{row.hasExploit ? "да" : "нет"}</td>
                      <td className={`border-b ${line} px-3 py-2`}>{row.hasFix ? "да" : "нет"}</td>
                      <td className={`border-b ${line} px-3 py-2 ${selected ? "text-white/80" : "text-[var(--vc-muted)]"}`}>
                        {row.publicationDate || row.identifyDate || "—"}
                      </td>
                    </tr>
                  );
                })}
                {!list.isLoading && !rows.length ? (
                  <tr>
                    <td colSpan={7} className="px-3 py-8 text-center text-[var(--vc-muted)]">
                      В каталоге нет записей по этому срезу. Если весь БДУ пуст — проверьте синхронизацию в Настройках / Health.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
          <div className="flex items-center justify-between border-t border-[var(--vc-border)] px-3 py-2 text-[12px] text-[var(--vc-muted)]">
            <span>{formatInt(from)}–{formatInt(to)}</span>
            <span className="flex gap-3">
              <button type="button" disabled={page === 0} className="disabled:opacity-40" onClick={() => setListPage((value) => Math.max(0, value - 1))}>
                Назад
              </button>
              <button type="button" disabled={!hasNext || list.isFetching} className="disabled:opacity-40" onClick={() => setListPage((value) => value + 1)}>
                Дальше
              </button>
            </span>
          </div>
        </section>

        {selectedId ? (
          <BduDetailPane
            bduId={selectedId}
            loading={detail.isLoading}
            error={detail.isError}
            data={detail.data}
            onClose={closeBdu}
          />
        ) : null}
      </div>
    </div>
  );
}

function BduDetailPane({
  bduId,
  loading,
  error,
  data,
  onClose
}: {
  bduId: string;
  loading: boolean;
  error: boolean;
  data: ReturnType<typeof useBduDetail>["data"];
  onClose: () => void;
}) {
  const item = data && data.found ? data.bdu : null;
  const mapped = useMemo(
    () => uniqueIds([...(item?.linkedCveIds ?? []), ...(item?.cveIds ?? []), ...((data && data.found ? data.links?.cves?.map((row) => row.cveId) : []) ?? [])]),
    [item, data]
  );
  const fstec = (data && data.found ? data.links?.fstec : null) || item?.fstecUrl || `https://bdu.fstec.ru/vul/${encodeURIComponent(bduId)}`;

  return (
    <aside className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-4">
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="font-mono text-[16px] font-semibold">BDU:{bduId}</div>
          <p className="mt-1 text-[12px] text-[var(--vc-muted)]">{item?.name || "Карточка БДУ"}</p>
        </div>
        <button type="button" onClick={onClose} className="rounded-md border border-[var(--vc-border)] p-1 text-[var(--vc-muted)] hover:bg-[var(--vc-hover)]" aria-label="Закрыть">
          <X className="h-3.5 w-3.5" />
        </button>
      </div>

      {loading ? <p className="mt-4 text-[12px] text-[var(--vc-muted)]">Загрузка…</p> : null}
      {error ? <p className="mt-4 text-[12px] text-[var(--vc-danger-text)]">Карточка БДУ не загрузилась.</p> : null}
      {data && data.found === false ? <p className="mt-4 text-[12px] text-[var(--vc-muted)]">Записи нет в каталоге.</p> : null}

      {item ? (
        <div className="mt-4 space-y-4 text-[12px]">
          <FactGrid
            rows={[
              { label: "CVSS", value: item.cvssScore == null ? "—" : item.cvssScore.toFixed(1) },
              { label: "Уровень ФСТЭК", value: item.severity || (item.severityLevel != null ? String(item.severityLevel) : "—") },
              { label: "Эксплойт", value: item.exploitStatus || (item.hasExploit ? "да" : "нет") },
              { label: "Исправление", value: item.fixStatus || (item.hasFix ? "да" : "нет") },
              { label: "Публикация", value: item.publicationDate || "—" },
              { label: "Обновление", value: item.lastUpdDate || "—" }
            ]}
          />

          {item.description ? (
            <section>
              <h3 className="text-[11px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">Описание</h3>
              <p className="mt-1 whitespace-pre-wrap leading-5">{item.description}</p>
            </section>
          ) : null}

          <section>
            <h3 className="text-[11px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">Маппинг на CVE</h3>
            {mapped.length ? (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {mapped.map((cveId) => (
                  <Link
                    key={cveId}
                    href={vulnerabilityPath(cveId)}
                    onClick={() => stashVcPage("bdu")}
                    className="rounded-md border border-[var(--vc-border)] px-2 py-1 font-mono text-[11px] text-[var(--vc-link)] hover:bg-[var(--vc-hover)]"
                  >
                    {cveId}
                  </Link>
                ))}
              </div>
            ) : (
              <p className="mt-1 text-[var(--vc-muted)]">Связанных CVE в платформе нет.</p>
            )}
          </section>

          {item.solution ? (
            <section>
              <h3 className="text-[11px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">Решение ФСТЭК</h3>
              <p className="mt-1 whitespace-pre-wrap leading-5 text-[var(--vc-muted)]">{item.solution}</p>
            </section>
          ) : null}

          {(item.vendors || item.softwareNames) ? (
            <section>
              <h3 className="text-[11px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">ПО</h3>
              <p className="mt-1 leading-5">{[item.vendors, item.softwareNames].filter(Boolean).join(" · ")}</p>
            </section>
          ) : null}

          <a
            href={fstec}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1.5 text-[11px] font-medium text-[var(--vc-link)] hover:underline"
          >
            Открыть на bdu.fstec.ru
            <ExternalLink className="h-3 w-3" aria-hidden />
          </a>
        </div>
      ) : null}
    </aside>
  );
}

function FactGrid({ rows }: { rows: Array<{ label: string; value: string }> }) {
  return (
    <dl className="grid grid-cols-2 gap-2">
      {rows.map((row) => (
        <div key={row.label} className="rounded-lg border border-[var(--vc-border)] px-2.5 py-2">
          <dt className="text-[10px] uppercase tracking-wide text-[var(--vc-muted)]">{row.label}</dt>
          <dd className="mt-0.5">{row.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function Stat({
  label,
  value,
  hint,
  color,
  onClick
}: {
  label: string;
  value: string;
  hint: string;
  color: string;
  onClick?: () => void;
}) {
  const Comp = onClick ? "button" : "div";
  return (
    <Comp
      type={onClick ? "button" : undefined}
      onClick={onClick}
      className={`rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] px-3 py-2.5 text-left ${onClick ? "hover:bg-[var(--vc-hover-soft)]" : ""}`}
    >
      <div className="text-[10px] uppercase tracking-wide text-[var(--vc-muted)]">{label}</div>
      <div className="mt-1 text-[18px] font-semibold tabular-nums" style={{ color }}>{value}</div>
      <div className="mt-0.5 text-[11px] text-[var(--vc-muted)]">{hint}</div>
    </Comp>
  );
}

function uniqueIds(ids: string[]) {
  const out: string[] = [];
  for (const id of ids) {
    const next = id.trim().toUpperCase();
    if (!next || out.includes(next)) continue;
    out.push(next);
  }
  return out;
}

function useDebounced(value: string, ms: number) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const id = window.setTimeout(() => setDebounced(value), ms);
    return () => window.clearTimeout(id);
  }, [value, ms]);
  return debounced;
}

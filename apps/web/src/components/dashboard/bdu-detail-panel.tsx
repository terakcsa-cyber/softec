"use client";

import { useCallback, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";
import { parseAiOutputJson } from "@/lib/bdu-enrich-ui";
import { computeBduPriority, bduRiskScore } from "@/lib/bdu-priority";
import { ExternalLink, FileDown, X } from "lucide-react";
import { TelegramPostButton } from "./telegram-post-button";
import { AiSummaryPanel } from "./ai-summary-panel";
import { VulnTicketHistory } from "./vuln-ticket-history";
import { DetailFactList, DetailMetricGrid, DetailSection, DetailTabs } from "./vuln-detail-chrome";
import type { BduListItem } from "./bdu-card";

type DetailTab = "general" | "products" | "fixes" | "history" | "sources";

export type BduDetail = BduListItem & {
  description?: string | null;
  softwareNames?: string | null;
  vendors?: string | null;
  solution?: string | null;
  status?: string | null;
  exploitStatus?: string | null;
  fixStatus?: string | null;
  publicationDate?: string | null;
  lastUpdDate?: string | null;
  cvssVector?: string | null;
  sources?: string | null;
  updatedAt?: string | null;
};

function fmtDateShort(s?: string | null) {
  if (!s) return "—";
  if (/\d{2}\.\d{2}\.\d{4}/.test(s)) return s;
  const d = new Date(s);
  return Number.isFinite(d.getTime()) ? d.toLocaleDateString() : String(s);
}

function parseSoftwareLines(softwareNames?: string | null, vendors?: string | null): Array<{ vendor: string; product: string }> {
  const out: Array<{ vendor: string; product: string }> = [];
  const names = (softwareNames ?? "")
    .split(/\s{2,}|\n|;/)
    .map((s) => s.trim())
    .filter(Boolean);
  const vendorList = (vendors ?? "")
    .split(/\s{2,}|\n|;/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (names.length === 0 && vendorList.length === 0) return out;
  const n = Math.max(names.length, vendorList.length, 1);
  for (let i = 0; i < n && out.length < 40; i++) {
    out.push({
      vendor: vendorList[i] ?? vendorList[0] ?? "—",
      product: names[i] ?? names[0] ?? "—"
    });
  }
  return out;
}

function extractTaskErrorMessage(status: number, raw: string): string {
  let message = raw.trim();
  if (message) {
    try {
      const parsed = JSON.parse(message) as unknown;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        const obj = parsed as Record<string, unknown>;
        const m = obj.message;
        if (Array.isArray(m)) message = m.map(String).join("; ");
        else if (typeof m === "string") message = m;
        else if (typeof obj.error === "string") message = obj.error;
      }
    } catch {
      // Keep plain text responses as-is.
    }
  }
  if (status >= 500 || !message || message === "Internal server error") {
    return "Не удалось создать задачу. Попробуйте ещё раз или откройте связанный CVE и создайте задачу оттуда.";
  }
  return message;
}

export type BduDetailsPayload = {
  found?: boolean;
  bdu?: BduDetail | null;
  ai?: { output_json?: unknown; output_text?: unknown } | null;
  links?: { fstec?: string | null };
  /** Optional linked CVE NVD raw for client baseline maturity. */
  linkedCveRaw?: unknown;
};

export function BduDetailPanel({
  bduId,
  data: dataProp,
  loading: loadingProp,
  aiPending,
  aiStalled,
  manualEnrichAllowed,
  onRequestEnrich,
  onClose,
  onOpenCve,
  onOpenTask
}: {
  bduId: string;
  data?: BduDetailsPayload | null;
  loading?: boolean;
  aiPending?: boolean;
  aiStalled?: boolean;
  manualEnrichAllowed?: boolean;
  onRequestEnrich?: (opts?: { force?: boolean }) => void;
  onClose?: () => void;
  onOpenCve?: (cveId: string) => void;
  onOpenTask?: (taskId: string) => void;
}) {
  const q = useQuery({
    queryKey: ["bdu", "detail", bduId],
    enabled: !dataProp,
    queryFn: async () => {
      const res = await apiFetch(`/api/bdu/${encodeURIComponent(bduId)}`, { cache: "no-store" });
      if (!res.ok) throw new Error(`Не удалось загрузить BDU (${res.status})`);
      return (await res.json()) as BduDetailsPayload;
    }
  });

  const payload = dataProp ?? q.data ?? null;
  const d = payload?.found ? payload.bdu ?? null : null;
  const loading = loadingProp ?? (q.isLoading && !dataProp);
  const aiOut = useMemo(
    () =>
      parseAiOutputJson(payload?.ai?.output_json ?? null, {
        bduId,
        bdu: d ?? payload?.bdu,
        linkedCveRaw: payload?.linkedCveRaw
      }),
    [payload?.ai, payload?.bdu, payload?.linkedCveRaw, bduId, d]
  );
  const hasAiSummary = Boolean(aiOut?.summary || payload?.ai?.output_text);
  const pr = useMemo(() => (d ? computeBduPriority(d) : null), [d]);
  const risk = useMemo(() => (d ? bduRiskScore(d) : null), [d]);
  const products = useMemo(() => parseSoftwareLines(d?.softwareNames, d?.vendors), [d?.softwareNames, d?.vendors]);

  const [tab, setTab] = useState<DetailTab>("general");
  const [taskBusy, setTaskBusy] = useState(false);
  const [taskErr, setTaskErr] = useState<string | null>(null);
  const [dlBusy, setDlBusy] = useState(false);
  const [dlErr, setDlErr] = useState<string | null>(null);

  const onDownload = useCallback(async () => {
    if (!bduId || dlBusy) return;
    setDlBusy(true);
    setDlErr(null);
    try {
      const href = `/api/bdu/${encodeURIComponent(bduId)}/risk-xlsx`;
      const res = await apiFetch(href, { cache: "no-store" });
      if (!res.ok) {
        const txt = await res.text().catch(() => "");
        throw new Error(txt || `download failed (${res.status})`);
      }
      const blob = await res.blob();
      const cd = res.headers.get("content-disposition") ?? "";
      const m = cd.match(/filename="([^"]+)"/i);
      const filename = m?.[1] || `BDU-${bduId}-risk.xlsx`;
      const url = URL.createObjectURL(blob);
      try {
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
      } finally {
        setTimeout(() => URL.revokeObjectURL(url), 2000);
      }
    } catch (e) {
      setDlErr(e instanceof Error ? e.message : String(e));
    } finally {
      setDlBusy(false);
    }
  }, [bduId, dlBusy]);

  const primaryCve = d?.linkedCveIds?.[0] ?? d?.cveIds?.[0] ?? null;

  const tasksByCveQuery = useQuery({
    queryKey: ["vuln-tasks", "by-cve", primaryCve],
    enabled: Boolean(primaryCve),
    queryFn: async () => {
      const res = await apiFetch(`/api/vuln-tasks/by-cve/${encodeURIComponent(String(primaryCve))}`, {
        cache: "no-store"
      });
      if (!res.ok) throw new Error("failed to fetch tasks");
      return (await res.json()) as { items: Array<{ id: string; title?: string; status?: string; score_final?: number }> };
    },
    staleTime: 15_000
  });

  const createTaskFromBdu = useCallback(async () => {
    if (!primaryCve || taskBusy) return;
    const vp0 = products[0];
    const vendorDisplay = vp0?.vendor && vp0.vendor !== "—" ? vp0.vendor : "vendor";
    const productDisplay = vp0?.product && vp0.product !== "—" ? vp0.product : "";
    setTaskBusy(true);
    setTaskErr(null);
    try {
      const res = await apiFetch(`/api/vuln-tasks`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          title: `${vendorDisplay}${productDisplay ? ` / ${productDisplay}` : ""} — ${primaryCve} (BDU:${bduId})`,
          vendorKey: vendorDisplay.toLowerCase(),
          vendorDisplay,
          productKeyNorm: productDisplay ? productDisplay.toLowerCase().replace(/\s+/g, "_") : "",
          productDisplay,
          cveIds: [primaryCve],
          notesMd: [
            `Источник: BDU:${bduId}`,
            d?.name ? `Название БДУ: ${d.name}` : null,
            primaryCve ? `CVE из БДУ: ${primaryCve}` : null
          ]
            .filter(Boolean)
            .join("\n")
        })
      });
      if (!res.ok) {
        const txt = await res.text().catch(() => "");
        throw new Error(extractTaskErrorMessage(res.status, txt));
      }
      const j = (await res.json().catch(() => null)) as { id?: string } | null;
      await tasksByCveQuery.refetch();
      if (j?.id && onOpenTask) onOpenTask(String(j.id));
    } catch (e) {
      setTaskErr(e instanceof Error ? e.message : String(e));
    } finally {
      setTaskBusy(false);
    }
  }, [primaryCve, taskBusy, products, bduId, d?.name, tasksByCveQuery, onOpenTask]);

  const fstecUrl = d?.fstecUrl ?? `https://bdu.fstec.ru/vul/${encodeURIComponent(bduId)}`;
  const scoreTone = (n: number | null | undefined): "danger" | "warn" | "ok" | "neutral" => {
    if (n == null || !Number.isFinite(n)) return "neutral";
    if (n >= 85) return "danger";
    if (n >= 70) return "warn";
    if (n >= 40) return "ok";
    return "neutral";
  };
  const cvssTone = (n: number | null | undefined): "danger" | "warn" | "ok" | "neutral" => {
    if (n == null || !Number.isFinite(n)) return "neutral";
    if (n >= 9) return "danger";
    if (n >= 7) return "warn";
    if (n >= 4) return "ok";
    return "neutral";
  };

  return (
    <div className="glass rounded-2xl p-5">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="text-[10px] uppercase tracking-wide text-muted">Бюллетень БДУ</div>
          <h2 className="truncate text-lg font-semibold tracking-tight text-fg">BDU:{bduId}</h2>
          {d?.name ? <p className="mt-1 line-clamp-2 text-sm leading-snug text-fg/80">{d.name}</p> : null}
          {(d?.linkedCveIds ?? []).length > 0 ? (
            <p className="mt-1 flex flex-wrap gap-x-3 gap-y-1 font-mono text-[11px]">
              {(d?.linkedCveIds ?? []).map((cve) => (
                <button key={cve} type="button" onClick={() => onOpenCve?.(cve)} className="text-accent hover:underline">
                  {cve}
                </button>
              ))}
            </p>
          ) : null}
        </div>

        <div className="flex shrink-0 items-center gap-2">
          <TelegramPostButton kind="bdu" entityId={bduId} disabled={loading || !d} />
          <button
            type="button"
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs text-fg/90 shadow-sm hover:bg-slate-50 dark:border-border dark:bg-black/25 dark:shadow-none dark:hover:bg-black/35"
            onClick={() => void onDownload()}
            disabled={dlBusy}
            title="Скачать XLSX отчёт"
          >
            <FileDown className="h-3.5 w-3.5" aria-hidden />
            {dlBusy ? "Формируем…" : "Экспорт XLSX"}
          </button>
          {onClose ? (
            <button
              type="button"
              className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 bg-white text-fg/85 shadow-sm hover:bg-slate-50 dark:border-border dark:bg-black/25 dark:shadow-none dark:hover:bg-black/35"
              onClick={onClose}
              title="Закрыть"
            >
              <X className="h-4 w-4" aria-hidden />
            </button>
          ) : null}
        </div>
      </div>
      {dlErr ? <div className="mt-2 text-[11px] text-rose-700">{dlErr}</div> : null}

      <DetailMetricGrid
        items={[
          {
            label: "Приоритет",
            value: pr ? `${pr.score}` : "—",
            title: pr?.reasons?.join(" · "),
            tone: pr?.level === "critical" ? "danger" : pr?.level === "high" ? "warn" : pr?.level === "low" ? "ok" : "neutral"
          },
          { label: "Risk", value: risk == null ? "—" : String(risk), tone: scoreTone(risk) },
          {
            label: "CVSS",
            value: typeof d?.cvssScore === "number" ? d.cvssScore.toFixed(1) : "—",
            tone: cvssTone(typeof d?.cvssScore === "number" ? d.cvssScore : null)
          },
          { label: "Эксплойт", value: d?.hasExploit ? "Да" : "Нет", tone: d?.hasExploit ? "danger" : "neutral" },
          {
            label: "ИИ",
            value: !manualEnrichAllowed ? "—" : aiPending ? "Считаем" : hasAiSummary ? "Готово" : "Доступно",
            tone: hasAiSummary ? "ok" : "neutral"
          },
          { label: "Уровень", value: d?.severity?.trim() || "—" }
        ]}
      />
      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted">
        <span>Выявлено {fmtDateShort(d?.identifyDate ?? null)}</span>
        <span>Опубликовано {fmtDateShort(d?.publicationDate ?? null)}</span>
        <span>Обновлено {fmtDateShort(d?.lastUpdDate ?? d?.updatedAt ?? null)}</span>
        <a className="inline-flex items-center gap-1 text-fg/80 hover:underline" href={fstecUrl} target="_blank" rel="noreferrer">
          БДУ ФСТЭК <ExternalLink className="h-3 w-3" />
        </a>
      </div>

      {loading ? (
        <div className="mt-6 text-sm text-muted">Загрузка…</div>
      ) : !d ? (
        <div className="mt-6 text-sm text-danger">Запись не найдена</div>
      ) : (
        <>
          <DetailTabs
            value={tab}
            onChange={setTab}
            tabs={[
              { id: "general", label: "Общая" },
              { id: "products", label: "Продукты" },
              { id: "fixes", label: "Исправления" },
              { id: "history", label: "История" },
              { id: "sources", label: "Источники" }
            ]}
          />

          {tab === "general" ? (
            <div className="mt-4 grid grid-cols-12 gap-4">
              <div className="col-span-12 xl:col-span-5 space-y-3">
                <DetailSection title="Реестр БДУ">
                  <DetailFactList
                    rows={[
                      { label: "Уровень", value: d.severity ?? "—" },
                      { label: "Статус", value: d.status ?? "—" },
                      { label: "Эксплуатация", value: d.exploitStatus ?? "—" },
                      { label: "Исправление", value: d.fixStatus ?? "—" },
                      {
                        label: "CVSS",
                        value: (
                          <span>
                            <span className="tabular-nums">
                              {typeof d.cvssScore === "number" ? d.cvssScore.toFixed(1) : "—"}
                            </span>
                            {d.cvssVector ? (
                              <span className="mt-0.5 block font-mono text-[11px] text-muted">{d.cvssVector}</span>
                            ) : null}
                          </span>
                        )
                      }
                    ]}
                  />
                </DetailSection>
              </div>

              <div className="col-span-12 xl:col-span-7 space-y-3">
                <div className="rounded-xl border border-border bg-white p-4 shadow-sm dark:bg-black/20 dark:shadow-none">
                  <div className="flex items-center justify-between gap-3">
                    <div className="text-xs text-muted">Задачник</div>
                    {primaryCve ? (
                      <button
                        type="button"
                        onClick={() => void createTaskFromBdu()}
                        disabled={taskBusy}
                        className="rounded-lg border border-accent/30 bg-accent/10 px-3 py-1.5 text-[11px] text-fg/90 hover:bg-accent/15 disabled:opacity-60"
                      >
                        {taskBusy ? "Создаём…" : `Создать задачу (${primaryCve})`}
                      </button>
                    ) : (
                      <span className="text-[11px] text-muted">Нужна привязка CVE</span>
                    )}
                  </div>
                  {taskErr ? <div className="mt-2 text-[11px] text-rose-700">{taskErr}</div> : null}
                  <div className="mt-2 text-sm text-muted">
                    {!primaryCve
                      ? "В реестре БДУ нет CVE — задачник работает по CVE."
                      : tasksByCveQuery.isLoading
                        ? "Загрузка…"
                        : (tasksByCveQuery.data?.items?.length ?? 0) > 0
                          ? `В задачах по ${primaryCve}: ${tasksByCveQuery.data!.items.length}`
                          : `Пока нет задач по ${primaryCve}.`}
                  </div>
                  {(d.linkedCveIds ?? []).length > 1 ? (
                    <div className="mt-3 flex flex-wrap gap-2">
                      {d.linkedCveIds!.map((cve) => (
                        <button
                          key={cve}
                          type="button"
                          onClick={() => onOpenCve?.(cve)}
                          className="rounded-lg border border-accent/30 bg-accent/10 px-2.5 py-1 font-mono text-[11px] hover:bg-accent/15"
                        >
                          {cve} →
                        </button>
                      ))}
                    </div>
                  ) : null}
                </div>

                <AiSummaryPanel
                  embedded
                  data={payload}
                  loading={loading}
                  aiPending={aiPending}
                  aiStalled={aiStalled}
                  manualEnrichAllowed={Boolean(manualEnrichAllowed)}
                  onRequestEnrich={onRequestEnrich}
                />
              </div>
            </div>
          ) : null}

          {tab === "products" ? (
            <div className="mt-4 rounded-xl border border-border bg-white p-4 shadow-sm dark:bg-black/20 dark:shadow-none">
              <div className="flex items-center justify-between gap-3">
                <div className="text-sm font-medium">Уязвимые продукты</div>
                <div className="text-xs text-muted">{products.length ? `${products.length}` : "—"}</div>
              </div>
              {products.length ? (
                <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-2">
                  {products.map((vp, i) => (
                    <div
                      key={`${vp.vendor}:${vp.product}:${i}`}
                      className="min-w-0 rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm dark:border-white/10 dark:bg-white/5"
                    >
                      <div className="text-[10px] uppercase tracking-wide text-muted">Вендор</div>
                      <div className="break-words font-medium text-fg/90">{vp.vendor}</div>
                      <div className="mt-2 text-[10px] uppercase tracking-wide text-muted">Продукт</div>
                      <div className="break-words text-fg/85">{vp.product}</div>
                      <div className="mt-2 text-[11px] text-muted">Источник: БДУ ФСТЭК</div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="mt-3 text-sm text-muted">Нет данных о ПО в записи БДУ.</div>
              )}
            </div>
          ) : null}

          {tab === "fixes" ? (
            <div className="mt-4 space-y-4">
              <div className="rounded-xl border border-border bg-white p-4 shadow-sm dark:bg-black/20 dark:shadow-none">
                <div className="text-sm font-medium">Исправления и mitigation</div>
                <div className="mt-1 text-xs text-muted">из реестра БДУ ФСТЭК</div>
              </div>
              {d.solution ? (
                <div className="rounded-xl border border-border bg-white p-4 shadow-sm dark:bg-black/20 dark:shadow-none">
                  <div className="text-xs text-muted">Рекомендации по устранению</div>
                  <p className="mt-2 whitespace-pre-wrap text-sm text-fg/85">{d.solution}</p>
                </div>
              ) : (
                <div className="text-sm text-muted">Рекомендации не указаны.</div>
              )}
            </div>
          ) : null}

          {tab === "history" ? (
            <VulnTicketHistory
              cveId={primaryCve}
              bduId={bduId}
              publishedAt={d.publicationDate ?? null}
              modifiedAt={d.lastUpdDate ?? d.updatedAt ?? null}
              onOpenTask={onOpenTask}
            />
          ) : null}

          {tab === "sources" ? (
            <div className="mt-4 rounded-xl border border-border bg-white p-4 shadow-sm dark:bg-black/20 dark:shadow-none">
              <div className="text-sm font-medium">Источники</div>
              <ul className="mt-3 space-y-2 text-sm">
                <li>
                  <a href={fstecUrl} target="_blank" rel="noreferrer" className="text-accent hover:underline">
                    bdu.fstec.ru — карточка BDU:{bduId}
                  </a>
                </li>
                {(d.cveIds ?? []).map((cve) => (
                  <li key={cve} className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-fg/85">{cve}</span>
                    {(d.linkedCveIds ?? []).includes(cve) && onOpenCve ? (
                      <button
                        type="button"
                        onClick={() => onOpenCve(cve)}
                        className="text-xs text-accent hover:underline"
                      >
                        открыть в платформе
                      </button>
                    ) : (
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-xs text-muted hover:text-accent"
                      >
                        NVD ↗
                      </a>
                    )}
                  </li>
                ))}
              </ul>
              {d.sources ? (
                <div className="mt-4 text-xs text-muted">
                  <span className="font-medium text-fg/80">Источник (текст):</span> {d.sources}
                </div>
              ) : null}
            </div>
          ) : null}
        </>
      )}
    </div>
  );
}

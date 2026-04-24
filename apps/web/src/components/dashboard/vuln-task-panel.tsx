"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";
import { cn } from "../ui/cn";
import { Loader2, Plus, RefreshCw, Search, Trash2 } from "lucide-react";

type TaskListRow = {
  id: string;
  title: string;
  status: string;
  priority_local: string;
  owner: string | null;
  due_date: string | null;
  review_date: string | null;
  vendor_display: string;
  product_display: string;
  score_raw: number;
  score_final: number;
  stats?: { cveCount?: number; kevCount?: number; perimeterHighCount?: number } | null;
  updated_at: string;
};

type TaskDetail = {
  task: any;
  cves: Array<any>;
  events: Array<any>;
};

function statusPill(st: string) {
  const s = String(st || "");
  if (s === "in_progress") return { label: "В работе", cls: "border-accent/30 bg-accent/10 text-fg/80" };
  if (s === "needs_info") return { label: "Нужны данные", cls: "border-warn/30 bg-warn/10 text-warn" };
  if (s === "fixing") return { label: "На исправлении", cls: "border-accent/30 bg-accent/10 text-fg/80" };
  if (s === "mitigated") return { label: "Смягчено", cls: "border-warn/30 bg-warn/10 text-warn" };
  if (s === "closed") return { label: "Закрыто", cls: "border-ok/30 bg-ok/10 text-ok" };
  if (s === "not_applicable") return { label: "N/A", cls: "border-slate-200 bg-slate-50 text-fg/75 dark:border-white/10 dark:bg-white/5" };
  if (s === "risk_accepted") return { label: "Принят риск", cls: "border-slate-200 bg-slate-50 text-fg/75 dark:border-white/10 dark:bg-white/5" };
  return { label: "Новая", cls: "border-slate-200 bg-slate-50 text-fg/75 dark:border-white/10 dark:bg-white/5" };
}

function scoreCls(n: number) {
  if (n >= 85) return "border-danger/30 bg-danger/10 text-danger";
  if (n >= 70) return "border-warn/30 bg-warn/10 text-warn";
  if (n >= 40) return "border-accent/30 bg-accent/10 text-fg/80";
  return "border-ok/30 bg-ok/10 text-ok";
}

export function VulnTaskPanel({
  vendorsHint,
  onOpenCve,
  selectedTaskId,
  onSelectTaskId
}: {
  vendorsHint?: { vendors: { vendor: string; count: number }[]; products: { vendor: string; product: string; count: number }[] } | null;
  onOpenCve?: (cveId: string) => void;
  selectedTaskId?: string | null;
  onSelectTaskId?: (taskId: string | null) => void;
}) {
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<string>(""); // empty = all
  const [selected, setSelected] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [viewMode, setViewMode] = useState<"list" | "board">("board");

  const listQuery = useQuery({
    queryKey: ["vuln-tasks", "list", q, status],
    queryFn: async () => {
      const url = new URL(`/api/vuln-tasks`, window.location.origin);
      if (q.trim()) url.searchParams.set("q", q.trim());
      if (status) url.searchParams.set("status", status);
      url.searchParams.set("limit", "200");
      const res = await apiFetch(url.toString(), { cache: "no-store" });
      if (!res.ok) throw new Error(`Failed to fetch tasks (${res.status})`);
      return (await res.json()) as { items: TaskListRow[] };
    },
    staleTime: 15_000
  });

  const detailQuery = useQuery({
    queryKey: ["vuln-tasks", "detail", selected],
    enabled: Boolean(selected),
    queryFn: async () => {
      const res = await apiFetch(`/api/vuln-tasks/${encodeURIComponent(selected!)}`, { cache: "no-store" });
      if (!res.ok) throw new Error(`Failed to fetch task (${res.status})`);
      return (await res.json()) as TaskDetail;
    }
  });

  const items = listQuery.data?.items ?? [];
  const active = detailQuery.data?.task ?? null;
  useEffect(() => {
    if (selectedTaskId === undefined) return;
    setSelected(selectedTaskId);
  }, [selectedTaskId]);

  const vendorOptions = useMemo(() => {
    const v = vendorsHint?.vendors ?? [];
    return v.slice(0, 80);
  }, [vendorsHint]);

  const [newVendor, setNewVendor] = useState<string>("");
  const productOptions = useMemo(() => {
    const p = vendorsHint?.products ?? [];
    const pickVendor = newVendor.trim().toLowerCase();
    if (!pickVendor) return [];
    return p.filter((x) => x.vendor.toLowerCase() === pickVendor).slice(0, 120);
  }, [vendorsHint, newVendor]);
  const [newProduct, setNewProduct] = useState<string>("");
  const [newTitle, setNewTitle] = useState<string>("");
  const [saveBusy, setSaveBusy] = useState(false);
  const [saveErr, setSaveErr] = useState<string | null>(null);

  const [addOpen, setAddOpen] = useState(false);
  const [addQ, setAddQ] = useState("");
  const [addPicked, setAddPicked] = useState<Record<string, true>>({});

  const cveSearchQuery = useQuery({
    queryKey: ["vuln-tasks", "cve-search", addQ],
    enabled: addOpen && addQ.trim().length >= 3,
    queryFn: async () => {
      const url = new URL(`/api/cves`, window.location.origin);
      url.searchParams.set("q", addQ.trim());
      url.searchParams.set("limit", "50");
      url.searchParams.set("view", "latest");
      url.searchParams.set("sort", "rank");
      const res = await apiFetch(url.toString(), { cache: "no-store" });
      if (!res.ok) throw new Error(`search failed (${res.status})`);
      return (await res.json()) as { items: Array<any> };
    },
    staleTime: 10_000
  });

  const createTask = useCallback(async () => {
    const vendorDisplay = newVendor.trim();
    const productDisplay = newProduct.trim();
    if (!vendorDisplay) return;
    const vendorKey = vendorDisplay.toLowerCase();
    const productKeyNorm = productDisplay ? productDisplay.toLowerCase().replace(/\s+/g, "_") : "";
    const title = newTitle.trim() || `${vendorDisplay}${productDisplay ? ` / ${productDisplay}` : ""} — кампания по уязвимостям`;
    const res = await apiFetch(`/api/vuln-tasks`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        title,
        vendorKey,
        vendorDisplay,
        productKeyNorm,
        productDisplay,
        cveIds: []
      })
    });
    if (!res.ok) throw new Error("create failed");
    const j = (await res.json()) as any;
    setCreateOpen(false);
    setNewTitle("");
    setNewProduct("");
    // Keep vendor selection for fast batching
    await listQuery.refetch();
    if (j?.id) setSelected(String(j.id));
  }, [newVendor, newProduct, newTitle, listQuery]);

  const savePatch = useCallback(async (patch: Record<string, unknown>) => {
    if (!selected || saveBusy) return;
    setSaveBusy(true);
    setSaveErr(null);
    try {
      const res = await apiFetch(`/api/vuln-tasks/${encodeURIComponent(selected)}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(patch)
      });
      if (!res.ok) {
        const txt = await res.text().catch(() => "");
        throw new Error(txt || `save failed (${res.status})`);
      }
      await detailQuery.refetch();
      await listQuery.refetch();
    } catch (e) {
      setSaveErr(e instanceof Error ? e.message : String(e));
    } finally {
      setSaveBusy(false);
    }
  }, [selected, saveBusy, detailQuery, listQuery]);

  const addCves = useCallback(async () => {
    if (!selected) return;
    const ids = Object.keys(addPicked);
    if (ids.length === 0) return;
    const res = await apiFetch(`/api/vuln-tasks/${encodeURIComponent(selected)}/cves`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ cveIds: ids })
    });
    if (!res.ok) throw new Error("add cves failed");
    setAddPicked({});
    setAddQ("");
    setAddOpen(false);
    await detailQuery.refetch();
    await listQuery.refetch();
  }, [selected, addPicked, detailQuery, listQuery]);

  const removeCve = useCallback(async (cveId: string) => {
    if (!selected) return;
    const res = await apiFetch(
      `/api/vuln-tasks/${encodeURIComponent(selected)}/cves/${encodeURIComponent(cveId)}/remove`,
      { method: "POST" }
    );
    if (!res.ok) throw new Error("remove failed");
    await detailQuery.refetch();
    await listQuery.refetch();
  }, [selected, detailQuery, listQuery]);

  const refresh = useCallback(async () => {
    await listQuery.refetch();
    if (selected) await detailQuery.refetch();
  }, [listQuery, selected, detailQuery]);

  const columns = useMemo(() => {
    const by: Record<string, TaskListRow[]> = {};
    for (const t of items) {
      const k = String(t.status || "new");
      if (!by[k]) by[k] = [];
      by[k].push(t);
    }
    const order: Array<{ key: string; title: string }> = [
      { key: "new", title: "Новая" },
      { key: "in_progress", title: "В работе" },
      { key: "needs_info", title: "Нужны данные" },
      { key: "fixing", title: "На исправлении" },
      { key: "mitigated", title: "Смягчено" },
      { key: "risk_accepted", title: "Принят риск" },
      { key: "not_applicable", title: "N/A" },
      { key: "closed", title: "Закрыто" }
    ];
    return order.map((o) => ({ ...o, items: by[o.key] ?? [] }));
  }, [items]);

  return (
    <div className="grid grid-cols-12 gap-6">
      <section className={cn("col-span-12 lg:col-span-4")}>
        <div className="glass rounded-2xl p-4">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="text-sm font-medium">Задачник по уязвимостям</div>
              <div className="mt-1 text-[11px] text-muted">
                Кампании по vendor/product: статусы, заметки, CVE внутри, сортировка по task‑score.
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <button
                type="button"
                onClick={() => setViewMode((m) => (m === "board" ? "list" : "board"))}
                className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-2.5 py-1.5 text-[11px] text-fg/90 hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/35"
                title="Переключить вид"
              >
                {viewMode === "board" ? "Доска" : "Список"}
              </button>
              <button
                type="button"
                onClick={() => void refresh()}
                className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-[11px] text-fg/90 hover:bg-slate-100 dark:border-border dark:bg-black/20 dark:hover:bg-black/35"
                title="Обновить"
              >
                {listQuery.isFetching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
                Обновить
              </button>
              <button
                type="button"
                onClick={() => setCreateOpen((v) => !v)}
                className="inline-flex items-center gap-2 rounded-xl border border-accent/30 bg-accent/10 px-2.5 py-1.5 text-[11px] text-fg/90 hover:bg-accent/15"
                title="Создать задачу"
              >
                <Plus className="h-3.5 w-3.5" />
                Новая
              </button>
            </div>
          </div>

          <div className="mt-3 grid grid-cols-2 gap-2">
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="поиск по названию / vendor / product"
              className="col-span-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
            />
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              className="col-span-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
              title="Статус"
            >
              <option value="">Все статусы</option>
              <option value="new">Новая</option>
              <option value="in_progress">В работе</option>
              <option value="needs_info">Нужны данные</option>
              <option value="fixing">На исправлении</option>
              <option value="mitigated">Смягчено</option>
              <option value="closed">Закрыто</option>
              <option value="not_applicable">N/A</option>
              <option value="risk_accepted">Принят риск</option>
            </select>
          </div>

          {createOpen ? (
            <div className="mt-3 rounded-xl border border-slate-200 bg-slate-50 p-3 dark:border-white/10 dark:bg-white/5">
              <div className="text-[11px] font-medium text-fg/85">Новая задача (vendor/product)</div>
              <div className="mt-2 space-y-2">
                <input
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="Название (опционально)"
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                />
                <input
                  list="vip-vendors"
                  value={newVendor}
                  onChange={(e) => setNewVendor(e.target.value)}
                  placeholder="Vendor (например, Citrix)"
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                />
                <datalist id="vip-vendors">
                  {vendorOptions.map((v) => (
                    <option key={v.vendor} value={v.vendor} />
                  ))}
                </datalist>
                <input
                  list="vip-products"
                  value={newProduct}
                  onChange={(e) => setNewProduct(e.target.value)}
                  placeholder="Product (например, NetScaler)"
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                />
                <datalist id="vip-products">
                  {productOptions.map((p) => (
                    <option key={`${p.vendor}:${p.product}`} value={p.product} />
                  ))}
                </datalist>
                <button
                  type="button"
                  onClick={() => void createTask()}
                  className="w-full rounded-lg border border-accent/30 bg-accent/10 px-3 py-2 text-sm text-fg/90 hover:bg-accent/15"
                >
                  Создать
                </button>
              </div>
            </div>
          ) : null}

          <div className="mt-4 space-y-2">
            {listQuery.isLoading ? (
              <div className="text-sm text-muted">Загрузка…</div>
            ) : items.length === 0 ? (
              <div className="text-sm text-muted">Пока нет задач.</div>
            ) : (
              viewMode === "list" ? items.map((t) => {
                const st = statusPill(t.status);
                const cveCount = (t.stats as any)?.cveCount ?? null;
                const kevCount = (t.stats as any)?.kevCount ?? null;
                return (
                  <button
                    key={t.id}
                    onClick={() => {
                      setSelected(t.id);
                      onSelectTaskId?.(t.id);
                    }}
                    className={cn(
                      "w-full rounded-xl border px-3 py-3 text-left transition",
                      selected === t.id ? "border-accent/40 shadow-glass" : "border-border",
                      "bg-gradient-to-br from-slate-50 to-white hover:from-slate-100 hover:to-slate-50/90",
                      "dark:from-white/5 dark:to-white/[0.02] dark:hover:from-white/7 dark:hover:to-white/[0.04]"
                    )}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="truncate text-sm font-semibold tracking-tight">{t.title}</div>
                        <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-muted">
                          <span className={cn("rounded-full border px-2 py-0.5", st.cls)}>{st.label}</span>
                          <span className={cn("rounded-full border px-2 py-0.5 tabular-nums", scoreCls(t.score_final))}>
                            Score {t.score_final}
                          </span>
                          {cveCount != null ? (
                            <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 tabular-nums dark:border-white/10 dark:bg-white/5">
                              CVE {cveCount}
                            </span>
                          ) : null}
                          {kevCount != null && kevCount > 0 ? (
                            <span className="rounded-full border border-danger/30 bg-danger/10 px-2 py-0.5 text-danger">
                              KEV {kevCount}
                            </span>
                          ) : null}
                        </div>
                        <div className="mt-1 text-[11px] text-muted">
                          {t.vendor_display}
                          {t.product_display ? ` / ${t.product_display}` : ""}
                        </div>
                      </div>
                      <div className="shrink-0 text-[10px] text-muted">
                        {t.updated_at ? new Date(t.updated_at).toLocaleDateString() : "—"}
                      </div>
                    </div>
                  </button>
                );
              }) : (
                <div className="mt-2 grid gap-3">
                  {columns.map((col) => (
                    <div key={col.key} className="rounded-xl border border-slate-200 bg-slate-50 p-3 dark:border-white/10 dark:bg-white/5">
                      <div className="flex items-center justify-between gap-2">
                        <div className="text-[11px] font-medium text-fg/85">{col.title}</div>
                        <div className="text-[11px] text-muted">{col.items.length}</div>
                      </div>
                      <div className="mt-2 space-y-2">
                        {col.items.slice(0, 12).map((t) => {
                          const st = statusPill(t.status);
                          return (
                            <button
                              key={t.id}
                              onClick={() => {
                                setSelected(t.id);
                                onSelectTaskId?.(t.id);
                              }}
                              className={cn(
                                "w-full rounded-lg border px-3 py-2 text-left transition",
                                selected === t.id ? "border-accent/40" : "border-border",
                                "bg-white/80 hover:bg-white dark:bg-black/20 dark:hover:bg-black/30"
                              )}
                            >
                              <div className="flex items-start justify-between gap-2">
                                <div className="min-w-0">
                                  <div className="truncate text-[12px] font-semibold text-fg/90">{t.title}</div>
                                  <div className="mt-1 flex flex-wrap gap-1 text-[10px] text-muted">
                                    <span className={cn("rounded-full border px-2 py-0.5", st.cls)}>{st.label}</span>
                                    <span className={cn("rounded-full border px-2 py-0.5 tabular-nums", scoreCls(t.score_final))}>
                                      {t.score_final}
                                    </span>
                                  </div>
                                </div>
                                <div className="shrink-0 text-[10px] text-muted">{new Date(t.updated_at).toLocaleDateString()}</div>
                              </div>
                            </button>
                          );
                        })}
                        {col.items.length > 12 ? <div className="text-[10px] text-muted">+ ещё {col.items.length - 12}</div> : null}
                      </div>
                    </div>
                  ))}
                </div>
              )
            )}
          </div>
        </div>
      </section>

      <section className="col-span-12 lg:col-span-8">
        <div className="glass rounded-2xl p-5 sm:p-6">
          {!selected ? (
            <div>
              <div className="text-sm font-medium">Задача</div>
              <div className="mt-2 text-sm text-muted">Выберите задачу слева или создайте новую.</div>
            </div>
          ) : detailQuery.isLoading ? (
            <div className="text-sm text-muted">Загрузка…</div>
          ) : detailQuery.isError ? (
            <div className="text-sm text-danger">Не удалось загрузить задачу.</div>
          ) : (
            <div className="space-y-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate text-base font-semibold tracking-tight">{active?.title ?? selected}</div>
                  <div className="mt-1 text-xs text-muted">
                    {active?.vendor_display}
                    {active?.product_display ? ` / ${active?.product_display}` : ""}
                  </div>
                </div>
                <div className="flex items-center gap-2 text-[11px]">
                  <span className={cn("rounded-full border px-2 py-0.5 tabular-nums", scoreCls(Number(active?.score_final ?? 0)))}>
                    Score {Number(active?.score_final ?? 0)}
                  </span>
                  <span className={cn("rounded-full border px-2 py-0.5", statusPill(String(active?.status ?? "new")).cls)}>
                    {statusPill(String(active?.status ?? "new")).label}
                  </span>
                </div>
              </div>

              <div className="rounded-xl border border-border bg-white p-4 shadow-sm dark:bg-black/20 dark:shadow-none">
                <div className="flex items-center justify-between gap-3">
                  <div className="text-xs text-muted">CVE в задаче</div>
                  <button
                    type="button"
                    onClick={() => setAddOpen((v) => !v)}
                    className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-[11px] text-fg/90 hover:bg-slate-100 dark:border-border dark:bg-black/20 dark:hover:bg-black/35"
                  >
                    <Search className="h-3.5 w-3.5" />
                    Добавить CVE
                  </button>
                </div>

                {addOpen ? (
                  <div className="mt-3 rounded-xl border border-slate-200 bg-slate-50 p-3 dark:border-white/10 dark:bg-white/5">
                    <div className="text-[11px] text-muted">Поиск CVE (минимум 3 символа)</div>
                    <div className="mt-2 flex items-center gap-2">
                      <input
                        value={addQ}
                        onChange={(e) => setAddQ(e.target.value)}
                        placeholder="CVE-2026-… или vendor/product"
                        className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                      />
                      <button
                        type="button"
                        onClick={() => void addCves()}
                        className="shrink-0 rounded-lg border border-accent/30 bg-accent/10 px-3 py-2 text-sm text-fg/90 hover:bg-accent/15"
                      >
                        Добавить
                      </button>
                    </div>
                    <div className="mt-2 grid gap-2 sm:grid-cols-2">
                      {(cveSearchQuery.data?.items ?? []).slice(0, 20).map((c: any) => (
                        <label
                          key={String(c.cve_id)}
                          className="flex cursor-pointer items-start gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-white/10 dark:bg-black/20"
                        >
                          <input
                            type="checkbox"
                            checked={Boolean(addPicked[String(c.cve_id)])}
                            onChange={(e) =>
                              setAddPicked((m) => {
                                const n = { ...m };
                                if (e.target.checked) n[String(c.cve_id)] = true;
                                else delete n[String(c.cve_id)];
                                return n;
                              })
                            }
                          />
                          <div className="min-w-0">
                            <div className="font-mono text-[12px] font-semibold">{String(c.cve_id)}</div>
                            <div className="mt-1 line-clamp-2 text-[11px] text-muted">
                              {String(c.short_ru ?? c.short_description ?? "")}
                            </div>
                          </div>
                        </label>
                      ))}
                    </div>
                  </div>
                ) : null}
                <div className="mt-2 grid gap-2 sm:grid-cols-2">
                  {(detailQuery.data?.cves ?? []).slice(0, 50).map((c) => (
                    <div
                      key={c.cve_id}
                      className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-left text-sm dark:border-white/10 dark:bg-white/5"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <button
                          onClick={() => onOpenCve?.(String(c.cve_id))}
                          className="min-w-0 text-left hover:underline"
                          title="Открыть CVE"
                        >
                          <div className="font-mono text-[12px] font-semibold text-fg/90">{String(c.cve_id)}</div>
                          <div className="mt-1 text-[11px] text-muted">
                            {c.exploit_known ? "KEV • " : ""}
                            EPSS{" "}
                            {typeof c.epss === "number" ? `${(Number(c.epss) * 100).toFixed(2)}%` : "—"} • CVSS{" "}
                            {typeof c.cvss_base === "number" ? Number(c.cvss_base).toFixed(1) : "—"}
                          </div>
                        </button>
                        <div className="flex items-center gap-2">
                          <div className="text-[11px] text-muted tabular-nums">
                            {typeof c.risk_score === "number" ? c.risk_score : "—"}
                          </div>
                          <button
                            type="button"
                            onClick={() => void removeCve(String(c.cve_id))}
                            className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-[11px] text-fg/80 hover:bg-slate-100 dark:border-white/10 dark:bg-black/20 dark:hover:bg-black/30"
                            title="Убрать из задачи"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
                {(detailQuery.data?.cves?.length ?? 0) > 50 ? (
                  <div className="mt-2 text-[11px] text-muted">Показаны первые 50 CVE…</div>
                ) : null}
              </div>

              <div className="rounded-xl border border-border bg-white p-4 shadow-sm dark:bg-black/20 dark:shadow-none">
                <div className="flex items-center justify-between gap-3">
                  <div className="text-xs text-muted">Поля задачи</div>
                  <div className="text-[11px] text-muted">{saveBusy ? "Сохраняем…" : ""}</div>
                </div>
                {saveErr ? <div className="mt-2 text-[11px] text-rose-700">{saveErr}</div> : null}
                <div className="mt-3 grid grid-cols-12 gap-3">
                  <div className="col-span-12 md:col-span-4">
                    <div className="text-[11px] text-muted">Статус</div>
                    <select
                      defaultValue={String(active?.status ?? "new")}
                      onChange={(e) => void savePatch({ status: e.target.value })}
                      className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                    >
                      <option value="new">Новая</option>
                      <option value="in_progress">В работе</option>
                      <option value="needs_info">Нужны данные</option>
                      <option value="fixing">На исправлении</option>
                      <option value="mitigated">Смягчено</option>
                      <option value="risk_accepted">Принят риск</option>
                      <option value="not_applicable">N/A</option>
                      <option value="closed">Закрыто</option>
                    </select>
                    <div className="mt-2 text-[10px] text-muted">
                      Важно: для `needs_info` нужен `review_date`; для `risk_accepted` — `review_date`; для `closed/N/A` — evidence/notes.
                    </div>
                  </div>
                  <div className="col-span-12 md:col-span-4">
                    <div className="text-[11px] text-muted">Приоритет (ручной)</div>
                    <select
                      defaultValue={String(active?.priority_local ?? "medium")}
                      onChange={(e) => void savePatch({ priorityLocal: e.target.value })}
                      className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                    >
                      <option value="low">Низкий</option>
                      <option value="medium">Средний</option>
                      <option value="high">Высокий</option>
                      <option value="critical">Критичный</option>
                    </select>
                  </div>
                  <div className="col-span-12 md:col-span-4">
                    <div className="text-[11px] text-muted">Owner</div>
                    <input
                      defaultValue={String(active?.owner ?? "")}
                      onBlur={(e) => void savePatch({ owner: e.target.value || null })}
                      className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                      placeholder="Иван / Коллега"
                    />
                  </div>
                  <div className="col-span-12 md:col-span-4">
                    <div className="text-[11px] text-muted">Due date</div>
                    <input
                      defaultValue={active?.due_date ? String(active.due_date).slice(0, 10) : ""}
                      onBlur={(e) => void savePatch({ dueDate: e.target.value ? new Date(e.target.value).toISOString() : null })}
                      type="date"
                      className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                    />
                  </div>
                  <div className="col-span-12 md:col-span-4">
                    <div className="text-[11px] text-muted">Review date</div>
                    <input
                      defaultValue={active?.review_date ? String(active.review_date).slice(0, 10) : ""}
                      onBlur={(e) => void savePatch({ reviewDate: e.target.value ? new Date(e.target.value).toISOString() : null })}
                      type="date"
                      className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                    />
                  </div>
                  <div className="col-span-12 md:col-span-4">
                    <div className="text-[11px] text-muted">Decision</div>
                    <input
                      defaultValue={String(active?.decision ?? "")}
                      onBlur={(e) => void savePatch({ decision: e.target.value || null })}
                      className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                      placeholder="patch / mitigation / accept / n/a"
                    />
                  </div>
                  <div className="col-span-12">
                    <div className="text-[11px] text-muted">Decision notes</div>
                    <textarea
                      defaultValue={String(active?.decision_notes ?? "")}
                      onBlur={(e) => void savePatch({ decisionNotes: e.target.value || null })}
                      className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                      rows={3}
                      placeholder="Почему так решили, какой план, кто делает…"
                    />
                  </div>
                  <div className="col-span-12">
                    <div className="text-[11px] text-muted">Evidence</div>
                    <textarea
                      defaultValue={String(active?.evidence ?? "")}
                      onBlur={(e) => void savePatch({ evidence: e.target.value || null })}
                      className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-border dark:bg-black/20"
                      rows={2}
                      placeholder="Ссылка на advisory / версия / тикет / скрин / команда проверки…"
                    />
                  </div>
                  <div className="col-span-12">
                    <div className="text-[11px] text-muted">Notes (Markdown)</div>
                    <textarea
                      defaultValue={String(active?.notes_md ?? "")}
                      onBlur={(e) => void savePatch({ notesMd: e.target.value })}
                      className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-mono dark:border-border dark:bg-black/20"
                      rows={8}
                    />
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}


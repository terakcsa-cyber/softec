"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { AppearanceSettings } from "@/components/auth/appearance-settings";
import { SecuritySettings } from "@/components/auth/security-settings";
import { apiFetch } from "@/lib/api-fetch";
import { needsOnDemandEnrich, parseAiOutputJson, shouldAutoEnrichOnOpen } from "@/lib/cve-enrich-ui";
import { CVE_POLL_BACKGROUND_ONLY_MS, CVE_POLL_WHILE_ENRICH_MS, ENRICH_UI_WAIT_MS } from "@/lib/enrich-ui-wait";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Bandage, BarChart3, Loader2, Radar, RefreshCw, Settings, ShieldAlert, ShieldCheck } from "lucide-react";
import * as Tabs from "@radix-ui/react-tabs";
import * as Dialog from "@radix-ui/react-dialog";
import { cn } from "../ui/cn";
import { CveCard } from "./cve-card";
import { AiSummaryPanel } from "./ai-summary-panel";
import { RiskBreakdownPanel } from "./risk-breakdown-panel";
import { OverviewDashboardPanel } from "./overview-dashboard-panel";
import { CveSourcesPanel } from "./cve-sources-panel";

/** reactflow ломает SSR/Webpack в Next 15 — только клиент. */
const AttackGraphPanel = dynamic(
  () => import("./attack-graph-panel").then((m) => m.AttackGraphPanel),
  {
    ssr: false,
    loading: () => <div className="py-10 text-center text-sm text-muted">Загрузка схемы атаки…</div>
  }
);
import {
  DASHBOARD_CVE_MODAL_BASE_WIDTH_PX,
  DraggableCveModals,
  type DashboardModalFrame
} from "./draggable-cve-modals";
import { FstecNewsPanel } from "../fstec/fstec-news-panel";
import { PatchManagementPanel } from "./patch-management-panel";
import { AsvScannerPanel } from ".";
import { VulnSearchBar } from "./vuln-search-bar";

type CveListItem = {
  cve_id: string;
  published_at: string | null;
  modified_at: string | null;
  risk_score: number | null;
  epss?: number | null;
  cvss_base?: number | null;
  exploit_known?: boolean;
  critical_reasons?: string[] | null;
  ai_ready?: boolean;
};

type CveDetails = {
  found: boolean;
  cve?: unknown;
  ai?: unknown;
};

async function fetchCveDetail(cveId: string): Promise<CveDetails> {
  const res = await apiFetch(`/api/cves/${encodeURIComponent(cveId)}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch CVE");
  return (await res.json()) as CveDetails;
}

type SavedView = {
  id: string;
  name: string;
  state: {
    view: "critical_v2" | "critical" | "latest" | "last24h" | "kev" | "all";
    sort: "rank" | "fresh" | "risk" | "epss" | "cvss";
    limit: 15 | 20;
    kevOnly: boolean;
    minCvss: number | null;
    minEpss: number | null;
    vendorFilter: string | null;
    productFilter: string | null;
    q: string;
  };
};

type TriageStatus = "new" | "review" | "done";
type ModuleKey = "dashboard" | "vulns" | "fstec" | "patches" | "asv" | "settings";

export function Dashboard() {
  const queryClient = useQueryClient();
  const [moduleKey, setModuleKey] = useState<ModuleKey>("dashboard");
  const [q, setQ] = useState("");
  /** Задержка запроса к API при наборе текста полнотекстового поиска */
  const [qDebounced, setQDebounced] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [view, setView] = useState<"critical_v2" | "critical" | "latest" | "last24h" | "kev" | "all">("critical_v2");
  const [limit, setLimit] = useState<15 | 20>(20);
  const [sort, setSort] = useState<"rank" | "fresh" | "risk" | "epss" | "cvss">("rank");
  const [kevOnly, setKevOnly] = useState(false);
  const [minCvss, setMinCvss] = useState<number | null>(null);
  const [minEpss, setMinEpss] = useState<number | null>(null);
  const [vendorFilter, setVendorFilter] = useState<string | null>(null);
  const [productFilter, setProductFilter] = useState<string | null>(null);
  const [savedViews, setSavedViews] = useState<SavedView[]>([]);
  const [triage, setTriage] = useState<Record<string, TriageStatus>>({});
  const [savedViewsOpen, setSavedViewsOpen] = useState(false);
  const [bulkMode, setBulkMode] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Record<string, true>>({});

  useEffect(() => {
    try {
      const raw = localStorage.getItem("vip:savedViews");
      if (raw) setSavedViews(JSON.parse(raw));
    } catch {
      // ignore
    }
    try {
      const raw = localStorage.getItem("vip:triageStatus");
      if (raw) setTriage(JSON.parse(raw));
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem("vip:savedViews", JSON.stringify(savedViews));
    } catch {
      // ignore
    }
  }, [savedViews]);

  useEffect(() => {
    const id = window.setTimeout(() => setQDebounced(q.trim()), 400);
    return () => window.clearTimeout(id);
  }, [q]);

  useEffect(() => {
    try {
      localStorage.setItem("vip:triageStatus", JSON.stringify(triage));
    } catch {
      // ignore
    }
  }, [triage]);


  const queueHealthQuery = useQuery({
    queryKey: ["stats", "queue"],
    queryFn: async () => {
      const res = await apiFetch(`/api/stats/queue`, { cache: "no-store" });
      if (!res.ok) throw new Error(`Failed to fetch queue (${res.status})`);
      return (await res.json()) as unknown;
    },
    staleTime: 10_000
  });

  const [dlqOpen, setDlqOpen] = useState(false);
  const [dlqQueue, setDlqQueue] = useState<"dlq.ai.enrich" | "dlq.ai.score">("dlq.ai.enrich");
  const dlqSampleQuery = useQuery({
    queryKey: ["stats", "dlq", "sample", dlqQueue],
    enabled: dlqOpen,
    queryFn: async () => {
      const res = await apiFetch(`/api/stats/dlq/sample?queue=${encodeURIComponent(dlqQueue)}&limit=8`, {
        cache: "no-store"
      });
      if (!res.ok) throw new Error(`Failed to fetch DLQ sample (${res.status})`);
      return (await res.json()) as unknown;
    }
  });

  const dlqRetry = async () => {
    await apiFetch(`/api/stats/dlq/retry?queue=${encodeURIComponent(dlqQueue)}&limit=1000`, {
      method: "POST"
    });
    await queueHealthQuery.refetch();
    await dlqSampleQuery.refetch();
  };

  const dlqClear = async () => {
    await apiFetch(`/api/stats/dlq/clear?queue=${encodeURIComponent(dlqQueue)}&limit=1000`, {
      method: "POST"
    });
    await queueHealthQuery.refetch();
    await dlqSampleQuery.refetch();
  };

  /** After opening a CVE, POST /enrich once; poll until AI row exists or timeout. */
  const [enrichPosted, setEnrichPosted] = useState(false);
  /** CVE, для которого реально ждём LLM (не путать с текущим selected в списке). */
  const [enrichTargetCveId, setEnrichTargetCveId] = useState<string | null>(null);
  /** True after ENRICH_UI_WAIT_MS wait with no successful AI row — do not auto re-POST until user picks another CVE. */
  const [enrichStalled, setEnrichStalled] = useState(false);
  /** Prevents re-running POST when `enrichPosted` flips false (timeout): same CVE would loop forever. */
  const enrichKickoffForCveRef = useRef<string | null>(null);
  const enrichPollDeadlineRef = useRef<number | null>(null);
  /** Один автозапрос enrich на CVE при открытии (без зацикливания). */
  const autoEnrichForCveRef = useRef<string | null>(null);
  const [dashboardModals, setDashboardModals] = useState<DashboardModalFrame[]>([]);

  const summaryQuery = useQuery({
    queryKey: ["stats", "summary"],
    queryFn: async () => {
      const res = await apiFetch(`/api/stats/summary`, { cache: "no-store" });
      if (!res.ok) throw new Error(`Failed to fetch summary (${res.status})`);
      return (await res.json()) as {
        totalCves: number;
        cvesLastHourCount?: number;
        kevCount: number;
        epssCount: number;
        cvssCount: number;
        scoredCount: number;
        aiEnrichedCount?: number;
        aiEnrichPerMinute?: number;
        aiLastEnrichAt?: string | null;
        manualEnrichAllowed?: boolean;
        freshness?: {
          nvdWatermarkTs?: string | null;
          epssIngestTs?: string | null;
          kevIngestTs?: string | null;
          riskScoreComputedAt?: string | null;
        };
      };
    }
  });

  /** Как на API: по умолчанию разрешено, только `false` отключает. Пока summary грузится — не блокируем кнопки (`=== true` ломало ручной enrich). */
  const manualEnrichAllowed = summaryQuery.data?.manualEnrichAllowed !== false;

  const vendorsQuery = useQuery({
    queryKey: ["stats", "vendors", 24, 50],
    enabled: moduleKey === "dashboard" || moduleKey === "vulns",
    queryFn: async () => {
      const res = await apiFetch(`/api/stats/vendors?windowHours=24&limit=50`, { cache: "no-store" });
      if (!res.ok) throw new Error(`Failed to fetch vendors (${res.status})`);
      return (await res.json()) as {
        windowHours: number;
        sampledCves: number;
        method?: string;
        usedCpe?: number;
        usedFallback?: number;
        vendors: { vendor: string; count: number }[];
        products: { vendor: string; product: string; count: number }[];
      };
    },
    staleTime: 30_000
  });

  const hotCvesQuery = useQuery({
    queryKey: ["cves", "dashboard", "last24h", "fresh", 24],
    enabled: moduleKey === "dashboard",
    staleTime: 45_000,
    refetchInterval: moduleKey === "dashboard" ? 90_000 : false,
    queryFn: async () => {
      const url = new URL(`/api/cves`, window.location.origin);
      url.searchParams.set("view", "last24h");
      url.searchParams.set("sort", "fresh");
      url.searchParams.set("limit", "24");
      const res = await apiFetch(url.toString(), { cache: "no-store" });
      if (!res.ok) throw new Error(`Failed to fetch hot CVEs (${res.status})`);
      const data = (await res.json()) as { items: CveListItem[] };
      return data.items;
    }
  });

  const listQuery = useQuery({
    queryKey: ["cves", view, limit, sort, kevOnly, minCvss, minEpss, vendorFilter, productFilter, qDebounced],
    enabled: moduleKey === "vulns",
    queryFn: async () => {
      const url = new URL(`/api/cves`, window.location.origin);
      url.searchParams.set("limit", String(view === "all" ? 50 : limit));
      url.searchParams.set("view", view === "all" ? "latest" : view);
      url.searchParams.set(
        "sort",
        view === "critical" || view === "critical_v2" ? sort : sort === "rank" ? "fresh" : sort
      );
      if (kevOnly) url.searchParams.set("kevOnly", "true");
      if (minCvss != null) url.searchParams.set("minCvss", String(minCvss));
      if (minEpss != null) url.searchParams.set("minEpss", String(minEpss));
      if (vendorFilter) url.searchParams.set("vendor", vendorFilter);
      if (productFilter) url.searchParams.set("product", productFilter);
      if (qDebounced) url.searchParams.set("q", qDebounced);
      const res = await apiFetch(url.toString(), { cache: "no-store" });
      if (!res.ok) throw new Error(`Failed to fetch list (${res.status})`);
      const data = (await res.json()) as { items: CveListItem[] };
      return data.items;
    }
  });

  const exportCsv = () => {
    const rows = (listQuery.data ?? []).map((it) => ({
      cve_id: it.cve_id,
      published_at: it.published_at ?? "",
      modified_at: it.modified_at ?? "",
      risk_score: it.risk_score ?? "",
      epss: typeof it.epss === "number" ? it.epss : "",
      cvss_base: typeof it.cvss_base === "number" ? it.cvss_base : "",
      exploit_known: it.exploit_known ? "true" : "false",
      ai_ready: it.ai_ready ? "true" : "false",
      triage: triage[it.cve_id] ?? ""
    }));
    const header = Object.keys(rows[0] ?? { cve_id: "" });
    const esc = (v: unknown) => {
      const s = String(v ?? "");
      if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
      return s;
    };
    const csv = [
      header.join(","),
      ...rows.map((r) => header.map((k) => esc((r as Record<string, unknown>)[k])).join(","))
    ].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cves_${view}_${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  
  const detailsQuery = useQuery({
    queryKey: ["cve", selected],
    enabled: selected != null && moduleKey === "vulns",
    /** Меньше лишних GET при ре-рендерах; явный refetch() после POST /enrich остаётся. */
    staleTime: 8_000,
    refetchOnWindowFocus: false,
    queryFn: () => (selected ? fetchCveDetail(selected) : Promise.reject(new Error("no cve"))),
    refetchInterval: (q) => {
      const d = q.state.data;
      if (!selected || !d?.found) return false;
      const manual = summaryQuery.data?.manualEnrichAllowed !== false;
      if (manual && enrichPosted && enrichTargetCveId === selected) {
        if (!needsOnDemandEnrich(d)) return false;
        const deadline = enrichPollDeadlineRef.current;
        if (deadline != null && Date.now() > deadline) return false;
        return CVE_POLL_WHILE_ENRICH_MS;
      }
      if (!manual) return CVE_POLL_BACKGROUND_ONLY_MS;
      return false;
    },
    refetchIntervalInBackground: false
  });

  /** Пока enrich идёт для другой CVE, опрашиваем её отдельно (selected уже переключили). */
  const enrichPollOffscreenQuery = useQuery({
    queryKey: ["cve", enrichTargetCveId ?? "__enrich_idle__"],
    enabled:
      moduleKey === "vulns" &&
      enrichPosted &&
      enrichTargetCveId != null &&
      enrichTargetCveId !== selected,
    staleTime: 0,
    refetchOnWindowFocus: false,
    queryFn: () => fetchCveDetail(enrichTargetCveId!),
    refetchInterval: (q) => {
      const d = q.state.data;
      if (!d?.found) return false;
      if (!needsOnDemandEnrich(d)) return false;
      const deadline = enrichPollDeadlineRef.current;
      if (deadline != null && Date.now() > deadline) return false;
      return CVE_POLL_WHILE_ENRICH_MS;
    },
    refetchIntervalInBackground: false
  });

  /** Смена CVE в списке: не сбрасываем enrichPosted — иначе обрывается ожидание LLM для другой карточки и refetch шёл не туда. */
  useEffect(() => {
    autoEnrichForCveRef.current = null;
  }, [selected]);

  /** Успешная ИИ-строка для CVE, по которой ждём enrich (учитываем offscreen poll). */
  useEffect(() => {
    if (!enrichTargetCveId || !enrichPosted) return;
    const d =
      enrichTargetCveId === selected ? detailsQuery.data : enrichPollOffscreenQuery.data;
    if (!d?.found) return;
    if (needsOnDemandEnrich(d)) return;
    enrichPollDeadlineRef.current = null;
    setEnrichPosted(false);
    setEnrichTargetCveId(null);
    setEnrichStalled(false);
  }, [detailsQuery.data, enrichPollOffscreenQuery.data, enrichTargetCveId, enrichPosted, selected]);

  /**
   * Do not rely on `setTimeout` alone for the wait cap: React Strict Mode / remounts clear it,
   * leaving `enrichPosted` stuck true while `refetchInterval` already stopped (deadline passed).
   */
  useEffect(() => {
    if (!enrichPosted || enrichTargetCveId == null) return;
    const tick = () => {
      const deadline = enrichPollDeadlineRef.current;
      if (deadline != null && Date.now() > deadline) {
        enrichPollDeadlineRef.current = null;
        setEnrichPosted(false);
        setEnrichTargetCveId(null);
        setEnrichStalled(true);
      }
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [enrichPosted, enrichTargetCveId]);

  const refreshOverview = useCallback(async () => {
    await Promise.all([
      summaryQuery.refetch(),
      hotCvesQuery.refetch(),
      vendorsQuery.refetch(),
      queueHealthQuery.refetch()
    ]);
  }, [summaryQuery, hotCvesQuery, vendorsQuery, queueHealthQuery]);

  const overviewRefreshing =
    summaryQuery.isFetching || hotCvesQuery.isFetching || vendorsQuery.isFetching || queueHealthQuery.isFetching;

  const refreshVulns = useCallback(async () => {
    const tasks: Promise<unknown>[] = [listQuery.refetch(), vendorsQuery.refetch()];
    if (selected) tasks.push(detailsQuery.refetch());
    await Promise.all(tasks);
  }, [listQuery, vendorsQuery, selected, detailsQuery]);

  const vulnsRefreshing =
    listQuery.isFetching || vendorsQuery.isFetching || (selected != null && detailsQuery.isFetching);

  const requestEnrich = useCallback(async (cveId: string, force = false) => {
    enrichKickoffForCveRef.current = cveId;
    setEnrichTargetCveId(cveId);
    setEnrichPosted(true);
    setEnrichStalled(false);
    enrichPollDeadlineRef.current = Date.now() + ENRICH_UI_WAIT_MS;
    try {
      const q = force ? "?force=1" : "";
      const res = await apiFetch(`/api/cves/${encodeURIComponent(cveId)}/enrich${q}`, { method: "POST" });
      if (!res.ok) throw new Error("enrich request failed");
      await queryClient.invalidateQueries({ queryKey: ["cve", cveId] });
    } catch {
      enrichPollDeadlineRef.current = null;
      setEnrichPosted(false);
      setEnrichTargetCveId(null);
      setEnrichStalled(true);
    }
  }, [queryClient]);

  /** При открытии карточки — авто enrich только для CVE за 24ч; старше — только кнопка в панели ИИ. */
  useEffect(() => {
    if (!selected || moduleKey !== "vulns" || !manualEnrichAllowed) return;
    if (detailsQuery.isLoading) return;
    const d = detailsQuery.data;
    if (!d) return;
    if (!shouldAutoEnrichOnOpen(d)) return;
    if (autoEnrichForCveRef.current === selected) return;
    autoEnrichForCveRef.current = selected;
    void requestEnrich(selected, false);
  }, [selected, moduleKey, manualEnrichAllowed, detailsQuery.data, detailsQuery.isLoading, requestEnrich]);

  const items = listQuery.data ?? [];
  const selectedDetails = detailsQuery.data?.found ? detailsQuery.data : null;
  const aiSummaryPending = Boolean(
    selectedDetails &&
      manualEnrichAllowed &&
      enrichPosted &&
      enrichTargetCveId === selected &&
      needsOnDemandEnrich(selectedDetails)
  );

  const graph = useMemo(() => {
    const ai = selectedDetails?.ai as { output_json?: unknown } | null | undefined;
    const parsed = parseAiOutputJson(ai?.output_json ?? null);
    const out = parsed?.graph;
    if (out && typeof out === "object") return out;
    return null;
  }, [selectedDetails]);

  const attackFlowSteps = useMemo(() => {
    const ai = selectedDetails?.ai as { output_json?: unknown } | null | undefined;
    const parsed = parseAiOutputJson(ai?.output_json ?? null);
    const af = parsed?.attackFlow;
    return Array.isArray(af) ? af.map(String).filter(Boolean) : [];
  }, [selectedDetails]);

  const dashboardHighlightSet = useMemo(
    () => new Set(dashboardModals.map((m) => m.cveId)),
    [dashboardModals]
  );

  const openDashboardModal = useCallback((cveId: string) => {
    setDashboardModals((prev) => {
      const dup = prev.find((m) => m.cveId === cveId);
      if (dup) {
        const maxZ = prev.reduce((a, m) => Math.max(a, m.z), 0);
        return prev.map((m) => (m.instanceId === dup.instanceId ? { ...m, z: maxZ + 1 } : m));
      }
      if (prev.length >= 4) return prev;
      const maxZ = prev.length === 0 ? 1999 : Math.max(...prev.map((m) => m.z));
      const i = prev.length;
      const vw = typeof window !== "undefined" ? window.innerWidth : 1200;
      const pad = 24;
      const x = Math.min(32 + (i % 5) * 36, Math.max(16, vw - DASHBOARD_CVE_MODAL_BASE_WIDTH_PX - pad));
      const y = 48 + (i % 5) * 32;
      return [
        ...prev,
        {
          instanceId: crypto.randomUUID(),
          cveId,
          x,
          y,
          z: maxZ + 1
        }
      ];
    });
  }, []);

  const closeDashboardModal = useCallback((instanceId: string) => {
    setDashboardModals((prev) => prev.filter((m) => m.instanceId !== instanceId));
  }, []);

  const moveDashboardModal = useCallback((instanceId: string, x: number, y: number) => {
    setDashboardModals((prev) => prev.map((m) => (m.instanceId === instanceId ? { ...m, x, y } : m)));
  }, []);

  const focusDashboardModal = useCallback((instanceId: string) => {
    setDashboardModals((prev) => {
      const maxZ = prev.reduce((a, m) => Math.max(a, m.z), 0);
      return prev.map((m) => (m.instanceId === instanceId ? { ...m, z: maxZ + 1 } : m));
    });
  }, []);

  const switchModule = (next: ModuleKey) => {
    if (moduleKey === "dashboard" && next !== "dashboard") {
      setDashboardModals([]);
    }
    setModuleKey(next);
    if (next !== "vulns" && next !== "dashboard") setSelected(null);
  };

  return (
    <div className="mx-auto max-w-[1400px]">
      <div className="mt-6 grid min-h-[calc(100vh-48px)] grid-cols-[56px_minmax(0,1fr)] gap-6">
        <aside className="glass sticky top-6 flex h-[calc(100vh-48px)] flex-col items-center gap-2 self-start rounded-2xl p-2">
          <button
            onClick={() => {
              switchModule("dashboard");
            }}
            className={cn(
              "flex h-11 w-11 items-center justify-center rounded-xl border text-fg/85",
              "hover:bg-slate-100 dark:hover:bg-black/25",
              moduleKey === "dashboard"
                ? "border-accent/30 bg-accent/10"
                : "border-slate-200 bg-white shadow-sm dark:border-border dark:bg-black/10 dark:shadow-none"
            )}
            title="Дашборды"
          >
            <BarChart3 className="h-5 w-5" />
          </button>
          <button
            onClick={() => switchModule("vulns")}
            className={cn(
              "flex h-11 w-11 items-center justify-center rounded-xl border text-fg/85",
              "hover:bg-slate-100 dark:hover:bg-black/25",
              moduleKey === "vulns"
                ? "border-accent/30 bg-accent/10"
                : "border-slate-200 bg-white shadow-sm dark:border-border dark:bg-black/10 dark:shadow-none"
            )}
            title="Уязвимости"
          >
            <ShieldAlert className="h-5 w-5" />
          </button>
          <button
            onClick={() => switchModule("fstec")}
            className={cn(
              "flex h-11 w-11 items-center justify-center rounded-xl border text-fg/85",
              "hover:bg-slate-100 dark:hover:bg-black/25",
              moduleKey === "fstec"
                ? "border-accent/30 bg-accent/10"
                : "border-slate-200 bg-white shadow-sm dark:border-border dark:bg-black/10 dark:shadow-none"
            )}
            title="ФСТЭК"
          >
            <ShieldCheck className="h-5 w-5" />
          </button>
          <button
            onClick={() => switchModule("patches")}
            className={cn(
              "flex h-11 w-11 items-center justify-center rounded-xl border text-fg/85",
              "hover:bg-slate-100 dark:hover:bg-black/25",
              moduleKey === "patches"
                ? "border-accent/30 bg-accent/10"
                : "border-slate-200 bg-white shadow-sm dark:border-border dark:bg-black/10 dark:shadow-none"
            )}
            title="Патч‑менеджмент"
          >
            <Bandage className="h-5 w-5" />
          </button>
          <button
            onClick={() => switchModule("asv")}
            className={cn(
              "flex h-11 w-11 items-center justify-center rounded-xl border text-fg/85",
              "hover:bg-slate-100 dark:hover:bg-black/25",
              moduleKey === "asv"
                ? "border-accent/30 bg-accent/10"
                : "border-slate-200 bg-white shadow-sm dark:border-border dark:bg-black/10 dark:shadow-none"
            )}
            title="ASV Scanner"
          >
            <Radar className="h-5 w-5" />
          </button>
          <button
            onClick={() => switchModule("settings")}
            className={cn(
              "mt-auto flex h-11 w-11 items-center justify-center rounded-xl border text-fg/85",
              "hover:bg-slate-100 dark:hover:bg-black/25",
              moduleKey === "settings"
                ? "border-accent/30 bg-accent/10"
                : "border-slate-200 bg-white shadow-sm dark:border-border dark:bg-black/10 dark:shadow-none"
            )}
            title="Настройки"
          >
            <Settings className="h-5 w-5" />
          </button>
        </aside>

        <main className="min-w-0">
          {moduleKey === "dashboard" ? (
            <div className="glass rounded-2xl p-5 sm:p-6">
              <OverviewDashboardPanel
                data={summaryQuery.data}
                loading={summaryQuery.isLoading}
                error={summaryQuery.isError ? (summaryQuery.error as Error) : null}
                vendors={vendorsQuery.data}
                vendorsLoading={vendorsQuery.isLoading}
                hotCves={hotCvesQuery.data}
                hotLoading={hotCvesQuery.isLoading}
                dashboardHighlightCveIds={dashboardHighlightSet}
                onHotCveClick={openDashboardModal}
                onVendorSelect={(v) => {
                  switchModule("vulns");
                  setView("last24h");
                  setVendorFilter(v);
                  setProductFilter(null);
                  setQ("");
                }}
                onProductSelect={(vendor, product) => {
                  switchModule("vulns");
                  setView("last24h");
                  setVendorFilter(vendor);
                  setProductFilter(product);
                  setQ("");
                }}
                queueHealth={queueHealthQuery.data}
                onOpenDlq={() => setDlqOpen(true)}
                onRefresh={() => void refreshOverview()}
                refreshing={overviewRefreshing}
              />
            </div>
          ) : moduleKey === "vulns" ? (
            <div className="mt-0 grid grid-cols-12 gap-6">
              <section className="col-span-12 lg:col-span-4">
                <div className="glass overflow-visible rounded-2xl p-4">
                  <div className="mb-1 flex items-start justify-between gap-2">
                    <div className="min-w-0 space-y-0.5">
                      <div className="text-sm font-medium">Уязвимости</div>
                      <div className="text-[11px] text-muted">
                        Список, фильтры и карточки CVE. Основной сценарий — полнотекстовый поиск ниже.
                      </div>
                    </div>
                    <button
                      type="button"
                      title="Обновить список и подсказки"
                      onClick={() => void refreshVulns()}
                      disabled={vulnsRefreshing}
                      className={cn(
                        "inline-flex shrink-0 items-center gap-1.5 rounded-xl border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-[11px] text-fg/90",
                        "hover:bg-slate-100 dark:border-border dark:bg-black/20 dark:hover:bg-black/35",
                        vulnsRefreshing && "cursor-wait opacity-80"
                      )}
                    >
                      {vulnsRefreshing ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <RefreshCw className="h-3.5 w-3.5" />
                      )}
                      Обновить
                    </button>
                  </div>
                  <VulnSearchBar
                    value={q}
                    onChange={setQ}
                    hints={
                      vendorsQuery.data
                        ? { vendors: vendorsQuery.data.vendors, products: vendorsQuery.data.products }
                        : null
                    }
                    hintsLoading={vendorsQuery.isLoading}
                    listLoading={listQuery.isFetching}
                    onClearFilters={() => {
                      setVendorFilter(null);
                      setProductFilter(null);
                    }}
                  />
                  <div className="mb-3 flex flex-wrap items-center gap-2">
                    <button
                      onClick={() => {
                        setBulkMode((b) => !b);
                        setSelectedIds({});
                      }}
                      className={cn(
                        "rounded-lg border px-2 py-1 text-xs hover:bg-slate-200/80 dark:hover:bg-black/30",
                        bulkMode
                          ? "border-accent/30 bg-accent/10 text-fg/90"
                          : "border-slate-200 bg-slate-50 text-fg/90 dark:border-border dark:bg-black/20"
                      )}
                    >
                      Массово
                    </button>
                    <button
                      onClick={exportCsv}
                      className="rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-xs text-fg/90 hover:bg-slate-200/80 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                    >
                      Экспорт CSV
                    </button>
                    <button
                      onClick={() => setSavedViewsOpen(true)}
                      className="rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-xs text-fg/90 hover:bg-slate-200/80 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                    >
                      Виды
                    </button>
                  </div>

                  <div className="mb-3 rounded-xl border border-slate-200/90 bg-slate-50/90 p-3 dark:border-white/[0.06] dark:bg-black/15">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="text-[11px] font-medium text-fg/85">Фильтры</div>
                      <div className="flex items-center gap-2">
                        <select
                          value={sort}
                          onChange={(e) => setSort(e.target.value as "rank" | "fresh" | "risk" | "epss" | "cvss")}
                          className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-xs text-fg/90 dark:border-border dark:bg-black/20"
                          title="Сортировка"
                        >
                          <option value="rank">Ранг</option>
                          <option value="risk">Риск</option>
                          <option value="epss">EPSS</option>
                          <option value="cvss">CVSS</option>
                          <option value="fresh">Свежесть</option>
                        </select>
                        <button
                          onClick={() => {
                            setKevOnly((v) => !v);
                            if (!kevOnly) setView("kev");
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
                      </div>
                    </div>

                    <Tabs.Root value={view} onValueChange={(v) => setView(v as typeof view)}>
                      <Tabs.List className="mt-2 grid grid-cols-5 gap-2">
                        {[
                          ["critical_v2", "Критичные"],
                          ["latest", "Свежие"],
                          ["last24h", "24 ч"],
                          ["kev", "KEV"],
                          ["all", "Все"]
                        ].map(([k, label]) => (
                          <Tabs.Trigger
                            key={k}
                            value={k as typeof view}
                            className="rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] data-[state=active]:border-accent/40 data-[state=active]:bg-accent/10 dark:border-border dark:bg-black/20"
                          >
                            {label}
                          </Tabs.Trigger>
                        ))}
                      </Tabs.List>
                    </Tabs.Root>

                    <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px]">
                      <div className="flex items-center gap-1 rounded-full border border-slate-200 bg-slate-50 px-2 py-1 dark:border-border dark:bg-black/20">
                        <span className="text-muted">CVSS</span>
                        <button
                          onClick={() => setMinCvss(null)}
                          className={cn(
                            "rounded-full px-2 py-0.5",
                            minCvss == null
                              ? "bg-white text-fg/90 shadow-sm dark:bg-white/10"
                              : "hover:bg-slate-200/80 dark:hover:bg-white/5"
                          )}
                        >
                          выкл
                        </button>
                        <button
                          onClick={() => setMinCvss(8)}
                          className={cn(
                            "rounded-full px-2 py-0.5",
                            minCvss === 8 ? "bg-accent/15 text-fg/90" : "hover:bg-slate-200/80 dark:hover:bg-white/5"
                          )}
                        >
                          ≥8
                        </button>
                        <button
                          onClick={() => setMinCvss(9)}
                          className={cn(
                            "rounded-full px-2 py-0.5",
                            minCvss === 9 ? "bg-accent/15 text-fg/90" : "hover:bg-slate-200/80 dark:hover:bg-white/5"
                          )}
                        >
                          ≥9
                        </button>
                      </div>

                      <div className="flex items-center gap-1 rounded-full border border-slate-200 bg-slate-50 px-2 py-1 dark:border-border dark:bg-black/20">
                        <span className="text-muted">EPSS</span>
                        <button
                          onClick={() => setMinEpss(null)}
                          className={cn(
                            "rounded-full px-2 py-0.5",
                            minEpss == null
                              ? "bg-white text-fg/90 shadow-sm dark:bg-white/10"
                              : "hover:bg-slate-200/80 dark:hover:bg-white/5"
                          )}
                        >
                          выкл
                        </button>
                        <button
                          onClick={() => setMinEpss(0.2)}
                          className={cn(
                            "rounded-full px-2 py-0.5",
                            minEpss === 0.2 ? "bg-accent/15 text-fg/90" : "hover:bg-slate-200/80 dark:hover:bg-white/5"
                          )}
                        >
                          ≥0.20
                        </button>
                        <button
                          onClick={() => setMinEpss(0.5)}
                          className={cn(
                            "rounded-full px-2 py-0.5",
                            minEpss === 0.5 ? "bg-accent/15 text-fg/90" : "hover:bg-slate-200/80 dark:hover:bg-white/5"
                          )}
                        >
                          ≥0.50
                        </button>
                      </div>

                      {(vendorFilter || productFilter) && (
                        <div className="flex flex-wrap items-center gap-2">
                          {vendorFilter ? (
                            <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 text-fg/85 shadow-sm dark:border-white/10 dark:bg-white/5">
                              вендор <span className="font-medium text-fg/90">{vendorFilter}</span>
                            </span>
                          ) : null}
                          {productFilter ? (
                            <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 text-fg/85 shadow-sm dark:border-white/10 dark:bg-white/5">
                              продукт <span className="font-medium text-fg/90">{productFilter}</span>
                            </span>
                          ) : null}
                          <button
                            className="rounded-full border border-slate-200 bg-slate-100 px-2 py-0.5 text-fg/80 hover:bg-slate-200/80 dark:border-white/10 dark:bg-black/20 dark:hover:bg-black/30"
                            onClick={() => {
                              setVendorFilter(null);
                              setProductFilter(null);
                            }}
                          >
                            Сбросить
                          </button>
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="space-y-3">
                    {items.map((it) => (
                      <CveCard
                        key={it.cve_id}
                        item={it}
                        selected={selected === it.cve_id}
                        onSelect={() => setSelected(it.cve_id)}
                        triage={triage[it.cve_id]}
                        showCheckbox={bulkMode}
                        checked={Boolean(selectedIds[it.cve_id])}
                        onToggleChecked={(next) =>
                          setSelectedIds((m) => {
                            const n = { ...m };
                            if (next) n[it.cve_id] = true;
                            else delete n[it.cve_id];
                            return n;
                          })
                        }
                      />
                    ))}
                    {items.length === 0 ? (
                      <div className="text-sm text-muted">Для этого вида пока нет CVE.</div>
                    ) : null}
                  </div>
                </div>
              </section>

              <section className="col-span-12 lg:col-span-8">
                <div className="glass rounded-2xl p-5 sm:p-6">
                  {selected ? (
                    <Tabs.Root defaultValue="ai">
                      <Tabs.List className="mb-4 flex flex-wrap gap-2">
                        <Tabs.Trigger
                          value="ai"
                          className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs data-[state=active]:border-accent/40 data-[state=active]:bg-accent/10 dark:border-border dark:bg-black/20"
                        >
                          ИИ‑сводка
                        </Tabs.Trigger>
                        <Tabs.Trigger
                          value="risk"
                          className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs data-[state=active]:border-accent/40 data-[state=active]:bg-accent/10 dark:border-border dark:bg-black/20"
                        >
                          Риск
                        </Tabs.Trigger>
                        <Tabs.Trigger
                          value="attack"
                          className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs data-[state=active]:border-accent/40 data-[state=active]:bg-accent/10 dark:border-border dark:bg-black/20"
                        >
                          Граф атаки
                        </Tabs.Trigger>
                        <Tabs.Trigger
                          value="sources"
                          className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs data-[state=active]:border-accent/40 data-[state=active]:bg-accent/10 dark:border-border dark:bg-black/20"
                        >
                          Источники
                        </Tabs.Trigger>
                        <div className="ml-auto flex items-center gap-2 text-[11px] text-muted">
                          <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 font-mono text-fg/85 shadow-sm dark:border-white/10 dark:bg-white/5">
                            {selected}
                          </span>
                          <button
                            onClick={() => setSelected(null)}
                            className="rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-fg/85 hover:bg-slate-200/80 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                          >
                            Закрыть
                          </button>
                        </div>
                      </Tabs.List>

                      <Tabs.Content value="ai">
                        <AiSummaryPanel
                          data={selectedDetails}
                          loading={detailsQuery.isLoading}
                          aiPending={aiSummaryPending}
                          aiStalled={enrichStalled}
                          manualEnrichAllowed={manualEnrichAllowed}
                          onRequestEnrich={
                            selected ? (opts) => void requestEnrich(selected, Boolean(opts?.force)) : undefined
                          }
                        />
                      </Tabs.Content>
                      <Tabs.Content value="risk">
                        <RiskBreakdownPanel data={selectedDetails} />
                      </Tabs.Content>
                      <Tabs.Content value="attack">
                        <AttackGraphPanel graph={graph} attackFlow={attackFlowSteps} />
                      </Tabs.Content>
                      <Tabs.Content value="sources">
                        <CveSourcesPanel data={selectedDetails} />
                      </Tabs.Content>
                    </Tabs.Root>
                  ) : (
                    <div>
                      <div className="text-sm font-medium">Анализ</div>
                      <div className="mt-2 text-sm text-muted">
                        Выбери CVE слева — здесь появятся ИИ‑сводка, risk‑разбор и схема атаки.
                      </div>
                      <div className="mt-4 grid grid-cols-2 gap-3 text-[11px]">
                        <div className="rounded-xl border border-slate-200/90 bg-slate-50 p-3 dark:border-white/[0.06] dark:bg-black/20">
                          <div className="text-muted">Сводка</div>
                          <div className="mt-1 text-fg/85">Русский текст + remediation/последствия</div>
                        </div>
                        <div className="rounded-xl border border-slate-200/90 bg-slate-50 p-3 dark:border-white/[0.06] dark:bg-black/20">
                          <div className="text-muted">Attack graph</div>
                          <div className="mt-1 text-fg/85">Схема attacker → vector → asset → impact</div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </section>
            </div>
          ) : moduleKey === "fstec" ? (
            <FstecNewsPanel onOpenCve={openDashboardModal} />
          ) : moduleKey === "patches" ? (
            <div className="glass rounded-2xl p-5 sm:p-6">
              <PatchManagementPanel onOpenCve={openDashboardModal} />
            </div>
          ) : moduleKey === "asv" ? (
            <div className="glass rounded-2xl p-5 sm:p-6">
              <AsvScannerPanel />
            </div>
          ) : (
            <div className="glass rounded-2xl p-6">
              <div className="text-sm font-medium">Настройки</div>
              <div className="mt-4 space-y-6">
                <AppearanceSettings />
                <SecuritySettings />
              </div>
            </div>
          )}
        </main>
      </div>

      <Dialog.Root open={dlqOpen} onOpenChange={setDlqOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content
            className={cn(
              "fixed left-1/2 top-1/2 z-50 w-[min(900px,calc(100vw-24px))] -translate-x-1/2 -translate-y-1/2",
              "rounded-2xl border border-border bg-white shadow-2xl backdrop-blur-xl dark:bg-black/60",
              "outline-none"
            )}
          >
            <div className="glass rounded-2xl">
              <div className="sticky top-0 z-10 rounded-t-2xl border-b border-slate-200 bg-white/95 px-5 py-4 backdrop-blur-xl dark:border-border dark:bg-black/60">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <Dialog.Title className="truncate text-sm font-semibold tracking-tight">Очередь DLQ</Dialog.Title>
                    <Dialog.Description className="mt-1 text-xs text-muted">
                      Просмотр сообщений, повторная постановка в очередь или очистка мёртвых писем.
                    </Dialog.Description>
                  </div>
                  <Dialog.Close asChild>
                    <button className="rounded-lg border border-slate-200 bg-slate-100 px-3 py-1.5 text-xs text-fg/90 hover:bg-slate-200/80 dark:border-border dark:bg-black/30 dark:hover:bg-black/40">
                      Закрыть
                    </button>
                  </Dialog.Close>
                </div>
              </div>

              <div className="p-5">
                <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <select
                      value={dlqQueue}
                      onChange={(e) => setDlqQueue(e.target.value as "dlq.ai.enrich" | "dlq.ai.score")}
                      className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-xs text-fg/90 dark:border-border dark:bg-black/20"
                    >
                      <option value="dlq.ai.enrich">dlq.ai.enrich</option>
                      <option value="dlq.ai.score">dlq.ai.score</option>
                    </select>
                    <button
                      onClick={() => void dlqSampleQuery.refetch()}
                      className="rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-xs text-fg/90 hover:bg-slate-200/80 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                    >
                      Обновить
                    </button>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => void dlqRetry()}
                      className="rounded-lg border border-accent/30 bg-accent/10 px-3 py-1.5 text-xs text-fg/90 hover:bg-accent/15"
                      title="До 1000 сообщений вернуть в основные очереди"
                    >
                      Повторить 1000
                    </button>
                    <button
                      onClick={() => void dlqClear()}
                      className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-1.5 text-xs text-danger hover:bg-danger/15"
                      title="Подтвердить и удалить до 1000 сообщений"
                    >
                      Очистить 1000
                    </button>
                  </div>
                </div>

                <div className="space-y-3">
                  {dlqSampleQuery.isError ? (
                    <div className="rounded-xl border border-danger/30 bg-danger/10 p-3 text-xs text-danger">
                      {String((dlqSampleQuery.error as Error | null)?.message ?? "Failed to load DLQ sample")}
                    </div>
                  ) : null}

                  {(
                    (dlqSampleQuery.data as
                      | { messages?: Array<{ body: string; headers?: Record<string, unknown>; redelivered?: boolean }> }
                      | undefined)?.messages ?? []
                  ).length ? (
                    <div className="space-y-2">
                      {(
                        (dlqSampleQuery.data as
                          | { messages?: Array<{ body: string; headers?: Record<string, unknown>; redelivered?: boolean }> }
                          | undefined)?.messages ?? []
                      ).map((m, idx) => (
                        <div key={idx} className="rounded-xl border border-slate-200/90 bg-slate-50 p-3 dark:border-white/[0.06] dark:bg-black/25">
                          <div className="mb-2 flex items-center justify-between gap-2 text-[11px] text-muted">
                            <div>повторная доставка: {String(Boolean(m.redelivered))}</div>
                            <div className="truncate">
                              x-death:{" "}
                              <span className="text-fg/80">
                                {Array.isArray(m.headers?.["x-death"]) ? (m.headers["x-death"] as unknown[]).length : 0}
                              </span>
                            </div>
                          </div>
                          <pre className="max-h-[220px] overflow-auto whitespace-pre-wrap break-words rounded-lg border border-slate-200 bg-white p-3 text-[11px] text-fg/85 dark:border-white/10 dark:bg-black/30">
                            {String(m.body ?? "").slice(0, 6000)}
                          </pre>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-sm text-muted">
                      {dlqSampleQuery.isFetching ? "Загрузка…" : "Очередь пуста"}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      <Dialog.Root open={savedViewsOpen} onOpenChange={setSavedViewsOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content
            className={cn(
              "fixed left-1/2 top-1/2 z-50 w-[min(700px,calc(100vw-24px))] -translate-x-1/2 -translate-y-1/2",
              "rounded-2xl border border-border bg-white shadow-2xl backdrop-blur-xl dark:bg-black/60",
              "outline-none"
            )}
          >
            <div className="glass rounded-2xl">
              <div className="sticky top-0 z-10 rounded-t-2xl border-b border-slate-200 bg-white/95 px-5 py-4 backdrop-blur-xl dark:border-border dark:bg-black/60">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <Dialog.Title className="truncate text-sm font-semibold tracking-tight">Сохранённые виды</Dialog.Title>
                    <Dialog.Description className="mt-1 text-xs text-muted">
                      Переименование или удаление сохранённых пресетов фильтров.
                    </Dialog.Description>
                  </div>
                  <Dialog.Close asChild>
                    <button className="rounded-lg border border-slate-200 bg-slate-100 px-3 py-1.5 text-xs text-fg/90 hover:bg-slate-200/80 dark:border-border dark:bg-black/30 dark:hover:bg-black/40">
                      Закрыть
                    </button>
                  </Dialog.Close>
                </div>
              </div>

              <div className="p-5">
                {savedViews.length ? (
                  <div className="space-y-2">
                    {savedViews.map((v) => (
                      <div
                        key={v.id}
                        className="flex items-center justify-between gap-2 rounded-xl border border-slate-200/90 bg-slate-50 px-3 py-2 text-[11px] dark:border-white/[0.06] dark:bg-black/25"
                      >
                        <button
                          className="min-w-0 truncate text-left text-fg/90 hover:underline"
                          onClick={() => {
                            setView(v.state.view);
                            setSort(v.state.sort);
                            setLimit(v.state.limit);
                            setKevOnly(v.state.kevOnly);
                            setMinCvss(v.state.minCvss);
                            setMinEpss(v.state.minEpss);
                            setVendorFilter(v.state.vendorFilter);
                            setProductFilter(v.state.productFilter);
                            setQ(v.state.q);
                            setSavedViewsOpen(false);
                          }}
                        >
                          {v.name}
                        </button>
                        <div className="flex items-center gap-2">
                          <button
                            className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-[11px] text-fg/85 hover:bg-slate-100 dark:border-white/10 dark:bg-black/20 dark:hover:bg-black/30"
                            onClick={() => {
                              const name = window.prompt("Новое имя вида", v.name);
                              if (!name) return;
                              setSavedViews((xs) => xs.map((x) => (x.id === v.id ? { ...x, name } : x)));
                            }}
                          >
                            Переименовать
                          </button>
                          <button
                            className="rounded-lg border border-danger/30 bg-danger/10 px-2 py-1 text-[11px] text-danger hover:bg-danger/15"
                            onClick={() => {
                              if (!window.confirm(`Удалить сохранённый вид «${v.name}»?`)) return;
                            setSavedViews((xs) => xs.filter((x) => x.id !== v.id));
                            }}
                          >
                            Удалить
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-sm text-muted">Пока нет сохранённых видов.</div>
                )}
              </div>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      <DraggableCveModals
        modals={dashboardModals}
        manualEnrichAllowed={manualEnrichAllowed}
        onClose={closeDashboardModal}
        onMove={moveDashboardModal}
        onFocus={focusDashboardModal}
      />
    </div>
  );
}


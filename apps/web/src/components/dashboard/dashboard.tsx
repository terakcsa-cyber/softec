"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { useAuth } from "@/contexts/auth-context";
import { apiFetch } from "@/lib/api-fetch";
import { needsOnDemandBduEnrich, parseAiOutputJson as parseBduAiOutputJson, shouldAutoEnrichBduOnOpen } from "@/lib/bdu-enrich-ui";
import { needsOnDemandEnrich, parseAiOutputJson, shouldAutoEnrichOnOpen } from "@/lib/cve-enrich-ui";
import { defaultAttackFlowSteps, isUsableAttackGraph } from "@/lib/baseline-enrichment";
import { CVE_POLL_BACKGROUND_ONLY_MS, CVE_POLL_WHILE_ENRICH_MS, ENRICH_UI_WAIT_MS } from "@/lib/enrich-ui-wait";
import { useLivePollInterval } from "@/lib/live-refresh";
import { EXPLOIT_RADAR_FILTER_LABELS, type ExploitRadarFilter } from "@/lib/exploit-intel-client";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Bandage,
  BarChart3,
  ClipboardList,
  HeartPulse,
  Inbox,
  Loader2,
  Pin,
  PinOff,
  RefreshCw,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Target
} from "lucide-react";
import * as Tabs from "@radix-ui/react-tabs";
import * as Dialog from "@radix-ui/react-dialog";
import { cn } from "../ui/cn";
import { CveCard } from "./cve-card";
import { AiSummaryPanel } from "./ai-summary-panel";
import { OverviewDashboardPanel } from "./overview-dashboard-panel";
import { SettingsPanel } from "./settings-panel";
import { SystemHealthPanel } from "./system-health-panel";
import { ThreatFeedPanel } from "./threat-feed-panel";
import { VocHomePanel } from "./voc-home-panel";
import { computeCvePriority } from "@/lib/cve-priority";
import { computeBduPriority } from "@/lib/bdu-priority";
import { cveRefKey } from "@/lib/voc-ref-keys";
import { useVocTriage } from "@/lib/voc-triage-context";
import { CveDetailPanel } from "./cve-detail-panel";
import { BduCard, type BduListItem } from "./bdu-card";
import { BduDetailPanel, type BduDetailsPayload } from "./bdu-detail-panel";

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
import {
  DASHBOARD_BDU_MODAL_BASE_WIDTH_PX,
  DraggableBduModals,
  type DashboardBduModalFrame
} from "./draggable-bdu-modals";
import { FstecModulePanel } from "../fstec/fstec-module-panel";
import { PatchManagementPanel } from "./patch-management-panel";
import { VulnSearchBar } from "./vuln-search-bar";
import { VulnTaskPanel } from "./vuln-task-panel";
import { VulnClassFilter } from "./vuln-class-filter";
import { VulnClassBadge } from "./vuln-class-badge";
import { isVulnClassId, type VulnClassId } from "@/lib/vuln-class";

type CveListItem = {
  cve_id: string;
  bdu_ids?: string[] | null;
  published_at: string | null;
  modified_at: string | null;
  risk_score: number | null;
  epss?: number | null;
  cvss_base?: number | null;
  vp_vendor?: string | null;
  vp_product?: string | null;
  short_description?: string | null;
  short_ru?: string | null;
  task_open_count?: number | null;
  cvss_av_network?: boolean;
  cvss_pr_none?: boolean;
  cvss_ui_none?: boolean;
  cvss_ac_low?: boolean;
  perimeter_product?: boolean;
  exploit_known?: boolean;
  critical_reasons?: string[] | null;
  ai_ready?: boolean;
  vuln_class?: string | null;
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

async function fetchBduDetail(bduId: string): Promise<BduDetailsPayload> {
  const res = await apiFetch(`/api/bdu/${encodeURIComponent(bduId)}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch BDU");
  return (await res.json()) as BduDetailsPayload;
}

type SavedView = {
  id: string;
  name: string;
  state: {
    view: "critical_v2" | "critical" | "latest" | "last24h" | "kev" | "exploit" | "all";
    sort: "rank" | "fresh" | "risk" | "epss" | "cvss" | "exploit" | "priority";
    limit: 15 | 20;
    kevOnly: boolean;
    minCvss: number | null;
    minEpss: number | null;
    vendorFilter: string | null;
    productFilter: string | null;
    vulnClasses: VulnClassId[];
    exploitFilter: ExploitRadarFilter | null;
    /** @deprecated legacy single-select */
    vulnClass?: string | null;
    q: string;
  };
};

type ModuleKey =
  | "dashboard"
  | "voc"
  | "vulns"
  | "threat"
  | "tasks"
  | "fstec"
  | "patches"
  | "systemHealth"
  | "settings";
type VulnPreviewRef = { kind: "cve" | "bdu"; id: string };

function vulnPreviewKey(ref: VulnPreviewRef): string {
  return `${ref.kind}:${ref.id}`;
}

function vulnPreviewFromEntry(entry: { kind: "cve"; item: { cve_id: string } } | { kind: "bdu"; item: { bduId: string } }): VulnPreviewRef {
  return entry.kind === "cve" ? { kind: "cve", id: entry.item.cve_id } : { kind: "bdu", id: entry.item.bduId };
}

function findVulnPreviewIndex(
  entries: Array<{ kind: "cve"; item: { cve_id: string } } | { kind: "bdu"; item: { bduId: string } }>,
  ref: VulnPreviewRef | null
): number {
  if (!ref) return -1;
  return entries.findIndex((entry) => {
    const id = entry.kind === "cve" ? entry.item.cve_id : entry.item.bduId;
    return entry.kind === ref.kind && id === ref.id;
  });
}

export function Dashboard() {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const canWrite = user?.role !== "viewer";
  const [moduleKey, setModuleKey] = useState<ModuleKey>("dashboard");
  const [tasksSelectedId, setTasksSelectedId] = useState<string | null>(null);
  const [q, setQ] = useState("");
  /** Задержка запроса к API при наборе текста полнотекстового поиска */
  const [qDebounced, setQDebounced] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [selectedBdu, setSelectedBdu] = useState<string | null>(null);
  const [hoveredPreview, setHoveredPreview] = useState<VulnPreviewRef | null>(null);
  const [pinnedPreview, setPinnedPreview] = useState<VulnPreviewRef | null>(null);
  const [kbdPreview, setKbdPreview] = useState<VulnPreviewRef | null>(null);
  const hoverDebounceRef = useRef<number | null>(null);
  const [view, setView] = useState<"critical_v2" | "critical" | "latest" | "last24h" | "kev" | "exploit" | "all">("critical_v2");
  const [limit, setLimit] = useState<15 | 20>(20);
  const [sort, setSort] = useState<"rank" | "fresh" | "risk" | "epss" | "cvss" | "exploit" | "priority">("rank");
  const [attentionOnly, setAttentionOnly] = useState(false);
  const [kevOnly, setKevOnly] = useState(false);
  const [minCvss, setMinCvss] = useState<number | null>(null);
  const [minEpss, setMinEpss] = useState<number | null>(null);
  const [vendorFilter, setVendorFilter] = useState<string | null>(null);
  const [productFilter, setProductFilter] = useState<string | null>(null);
  const [exploitFilter, setExploitFilter] = useState<ExploitRadarFilter | null>(null);
  const [vulnClasses, setVulnClasses] = useState<VulnClassId[]>([]);
  const [savedViews, setSavedViews] = useState<SavedView[]>([]);
  const [savedViewsOpen, setSavedViewsOpen] = useState(false);
  const { isDone } = useVocTriage();
  const [bulkMode, setBulkMode] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Record<string, true>>({});

  useEffect(() => {
    try {
      const raw = localStorage.getItem("vip:savedViews");
      if (raw) setSavedViews(JSON.parse(raw));
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

  const livePollMs = useLivePollInterval();

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
  const [bduEnrichPosted, setBduEnrichPosted] = useState(false);
  const [bduEnrichTargetId, setBduEnrichTargetId] = useState<string | null>(null);
  const [bduEnrichStalled, setBduEnrichStalled] = useState(false);
  const bduEnrichPollDeadlineRef = useRef<number | null>(null);
  const autoEnrichForBduRef = useRef<string | null>(null);
  const [dashboardModals, setDashboardModals] = useState<DashboardModalFrame[]>([]);
  const [dashboardBduModals, setDashboardBduModals] = useState<DashboardBduModalFrame[]>([]);

  const summaryQuery = useQuery({
    queryKey: ["stats", "summary"],
    queryFn: async () => {
      const res = await apiFetch(`/api/stats/summary`, { cache: "no-store" });
      if (!res.ok) throw new Error(`Failed to fetch summary (${res.status})`);
      return (await res.json()) as {
        totalCves: number;
        cvesLastHourCount?: number;
        cvesPublishedLast24hCount?: number;
        maxPublishedAt?: string | null;
        totalBduCount?: number;
        bduPublishedLast24hCount?: number;
        cveBduLinkCount?: number;
        maxBduPublicationAt?: string | null;
        kevCount: number;
        epssCount: number;
        cvssCount: number;
        scoredCount: number;
        aiEnrichedCount?: number;
        hot24CveCount?: number;
        hot24AiEnrichedCount?: number;
        hot24ScoredCount?: number;
        hot24EpssCount?: number;
        hot24CvssCount?: number;
        aiEnrichPerMinute?: number;
        aiLastEnrichAt?: string | null;
        manualEnrichAllowed?: boolean;
        freshness?: {
          nvdWatermarkTs?: string | null;
          epssIngestTs?: string | null;
          kevIngestTs?: string | null;
          riskScoreComputedAt?: string | null;
          bduIngestTs?: string | null;
        };
      };
    },
    staleTime: 8_000,
    refetchInterval: moduleKey === "dashboard" ? livePollMs : false,
    refetchIntervalInBackground: false
  });

  /** Как на API: по умолчанию разрешено, только `false` отключает. Пока summary грузится — не блокируем кнопки (`=== true` ломало ручной enrich). */
  const manualEnrichAllowed = summaryQuery.data?.manualEnrichAllowed !== false && canWrite;

  const vendorsQuery = useQuery({
    queryKey: ["stats", "vendors", 24, 50],
    enabled: moduleKey === "dashboard" || moduleKey === "vulns",
    queryFn: async () => {
      const res = await apiFetch(`/api/stats/vendors?windowHours=24&limit=50`, { cache: "no-store" });
      if (!res.ok) throw new Error(`Failed to fetch vendors (${res.status})`);
      return (await res.json()) as {
        windowHours: number;
        sampledCves: number;
        sampledBdu?: number;
        sampledTotal?: number;
        usedBdu?: number;
        method?: string;
        usedCpe?: number;
        usedFallback?: number;
        vendors: { vendor: string; count: number }[];
        products: { vendor: string; product: string; count: number }[];
      };
    },
    staleTime: 8_000,
    refetchInterval: moduleKey === "dashboard" || moduleKey === "vulns" ? livePollMs : false,
    refetchIntervalInBackground: false
  });

  const topPriorityQuery = useQuery({
    queryKey: ["cves", "dashboard", "topPriority", "latest", "rank", 80],
    enabled: moduleKey === "dashboard",
    staleTime: 8_000,
    refetchInterval: moduleKey === "dashboard" ? livePollMs : false,
    refetchIntervalInBackground: false,
    queryFn: async () => {
      const url = new URL(`/api/cves`, window.location.origin);
      url.searchParams.set("view", "latest");
      url.searchParams.set("sort", "rank");
      url.searchParams.set("limit", "80");
      const res = await apiFetch(url.toString(), { cache: "no-store" });
      if (!res.ok) throw new Error(`Failed to fetch top priority CVEs (${res.status})`);
      const data = (await res.json()) as { items: CveListItem[] };
      return data.items;
    }
  });

  const bduListQuery = useQuery({
    queryKey: ["bdu", "search", qDebounced],
    enabled: moduleKey === "vulns" && qDebounced.length > 0,
    queryFn: async () => {
      const url = new URL(`/api/bdu`, window.location.origin);
      url.searchParams.set("q", qDebounced);
      url.searchParams.set("limit", "20");
      const res = await apiFetch(url.toString(), { cache: "no-store" });
      if (!res.ok) throw new Error(`Поиск БДУ (${res.status})`);
      return (await res.json()) as { items: BduListItem[] };
    },
    staleTime: 30_000
  });

  const listQuery = useQuery({
    queryKey: ["cves", view, limit, sort, kevOnly, minCvss, minEpss, vendorFilter, productFilter, vulnClasses, exploitFilter, qDebounced],
    enabled: moduleKey === "vulns",
    queryFn: async () => {
      const url = new URL(`/api/cves`, window.location.origin);
      url.searchParams.set("limit", String(view === "all" ? 50 : limit));
      url.searchParams.set("view", view === "all" ? "latest" : view);
      // `priority` is client-side (bank-ish); use upstream rank/fresh then re-sort locally.
      const upstreamSort =
        sort === "priority"
          ? "rank"
          : view === "exploit" && sort === "rank"
            ? "exploit"
            : view === "critical" || view === "critical_v2"
              ? sort
              : sort === "rank"
                ? "fresh"
                : sort;
      url.searchParams.set("sort", upstreamSort);
      if (kevOnly) url.searchParams.set("kevOnly", "true");
      if (exploitFilter === "vckev_only") url.searchParams.set("vckevOnly", "true");
      if (exploitFilter === "epss_spike") url.searchParams.set("epssSpike", "true");
      if (exploitFilter === "has_poc") url.searchParams.set("hasPoc", "true");
      if (exploitFilter === "has_public_exploit") url.searchParams.set("hasPublicExploit", "true");
      if (exploitFilter === "new_vckev_7d") url.searchParams.set("newVckev7d", "true");
      if (minCvss != null) url.searchParams.set("minCvss", String(minCvss));
      if (minEpss != null) url.searchParams.set("minEpss", String(minEpss));
      if (vendorFilter) url.searchParams.set("vendor", vendorFilter);
      if (productFilter) url.searchParams.set("product", productFilter);
      for (const cls of vulnClasses) url.searchParams.append("vulnClass", cls);
      if (qDebounced) url.searchParams.set("q", qDebounced);
      const res = await apiFetch(url.toString(), { cache: "no-store" });
      if (!res.ok) throw new Error(`Failed to fetch list (${res.status})`);
      const data = (await res.json()) as { items: CveListItem[] };
      return data.items;
    }
  });

  const visibleItems = useMemo(() => {
    const items = listQuery.data ?? [];
    let out = items;
    const searching = qDebounced.trim().length > 0;
    if (attentionOnly && !searching) {
      out = out.filter((it) => {
        const p = computeCvePriority(it);
        return p.level === "critical" || p.level === "high";
      });
    }
    if (sort === "priority") {
      out = [...out].sort((a, b) => computeCvePriority(b).score - computeCvePriority(a).score);
    }
    return out;
  }, [listQuery.data, attentionOnly, sort, qDebounced]);

  type VulnListEntry =
    | { kind: "cve"; item: CveListItem; priority: number }
    | { kind: "bdu"; item: BduListItem; priority: number };

  const vulnListEntries = useMemo((): VulnListEntry[] => {
    const searching = qDebounced.trim().length > 0;
    if (!searching) {
      return visibleItems.map((item) => ({
        kind: "cve" as const,
        item,
        priority: computeCvePriority(item).score
      }));
    }
    const entries: VulnListEntry[] = [
      ...(bduListQuery.data?.items ?? []).map((item) => ({
        kind: "bdu" as const,
        item,
        priority: computeBduPriority(item).score
      })),
      ...visibleItems.map((item) => ({
        kind: "cve" as const,
        item,
        priority: computeCvePriority(item).score
      }))
    ];
    return entries.sort((a, b) => b.priority - a.priority);
  }, [visibleItems, bduListQuery.data?.items, qDebounced]);

  /** Точный CVE в поиске — сразу открыть карточку, если запись есть в списке. */
  useEffect(() => {
    const needle = qDebounced.trim();
    if (!/^cve-\d{4}-\d+/i.test(needle)) return;
    const cveId = needle.toUpperCase();
    const hit = (listQuery.data ?? []).find((it) => it.cve_id.toUpperCase() === cveId);
    if (!hit) return;
    setSelectedBdu(null);
    setSelected(hit.cve_id);
  }, [qDebounced, listQuery.data]);

  const activePreview = useMemo(
    () => pinnedPreview ?? kbdPreview ?? hoveredPreview,
    [pinnedPreview, kbdPreview, hoveredPreview]
  );

  const activePreviewVulnClass = useMemo(() => {
    if (!activePreview || activePreview.kind !== "cve") return null;
    const hit = vulnListEntries.find((e) => e.kind === "cve" && e.item.cve_id === activePreview.id);
    return hit?.kind === "cve" ? (hit.item.vuln_class ?? null) : null;
  }, [activePreview, vulnListEntries]);

  const setHoveredDebounced = useCallback((next: VulnPreviewRef | null) => {
    if (pinnedPreview) return;
    if (hoverDebounceRef.current != null) {
      window.clearTimeout(hoverDebounceRef.current);
      hoverDebounceRef.current = null;
    }
    hoverDebounceRef.current = window.setTimeout(() => {
      setHoveredPreview(next);
      if (next) setKbdPreview(null);
    }, 120);
  }, [pinnedPreview]);

  const scrollPreviewIntoView = useCallback((ref: VulnPreviewRef) => {
    requestAnimationFrame(() => {
      document
        .querySelector(`[data-vuln-preview-key="${vulnPreviewKey(ref)}"]`)
        ?.scrollIntoView({ block: "nearest", behavior: "smooth" });
    });
  }, []);

  const openPreviewFullCard = useCallback((ref: VulnPreviewRef) => {
    if (ref.kind === "cve") {
      setSelectedBdu(null);
      setSelected(ref.id);
    } else {
      setSelected(null);
      setSelectedBdu(ref.id);
    }
  }, []);

  useEffect(() => {
    return () => {
      if (hoverDebounceRef.current != null) window.clearTimeout(hoverDebounceRef.current);
    };
  }, []);

  useEffect(() => {
    if (moduleKey !== "vulns") {
      setPinnedPreview(null);
      setKbdPreview(null);
      setHoveredPreview(null);
    }
  }, [moduleKey]);

  useEffect(() => {
    if (selected || selectedBdu) {
      setPinnedPreview(null);
      setKbdPreview(null);
    }
  }, [selected, selectedBdu]);

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
      triage: isDone(cveRefKey(it.cve_id)) ? "done" : ""
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

  const previewCveQuery = useQuery({
    queryKey: ["cve", "preview", activePreview?.kind === "cve" ? activePreview.id : null],
    enabled: moduleKey === "vulns" && !selected && !selectedBdu && activePreview?.kind === "cve",
    staleTime: 25_000,
    refetchOnWindowFocus: false,
    queryFn: () =>
      activePreview?.kind === "cve" ? fetchCveDetail(activePreview.id) : Promise.reject(new Error("no cve preview"))
  });

  const previewBduQuery = useQuery({
    queryKey: ["bdu", "preview", activePreview?.kind === "bdu" ? activePreview.id : null],
    enabled: moduleKey === "vulns" && !selected && !selectedBdu && activePreview?.kind === "bdu",
    staleTime: 25_000,
    refetchOnWindowFocus: false,
    queryFn: () =>
      activePreview?.kind === "bdu" ? fetchBduDetail(activePreview.id) : Promise.reject(new Error("no bdu preview"))
  });

  useEffect(() => {
    if (moduleKey !== "vulns" || selected || selectedBdu) return;

    const onKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const tag = target?.tagName ?? "";
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || target?.isContentEditable) return;

      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        if (!vulnListEntries.length) return;
        e.preventDefault();
        const curIdx = findVulnPreviewIndex(vulnListEntries, activePreview);
        const nextIdx =
          e.key === "ArrowDown"
            ? Math.min(vulnListEntries.length - 1, curIdx < 0 ? 0 : curIdx + 1)
            : Math.max(0, curIdx < 0 ? 0 : curIdx - 1);
        const next = vulnPreviewFromEntry(vulnListEntries[nextIdx]!);
        setKbdPreview(next);
        setHoveredPreview(null);
        scrollPreviewIntoView(next);
        return;
      }

      if (e.key === "Enter" && activePreview) {
        e.preventDefault();
        openPreviewFullCard(activePreview);
        return;
      }

      if (e.key === "Escape") {
        if (pinnedPreview) {
          e.preventDefault();
          setPinnedPreview(null);
        } else if (kbdPreview || hoveredPreview) {
          e.preventDefault();
          setKbdPreview(null);
          setHoveredPreview(null);
        }
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [
    moduleKey,
    selected,
    selectedBdu,
    vulnListEntries,
    activePreview,
    pinnedPreview,
    kbdPreview,
    hoveredPreview,
    scrollPreviewIntoView,
    openPreviewFullCard
  ]);

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

  const bduDetailsQuery = useQuery({
    queryKey: ["bdu", "detail", selectedBdu],
    enabled: selectedBdu != null && moduleKey === "vulns",
    staleTime: 8_000,
    refetchOnWindowFocus: false,
    queryFn: () => (selectedBdu ? fetchBduDetail(selectedBdu) : Promise.reject(new Error("no bdu"))),
    refetchInterval: (q) => {
      const d = q.state.data;
      if (!selectedBdu || !d?.found) return false;
      const manual = summaryQuery.data?.manualEnrichAllowed !== false;
      if (manual && bduEnrichPosted && bduEnrichTargetId === selectedBdu) {
        if (!needsOnDemandBduEnrich(d)) return false;
        const deadline = bduEnrichPollDeadlineRef.current;
        if (deadline != null && Date.now() > deadline) return false;
        return CVE_POLL_WHILE_ENRICH_MS;
      }
      return false;
    },
    refetchIntervalInBackground: false
  });

  useEffect(() => {
    autoEnrichForBduRef.current = null;
  }, [selectedBdu]);

  useEffect(() => {
    if (!bduEnrichTargetId || !bduEnrichPosted) return;
    const d = bduDetailsQuery.data;
    if (!d?.found) return;
    if (needsOnDemandBduEnrich(d)) return;
    bduEnrichPollDeadlineRef.current = null;
    setBduEnrichPosted(false);
    setBduEnrichTargetId(null);
    setBduEnrichStalled(false);
  }, [bduDetailsQuery.data, bduEnrichTargetId, bduEnrichPosted]);

  useEffect(() => {
    if (!bduEnrichPosted || bduEnrichTargetId == null) return;
    const tick = () => {
      const deadline = bduEnrichPollDeadlineRef.current;
      if (deadline != null && Date.now() > deadline) {
        bduEnrichPollDeadlineRef.current = null;
        setBduEnrichPosted(false);
        setBduEnrichTargetId(null);
        setBduEnrichStalled(true);
      }
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [bduEnrichPosted, bduEnrichTargetId]);

  const requestBduEnrich = useCallback(
    async (bduId: string, force = false) => {
      setBduEnrichTargetId(bduId);
      setBduEnrichPosted(true);
      setBduEnrichStalled(false);
      bduEnrichPollDeadlineRef.current = Date.now() + ENRICH_UI_WAIT_MS;
      try {
        const q = force ? "?force=1" : "";
        const res = await apiFetch(`/api/bdu/${encodeURIComponent(bduId)}/enrich${q}`, { method: "POST" });
        if (!res.ok) throw new Error("bdu enrich request failed");
        await queryClient.invalidateQueries({ queryKey: ["bdu", "detail", bduId] });
      } catch {
        bduEnrichPollDeadlineRef.current = null;
        setBduEnrichPosted(false);
        setBduEnrichTargetId(null);
        setBduEnrichStalled(true);
      }
    },
    [queryClient]
  );

  useEffect(() => {
    if (!selectedBdu || moduleKey !== "vulns" || !manualEnrichAllowed) return;
    if (bduDetailsQuery.isLoading) return;
    const d = bduDetailsQuery.data;
    if (!d) return;
    if (!shouldAutoEnrichBduOnOpen(d)) return;
    if (autoEnrichForBduRef.current === selectedBdu) return;
    autoEnrichForBduRef.current = selectedBdu;
    void requestBduEnrich(selectedBdu, false);
  }, [
    selectedBdu,
    moduleKey,
    manualEnrichAllowed,
    bduDetailsQuery.data,
    bduDetailsQuery.isLoading,
    requestBduEnrich
  ]);

  const refreshOverview = useCallback(async () => {
    await Promise.all([summaryQuery.refetch(), topPriorityQuery.refetch(), vendorsQuery.refetch()]);
  }, [summaryQuery, topPriorityQuery, vendorsQuery]);

  const overviewRefreshing =
    summaryQuery.isFetching || topPriorityQuery.isFetching || vendorsQuery.isFetching;

  const topPriorityItems = useMemo(() => {
    const items = topPriorityQuery.data ?? [];
    const boost = (it: CveListItem) => {
      // Perimeter exploitation heuristic: CVSS v3 AV:N + (PR:N, UI:N, AC:L) are strong proxies.
      let b = 0;
      const avN = it.cvss_av_network === true;
      const prN = it.cvss_pr_none === true;
      const uiN = it.cvss_ui_none === true;
      const acL = it.cvss_ac_low === true;
      const edge = it.perimeter_product === true;
      if (edge) b += 10;
      if (edge && avN) b += 6;
      if (avN) b += 12;
      if (avN && prN) b += 8;
      if (avN && uiN) b += 6;
      if (avN && acL) b += 3;
      if (avN && prN && uiN) b += 10; // "internet RCE style" shape

      if (it.exploit_known) b += 12; // KEV is the strongest "externally relevant" indicator.
      if (typeof it.epss === "number" && it.epss >= 0.6) b += 8;
      else if (typeof it.epss === "number" && it.epss >= 0.3) b += 4;
      if (typeof it.cvss_base === "number" && it.cvss_base >= 9.0) b += 5;
      if (typeof it.risk_score === "number" && it.risk_score >= 85) b += 4;
      return b;
    };
    return [...items]
      .map((it) => {
        const p = computeCvePriority(it);
        return { ...it, _prio: p.score + boost(it) };
      })
      .sort((a, b) => b._prio - a._prio)
      .slice(0, 20);
  }, [topPriorityQuery.data]);

  const refreshVulns = useCallback(async () => {
    const tasks: Promise<unknown>[] = [listQuery.refetch(), vendorsQuery.refetch()];
    if (selected) tasks.push(detailsQuery.refetch());
    if (selectedBdu) tasks.push(bduDetailsQuery.refetch());
    await Promise.all(tasks);
  }, [listQuery, vendorsQuery, selected, selectedBdu, detailsQuery, bduDetailsQuery]);

  const vulnsRefreshing =
    listQuery.isFetching ||
    vendorsQuery.isFetching ||
    (selected != null && detailsQuery.isFetching) ||
    (selectedBdu != null && bduDetailsQuery.isFetching);

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

  /** Auto-enrich on open: baseline/translate sync to mature RU; LLM stays manual-only. */
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

  const selectedDetails = detailsQuery.data?.found ? detailsQuery.data : null;
  const aiSummaryPending = Boolean(
    selectedDetails &&
      manualEnrichAllowed &&
      enrichPosted &&
      enrichTargetCveId === selected &&
      needsOnDemandEnrich(selectedDetails)
  );

  const selectedBduDetails = bduDetailsQuery.data?.found ? bduDetailsQuery.data : null;
  const bduAiSummaryPending = Boolean(
    selectedBduDetails &&
      manualEnrichAllowed &&
      bduEnrichPosted &&
      bduEnrichTargetId === selectedBdu &&
      needsOnDemandBduEnrich(selectedBduDetails)
  );

  const bduGraph = useMemo(() => {
    if (!selectedBdu) return null;
    const ai = selectedBduDetails?.ai as { output_json?: unknown } | null | undefined;
    const linkedCveRaw = (selectedBduDetails as { linkedCveRaw?: unknown } | null)?.linkedCveRaw;
    const parsed = parseBduAiOutputJson(ai?.output_json ?? null, {
      bduId: selectedBdu,
      bdu: selectedBduDetails?.bdu,
      linkedCveRaw
    });
    const out = parsed?.graph;
    return isUsableAttackGraph(out) ? out : null;
  }, [selectedBduDetails, selectedBdu]);

  const bduAttackFlowSteps = useMemo(() => {
    if (!selectedBdu) return defaultAttackFlowSteps();
    const ai = selectedBduDetails?.ai as { output_json?: unknown } | null | undefined;
    const linkedCveRaw = (selectedBduDetails as { linkedCveRaw?: unknown } | null)?.linkedCveRaw;
    const parsed = parseBduAiOutputJson(ai?.output_json ?? null, {
      bduId: selectedBdu,
      bdu: selectedBduDetails?.bdu,
      linkedCveRaw
    });
    const af = parsed?.attackFlow;
    if (Array.isArray(af) && af.length > 0) return af.map(String).filter(Boolean);
    return defaultAttackFlowSteps(linkedCveRaw);
  }, [selectedBduDetails, selectedBdu]);

  const cveGraph = useMemo(() => {
    if (!selected || !selectedDetails) return null;
    const ai = selectedDetails.ai as { output_json?: unknown } | null | undefined;
    const cve = selectedDetails.cve as { raw?: unknown } | null | undefined;
    const nvdRaw =
      cve?.raw != null && typeof cve.raw === "object" && !Array.isArray(cve.raw) ? cve.raw : undefined;
    const parsed = parseAiOutputJson(ai?.output_json ?? null, { cveId: selected, nvdRaw });
    const out = parsed?.graph;
    return isUsableAttackGraph(out) ? out : null;
  }, [selectedDetails, selected]);

  const cveAttackFlowSteps = useMemo(() => {
    if (!selected || !selectedDetails) return [];
    const ai = selectedDetails.ai as { output_json?: unknown } | null | undefined;
    const cve = selectedDetails.cve as { raw?: unknown } | null | undefined;
    const nvdRaw =
      cve?.raw != null && typeof cve.raw === "object" && !Array.isArray(cve.raw) ? cve.raw : undefined;
    const parsed = parseAiOutputJson(ai?.output_json ?? null, { cveId: selected, nvdRaw });
    const af = parsed?.attackFlow;
    if (Array.isArray(af) && af.length > 0) return af.map(String).filter(Boolean);
    return defaultAttackFlowSteps(nvdRaw);
  }, [selectedDetails, selected]);

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

  const openDashboardBduModal = useCallback((bduId: string) => {
    const id = bduId.replace(/^BDU:/i, "").trim();
    if (!id) return;
    setDashboardBduModals((prev) => {
      const dup = prev.find((m) => m.bduId === id);
      if (dup) {
        const maxZ = prev.reduce((a, m) => Math.max(a, m.z), 0);
        return prev.map((m) => (m.instanceId === dup.instanceId ? { ...m, z: maxZ + 1 } : m));
      }
      if (prev.length >= 4) return prev;
      const maxZ = prev.length === 0 ? 3099 : Math.max(...prev.map((m) => m.z));
      const i = prev.length;
      const vw = typeof window !== "undefined" ? window.innerWidth : 1200;
      const pad = 24;
      const x = Math.min(48 + (i % 5) * 40, Math.max(16, vw - DASHBOARD_BDU_MODAL_BASE_WIDTH_PX - pad));
      const y = 56 + (i % 5) * 36;
      return [
        ...prev,
        {
          instanceId: crypto.randomUUID(),
          bduId: id,
          x,
          y,
          z: maxZ + 1
        }
      ];
    });
  }, []);

  const closeDashboardBduModal = useCallback((instanceId: string) => {
    setDashboardBduModals((prev) => prev.filter((m) => m.instanceId !== instanceId));
  }, []);

  const moveDashboardBduModal = useCallback((instanceId: string, x: number, y: number) => {
    setDashboardBduModals((prev) => prev.map((m) => (m.instanceId === instanceId ? { ...m, x, y } : m)));
  }, []);

  const focusDashboardBduModal = useCallback((instanceId: string) => {
    setDashboardBduModals((prev) => {
      const maxZ = prev.reduce((a, m) => Math.max(a, m.z), 0);
      return prev.map((m) => (m.instanceId === instanceId ? { ...m, z: maxZ + 1 } : m));
    });
  }, []);

  const switchModule = useCallback((next: ModuleKey) => {
    if (moduleKey === "dashboard" && next !== "dashboard") {
      setDashboardModals([]);
    }
    setModuleKey(next);
    if (next !== "vulns" && next !== "dashboard") {
      setSelected(null);
      setSelectedBdu(null);
    }
    if (next !== "tasks") setTasksSelectedId(null);
  }, [moduleKey]);

  const openExploitFilter = useCallback((filter: ExploitRadarFilter) => {
    switchModule("vulns");
    setView("exploit");
    setSort("exploit");
    setExploitFilter(filter);
    setKevOnly(false);
    setQ("");
    setSelected(null);
    setSelectedBdu(null);
  }, [switchModule]);

  const captureSavedViewState = (): SavedView["state"] => ({
    view,
    sort,
    limit,
    kevOnly,
    minCvss,
    minEpss,
    vendorFilter,
    productFilter,
    vulnClasses,
    exploitFilter,
    q
  });

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
            onClick={() => switchModule("voc")}
            className={cn(
              "flex h-11 w-11 items-center justify-center rounded-xl border text-fg/85",
              "hover:bg-slate-100 dark:hover:bg-black/25",
              moduleKey === "voc"
                ? "border-accent/30 bg-accent/10"
                : "border-slate-200 bg-white shadow-sm dark:border-border dark:bg-black/10 dark:shadow-none"
            )}
            title="VOC — очередь смены"
          >
            <Inbox className="h-5 w-5" />
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
            onClick={() => switchModule("threat")}
            className={cn(
              "flex h-11 w-11 items-center justify-center rounded-xl border text-fg/85",
              "hover:bg-slate-100 dark:hover:bg-black/25",
              moduleKey === "threat"
                ? "border-accent/30 bg-accent/10"
                : "border-slate-200 bg-white shadow-sm dark:border-border dark:bg-black/10 dark:shadow-none"
            )}
            title="Threat feed"
          >
            <Target className="h-5 w-5" />
          </button>
            <button
              onClick={() => switchModule("tasks")}
              className={cn(
                "rounded-2xl border p-3 transition",
                moduleKey === "tasks"
                  ? "border-accent/40 bg-accent/10"
                  : "border-border bg-white/60 hover:bg-white dark:bg-black/20 dark:hover:bg-black/30"
              )}
              title="Задачник"
            >
              <ClipboardList className="h-5 w-5" />
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
          <div className="mt-auto flex flex-col items-center gap-2">
            <button
              onClick={() => switchModule("systemHealth")}
              className={cn(
                "flex h-11 w-11 items-center justify-center rounded-xl border text-fg/85",
                "hover:bg-slate-100 dark:hover:bg-black/25",
                moduleKey === "systemHealth"
                  ? "border-accent/30 bg-accent/10"
                  : "border-slate-200 bg-white shadow-sm dark:border-border dark:bg-black/10 dark:shadow-none"
              )}
              title="Здоровье системы"
            >
              <HeartPulse className="h-5 w-5" />
            </button>
            <button
              onClick={() => switchModule("settings")}
              className={cn(
                "flex h-11 w-11 items-center justify-center rounded-xl border text-fg/85",
                "hover:bg-slate-100 dark:hover:bg-black/25",
                moduleKey === "settings"
                  ? "border-accent/30 bg-accent/10"
                  : "border-slate-200 bg-white shadow-sm dark:border-border dark:bg-black/10 dark:shadow-none"
              )}
              title="Настройки"
            >
              <Settings className="h-5 w-5" />
            </button>
          </div>
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
                onOpenCve={openDashboardModal}
                topPriorityCves={topPriorityItems}
                topPriorityLoading={topPriorityQuery.isLoading}
                onTopPriorityCveClick={openDashboardModal}
                dashboardHighlightCveIds={dashboardHighlightSet}
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
                onOpenSystemHealth={() => switchModule("systemHealth")}
                onOpenVoc={() => switchModule("voc")}
                onOpenVulns={() => switchModule("vulns")}
                onOpenThreat={() => switchModule("threat")}
                onRefresh={() => void refreshOverview()}
                refreshing={overviewRefreshing}
                onExploitFilter={openExploitFilter}
                exploitFilter={exploitFilter}
              />
            </div>
          ) : moduleKey === "voc" ? (
            <div className="glass rounded-2xl p-5 sm:p-6">
              <VocHomePanel
                variant="page"
                onOpenCve={openDashboardModal}
                onOpenBdu={openDashboardBduModal}
                onOpenTgLink={(link) => {
                  if (link) window.open(link, "_blank", "noopener,noreferrer");
                }}
              />
            </div>
          ) : moduleKey === "vulns" ? (
            <div className="mt-0 grid grid-cols-12 items-start gap-6">
              {selectedBdu ? (
                <section className="col-span-12 space-y-4">
                  <div className="glass rounded-2xl p-3 sm:p-4">
                    <BduDetailPanel
                      bduId={selectedBdu}
                      data={selectedBduDetails}
                      loading={bduDetailsQuery.isLoading}
                      aiPending={bduAiSummaryPending}
                      aiStalled={bduEnrichStalled}
                      manualEnrichAllowed={manualEnrichAllowed}
                      onRequestEnrich={(opts) => void requestBduEnrich(selectedBdu, Boolean(opts?.force))}
                      onClose={() => setSelectedBdu(null)}
                      onOpenCve={(cveId) => {
                        setSelectedBdu(null);
                        setSelected(cveId);
                      }}
                      onOpenTask={(taskId: string) => {
                        setTasksSelectedId(taskId);
                        setModuleKey("tasks");
                      }}
                    />
                  </div>
                  <AttackGraphPanel
                    graph={bduGraph}
                    attackFlow={bduAttackFlowSteps}
                    entityId={selectedBdu}
                  />
                </section>
              ) : null}
              {selected ? (
                <section className="col-span-12 space-y-4">
                  <div className="glass rounded-2xl p-3 sm:p-4">
                    <CveDetailPanel
                      data={selectedDetails}
                      loading={detailsQuery.isLoading}
                      aiPending={aiSummaryPending}
                      aiStalled={enrichStalled}
                      manualEnrichAllowed={manualEnrichAllowed}
                      onRequestEnrich={selected ? (opts) => void requestEnrich(selected, Boolean(opts?.force)) : undefined}
                      onClose={() => setSelected(null)}
                      onOpenTask={(taskId: string) => {
                        setTasksSelectedId(taskId);
                        setModuleKey("tasks");
                      }}
                    />
                  </div>
                  <AttackGraphPanel
                    graph={cveGraph}
                    attackFlow={cveAttackFlowSteps}
                    entityId={selected}
                  />
                </section>
              ) : null}

              <section
                className={cn(
                  "col-span-12 lg:col-span-4",
                  (selected || selectedBdu) && "hidden",
                  "lg:sticky lg:top-4 lg:max-h-[calc(100vh-5.5rem)] lg:self-start"
                )}
              >
                <div className="glass flex max-h-[calc(100vh-5.5rem)] flex-col overflow-hidden rounded-2xl p-4">
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
                      setVulnClasses([]);
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
                      onClick={() => setAttentionOnly((v) => !v)}
                      className={cn(
                        "rounded-lg border px-2 py-1 text-xs hover:bg-slate-200/80 dark:hover:bg-black/30",
                        attentionOnly
                          ? "border-warn/30 bg-warn/15 text-warn"
                          : "border-slate-200 bg-slate-50 text-fg/90 dark:border-border dark:bg-black/20"
                      )}
                      title="Показать только высокий/критический приоритет (фокус для triage)"
                    >
                      Внимание
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
                          onChange={(e) =>
                            setSort(
                              e.target.value as "rank" | "fresh" | "risk" | "epss" | "cvss" | "exploit" | "priority"
                            )
                          }
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
                        {exploitFilter ? (
                          <button
                            type="button"
                            onClick={() => setExploitFilter(null)}
                            className="rounded-full border border-accent/35 bg-accent/10 px-2 py-0.5 text-[11px] text-accent"
                            title={EXPLOIT_RADAR_FILTER_LABELS[exploitFilter].hint}
                          >
                            {EXPLOIT_RADAR_FILTER_LABELS[exploitFilter].title} ×
                          </button>
                        ) : null}
                      </div>
                    </div>

                    <Tabs.Root value={view} onValueChange={(v: string) => setView(v as typeof view)}>
                      <Tabs.List className="mt-2 grid grid-cols-6 gap-2">
                        {[
                          ["critical_v2", "Критичные"],
                          ["latest", "Свежие"],
                          ["last24h", "24 ч"],
                          ["kev", "KEV"],
                          ["exploit", "Exploit"],
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

                      <VulnClassFilter value={vulnClasses} onChange={setVulnClasses} className="w-full" />

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

                  <div className="mt-1 min-h-0 flex-1 overflow-y-auto overscroll-contain pr-0.5">
                    <div className="space-y-3 pb-1">
                    {vulnListEntries.map((entry) => {
                      const previewRef = vulnPreviewFromEntry(entry);
                      const previewActive =
                        activePreview != null &&
                        activePreview.kind === previewRef.kind &&
                        activePreview.id === previewRef.id;
                      return entry.kind === "bdu" ? (
                        <div key={`bdu-${entry.item.bduId}`} data-vuln-preview-key={vulnPreviewKey(previewRef)}>
                          <BduCard
                            item={entry.item}
                            selected={selectedBdu === entry.item.bduId}
                            previewActive={previewActive}
                            onSelect={() => {
                              setSelected(null);
                              setSelectedBdu(entry.item.bduId);
                            }}
                            onHover={() => setHoveredDebounced(previewRef)}
                            onUnhover={() => setHoveredDebounced(null)}
                          />
                        </div>
                      ) : (
                        <div key={entry.item.cve_id} data-vuln-preview-key={vulnPreviewKey(previewRef)}>
                          <CveCard
                            item={entry.item}
                            selected={selected === entry.item.cve_id}
                            previewActive={previewActive}
                            onSelect={() => {
                              setSelectedBdu(null);
                              setSelected(entry.item.cve_id);
                            }}
                            onHover={() => setHoveredDebounced(previewRef)}
                            onUnhover={() => setHoveredDebounced(null)}
                            showCheckbox={bulkMode}
                            checked={Boolean(selectedIds[entry.item.cve_id])}
                            onToggleChecked={(next) =>
                              setSelectedIds((m) => {
                                const n = { ...m };
                                if (next) n[entry.item.cve_id] = true;
                                else delete n[entry.item.cve_id];
                                return n;
                              })
                            }
                          />
                        </div>
                      );
                    })}
                    {vulnListEntries.length === 0 ? (
                      <div className="text-sm text-muted">
                        {qDebounced.trim() ? "Ничего не найдено." : "Для этого вида пока нет записей."}
                      </div>
                    ) : null}
                    </div>
                  </div>
                </div>
              </section>

              <section
                className={cn(
                  "col-span-12 lg:col-span-8",
                  (selected || selectedBdu) && "hidden",
                  "lg:sticky lg:top-4 lg:max-h-[calc(100vh-5.5rem)] lg:self-start"
                )}
              >
                <div className="glass flex max-h-[calc(100vh-5.5rem)] flex-col overflow-hidden rounded-2xl p-5 sm:p-6">
                  <div className="shrink-0 flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="text-sm font-medium">Превью</div>
                      <div className="mt-2 text-sm text-muted">
                        Наведи курсор или жми ↑↓ — описание и рекомендации справа. Enter — открыть карточку, Esc — сброс.
                      </div>
                    </div>
                    <div className="flex shrink-0 flex-wrap items-center gap-2">
                      {activePreview ? (
                        <div className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-[11px] text-fg/80 dark:border-border dark:bg-black/20">
                          <span>
                            {activePreview.kind === "cve" ? "CVE" : "BDU"}:{" "}
                            <span className="font-mono">{activePreview.id}</span>
                          </span>
                          {activePreview.kind === "cve" ? (
                            <VulnClassBadge vulnClass={activePreviewVulnClass} />
                          ) : null}
                        </div>
                      ) : null}
                      {activePreview ? (
                        <button
                          type="button"
                          onClick={() => openPreviewFullCard(activePreview)}
                          className="rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-[11px] text-fg/90 hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                        >
                          Открыть
                        </button>
                      ) : null}
                      <button
                        type="button"
                        disabled={!activePreview}
                        onClick={() => {
                          if (pinnedPreview) {
                            setPinnedPreview(null);
                          } else if (activePreview) {
                            setPinnedPreview(activePreview);
                            setKbdPreview(null);
                            setHoveredPreview(null);
                          }
                        }}
                        className={cn(
                          "inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-[11px] transition",
                          pinnedPreview
                            ? "border-accent/40 bg-accent/10 text-fg/90"
                            : "border-slate-200 bg-white text-fg/90 hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30",
                          !activePreview && "cursor-not-allowed opacity-50"
                        )}
                        title={pinnedPreview ? "Открепить превью (Esc)" : "Закрепить текущее превью"}
                      >
                        {pinnedPreview ? <PinOff className="h-3.5 w-3.5" /> : <Pin className="h-3.5 w-3.5" />}
                        {pinnedPreview ? "Открепить" : "Закрепить"}
                      </button>
                    </div>
                  </div>

                  <div className="mt-4 min-h-0 flex-1 overflow-y-auto overscroll-contain pr-0.5">
                    {activePreview?.kind === "cve" ? (
                      <AiSummaryPanel
                        data={previewCveQuery.data ?? null}
                        loading={previewCveQuery.isLoading}
                        aiPending={false}
                        aiStalled={previewCveQuery.isError}
                        manualEnrichAllowed={false}
                      />
                    ) : activePreview?.kind === "bdu" ? (
                      <AiSummaryPanel
                        data={previewBduQuery.data ?? null}
                        loading={previewBduQuery.isLoading}
                        aiPending={false}
                        aiStalled={previewBduQuery.isError}
                        manualEnrichAllowed={false}
                      />
                    ) : (
                      <div className="grid grid-cols-2 gap-3 text-[11px]">
                        <div className="rounded-xl border border-slate-200/90 bg-slate-50 p-3 dark:border-white/[0.06] dark:bg-black/20">
                          <div className="text-muted">Фокус без кликов</div>
                          <div className="mt-1 text-fg/85">Просматривай много уязвимостей подряд — карточки не прыгают.</div>
                        </div>
                        <div className="rounded-xl border border-slate-200/90 bg-slate-50 p-3 dark:border-white/[0.06] dark:bg-black/20">
                          <div className="text-muted">Клавиатура</div>
                          <div className="mt-1 text-fg/85">↑↓ — листать список, Enter — открыть, Esc — сброс превью.</div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </section>
            </div>
          ) : moduleKey === "threat" ? (
            <div className="glass rounded-2xl p-5 sm:p-6">
              <ThreatFeedPanel onOpenCve={openDashboardModal} onFilter={openExploitFilter} />
            </div>
          ) : moduleKey === "tasks" ? (
            <div className="glass rounded-2xl p-3 sm:p-4">
              <VulnTaskPanel
                vendorsHint={
                  vendorsQuery.data
                    ? { vendors: vendorsQuery.data.vendors, products: vendorsQuery.data.products }
                    : null
                }
                onOpenCve={openDashboardModal}
                selectedTaskId={tasksSelectedId}
                onSelectTaskId={setTasksSelectedId}
              />
            </div>
          ) : moduleKey === "fstec" ? (
            <FstecModulePanel
              onOpenCve={openDashboardModal}
              onOpenBdu={openDashboardBduModal}
            />
          ) : moduleKey === "patches" ? (
            <div className="glass rounded-2xl p-5 sm:p-6">
              <PatchManagementPanel onOpenCve={openDashboardModal} />
            </div>
          ) : moduleKey === "systemHealth" ? (
            <div className="glass rounded-2xl p-5 sm:p-6">
              <SystemHealthPanel onOpenSettings={() => switchModule("settings")} />
            </div>
          ) : (
            <SettingsPanel />
          )}
        </main>
      </div>

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
                <div className="mb-4 flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    className="rounded-lg border border-accent/30 bg-accent/10 px-3 py-1.5 text-xs text-fg/90 hover:bg-accent/15"
                    onClick={() => {
                      const name = window.prompt("Имя сохранённого вида");
                      if (!name?.trim()) return;
                      setSavedViews((xs) => [
                        ...xs,
                        { id: crypto.randomUUID(), name: name.trim(), state: captureSavedViewState() }
                      ]);
                    }}
                  >
                    Сохранить текущий
                  </button>
                </div>
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
                            setVulnClasses(
                              Array.isArray(v.state.vulnClasses)
                                ? v.state.vulnClasses.filter(isVulnClassId)
                                : v.state.vulnClass && isVulnClassId(v.state.vulnClass)
                                  ? [v.state.vulnClass]
                                  : []
                            );
                            setExploitFilter(v.state.exploitFilter ?? null);
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

      <DraggableBduModals
        modals={dashboardBduModals}
        manualEnrichAllowed={manualEnrichAllowed}
        onClose={closeDashboardBduModal}
        onMove={moveDashboardBduModal}
        onFocus={focusDashboardBduModal}
        onOpenCve={openDashboardModal}
        onOpenTask={(taskId) => {
          setTasksSelectedId(taskId);
          setModuleKey("tasks");
        }}
      />
    </div>
  );
}


"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";
import type { VcQuery, VcRange } from "./types";

export type CatalogSummary = {
  totalCves: number;
  cvesPublishedLast24hCount?: number;
  kevCount: number;
  /** Новые записи CISA KEV за 7 календарных дней UTC. */
  newCisaKev7dCount?: number;
  highEpssCount?: number;
  epssCount: number;
  cvssCount: number;
  scoredCount: number;
  totalBduCount?: number;
  cveBduLinkCount?: number;
  severity?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    unscored: number;
  };
  publishedByDay?: Array<{ day: string; count: number }>;
};

export type LiveCve = {
  cve_id: string;
  published_at: string | null;
  modified_at: string | null;
  risk_score: number | null;
  epss: number | null;
  epss_delta_7d?: number | null;
  epss_spike?: boolean;
  cvss_base: number | null;
  vp_vendor: string | null;
  vp_product: string | null;
  short_description: string | null;
  short_ru: string | null;
  task_open_count: number | null;
  exploit_known: boolean;
  has_poc?: boolean;
  has_public_exploit?: boolean;
  vckev_only?: boolean;
  affected_version?: string | null;
  bdu_ids?: string[] | null;
};

export type VendorWindow = {
  windowHours: number;
  sampledCves: number;
  vendors: Array<{ vendor: string; count: number }>;
  products: Array<{ vendor: string; product: string; count: number }>;
};

export type ExploitRadarHighlight = {
  cve_id: string;
  epss: number | null;
  cvss_base: number | null;
  vckev_only: boolean;
  epss_spike: boolean;
  has_poc: boolean;
  has_public_exploit: boolean;
  radar_reason: string;
};

export type ExploitRadar = {
  vckevOnly: number;
  epssSpikes: number;
  newVckev7d: number;
  withPoc: number;
  withPublicExploit: number;
  intelRows: number;
  lastVckevIngestAt?: string | null;
  highlights?: ExploitRadarHighlight[];
};

export type AnalyticsDay = {
  day: string;
  published: number;
  critical: number;
  network: number;
  adjacent: number;
  local: number;
  physical: number;
  kev: number;
};

export type AnalyticsPulse = {
  cveId: string;
  publishedAt: string | null;
  cvss: number | null;
  risk: number | null;
  vendor: string | null;
  product: string | null;
  attackVector: string | null;
  kev: boolean;
};

export type AnalyticsSeries = {
  generatedAt: string;
  days: AnalyticsDay[];
  /** Сколько CVE с published_at за 14 дней (pulse — выборка из них). */
  pulseTotal?: number;
  pulse: AnalyticsPulse[];
};

export type LiveTask = {
  id: string;
  title: string;
  status: string;
  priority_local: string | null;
  owner: string | null;
  due_date: string | null;
  vendor_display: string | null;
  product_display: string | null;
  score_final: number | null;
  notes_md?: string | null;
  evidence?: string | null;
  stats?: { cveCount?: number; kevCount?: number; perimeterHighCount?: number } | null;
  created_at: string | null;
  updated_at: string | null;
};

export type TaskCveLink = {
  cve_id: string;
  added_at: string | null;
  note: string | null;
  risk_score: number | null;
  epss: number | null;
  cvss_base: number | null;
  exploit_known: boolean;
};

export type TaskEvent = {
  id: string;
  ts: string | null;
  actor: string | null;
  action: string;
  before: unknown;
  after: unknown;
};

export type TaskDetail = {
  task: LiveTask & { closed_at?: string | null; review_date?: string | null };
  cves: TaskCveLink[];
  events: TaskEvent[];
};

async function getJson<T>(url: string): Promise<T> {
  const res = await apiFetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`Запрос не выполнен (${res.status})`);
  return (await res.json()) as T;
}

export function formatInt(value: number | null | undefined) {
  if (value == null || !Number.isFinite(value)) return "—";
  return new Intl.NumberFormat("ru-RU").format(value);
}

export function formatDate(value: string | null | undefined) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("ru-RU", { day: "2-digit", month: "2-digit", year: "numeric" }).format(date);
}

export function cvssBand(cvss: number | null | undefined) {
  if (cvss == null || !Number.isFinite(cvss)) return null;
  if (cvss >= 9) return { key: "critical", label: "Критический", color: "var(--vc-critical)" };
  if (cvss >= 7) return { key: "high", label: "Высокий", color: "var(--vc-high)" };
  if (cvss >= 4) return { key: "medium", label: "Средний", color: "var(--vc-medium)" };
  return { key: "low", label: "Низкий", color: "var(--vc-low)" };
}

export function windowHoursFor(range: VcRange) {
  if (range === "7d") return 24 * 7;
  return 24 * 30;
}

export function slicePublished(days: Array<{ day: string; count: number }>, range: VcRange) {
  if (range !== "7d") return days;
  const cutoff = new Date();
  cutoff.setUTCDate(cutoff.getUTCDate() - 6);
  const key = cutoff.toISOString().slice(0, 10);
  return days.filter((day) => day.day >= key);
}

export type CveListOpts = { limit?: number; offset?: number; includeTotal?: boolean };

export function taskPresence(status: VcQuery["status"]): "1" | "0" | null {
  if (status === "open" || status === "in_progress") return "1";
  if (status === "resolved" || status === "accepted_risk") return "0";
  return null;
}

type CveListQuery = Pick<
  VcQuery,
  "q" | "severity" | "tab" | "vendor" | "product" | "status" | "kevAddedDays" | "publishedDays" | "exploitSignal"
>;

/** Итог из сводки каталога, когда фильтр совпадает с уже посчитанным срезом. */
export function knownCatalogTotal(query: CveListQuery, summary: CatalogSummary | undefined): number | null {
  if (!summary) return null;
  if (query.q.trim() || query.vendor !== "all" || query.product !== "all" || taskPresence(query.status)) return null;
  if (query.exploitSignal && query.exploitSignal !== "all") return null;
  if (query.kevAddedDays != null || query.publishedDays != null) {
    if (query.tab === "kev" && query.kevAddedDays === 7 && query.publishedDays == null && query.severity === "all") {
      return summary.newCisaKev7dCount ?? null;
    }
    return null;
  }
  const severityOn = query.severity !== "all";
  const tabOn = query.tab === "kev" || query.tab === "epss";
  if (severityOn && tabOn) return null;
  if (query.tab === "kev") return summary.kevCount;
  if (query.tab === "epss") return summary.highEpssCount ?? null;
  if (query.severity === "critical") return summary.severity?.critical ?? null;
  if (query.severity === "high") return summary.severity?.high ?? null;
  if (query.severity === "medium") return summary.severity?.medium ?? null;
  if (query.severity === "low") return summary.severity?.low ?? null;
  if (query.tab === "all" && query.severity === "all") return summary.totalCves;
  return null;
}

export function cveListUrl(query: CveListQuery, opts: CveListOpts = {}) {
  const params = new URLSearchParams();
  params.set("limit", String(opts.limit ?? 25));
  params.set("sort", "risk");
  if (opts.offset) params.set("offset", String(opts.offset));
  if (opts.includeTotal) params.set("includeTotal", "1");
  const q = query.q.trim();
  if (q) params.set("q", q);
  if (query.vendor !== "all") params.set("vendor", query.vendor);
  if (query.product !== "all") params.set("product", query.product);
  const task = taskPresence(query.status);
  if (task) params.set("hasTask", task);
  if (query.tab === "kev" || query.kevAddedDays != null) params.set("kevOnly", "1");
  if (query.tab === "epss") params.set("minEpss", "0.7");
  if (query.kevAddedDays != null && query.kevAddedDays > 0) params.set("kevAddedDays", String(query.kevAddedDays));
  if (query.publishedDays != null && query.publishedDays > 0) params.set("publishedDays", String(query.publishedDays));
  if (query.exploitSignal === "epss_spike") params.set("epssSpike", "1");
  else if (query.exploitSignal === "has_poc") params.set("hasPoc", "1");
  else if (query.exploitSignal === "has_public_exploit") params.set("hasPublicExploit", "1");
  else if (query.exploitSignal === "vckev_only") params.set("vckevOnly", "1");
  else if (query.exploitSignal === "new_vckev_7d") params.set("newVckev7d", "1");
  if (query.exploitSignal && query.exploitSignal !== "all") params.set("sort", "exploit");
  if (query.severity === "critical") {
    params.set("minCvss", "9");
  } else if (query.severity === "high") {
    params.set("minCvss", "7");
    params.set("maxCvss", "9");
  } else if (query.severity === "medium") {
    params.set("minCvss", "4");
    params.set("maxCvss", "7");
  } else if (query.severity === "low") {
    params.set("minCvss", "0");
    params.set("maxCvss", "4");
  }
  return `/api/cves?${params.toString()}`;
}

export function useCatalogSummary() {
  return useQuery({
    queryKey: ["vc", "summary"],
    queryFn: () => getJson<CatalogSummary>("/api/stats/summary"),
    staleTime: 30_000
  });
}

export function useVendorWindow(range: VcRange) {
  const hours = windowHoursFor(range);
  return useQuery({
    queryKey: ["vc", "vendors", hours],
    queryFn: () => getJson<VendorWindow>(`/api/stats/vendors?windowHours=${hours}&limit=12`),
    staleTime: 30_000
  });
}

export function useExploitRadar() {
  return useQuery({
    queryKey: ["vc", "exploit-radar"],
    queryFn: () => getJson<ExploitRadar>("/api/stats/exploit-radar"),
    staleTime: 30_000
  });
}

export function useAnalyticsSeries() {
  return useQuery({
    queryKey: ["vc", "analytics"],
    queryFn: () => getJson<AnalyticsSeries>("/api/stats/analytics"),
    staleTime: 30_000,
    refetchInterval: 60_000
  });
}

function uniqueByCve(items: LiveCve[] | undefined) {
  const seen = new Set<string>();
  return (items ?? []).filter((row) => {
    if (seen.has(row.cve_id)) return false;
    seen.add(row.cve_id);
    return true;
  });
}

export function useCveList(query: CveListQuery, opts: CveListOpts = {}) {
  const url = cveListUrl(query, opts);
  return useQuery({
    queryKey: ["vc", "cves", url],
    queryFn: async () => {
      const data = await getJson<{ items: LiveCve[]; total: number | null }>(url);
      return { ...data, items: uniqueByCve(data.items) };
    },
    placeholderData: keepPreviousData,
    staleTime: 15_000
  });
}

export function useVulnTasks(q?: string) {
  const params = new URLSearchParams({ limit: "200", sort: "score" });
  const needle = q?.trim();
  if (needle) params.set("q", needle);
  const url = `/api/vuln-tasks?${params.toString()}`;
  return useQuery({
    queryKey: ["vc", "tasks", url],
    queryFn: () => getJson<{ items: LiveTask[] }>(url),
    staleTime: 15_000
  });
}

export function useTaskDetail(taskId: string | null) {
  return useQuery({
    queryKey: ["vc", "task", taskId],
    enabled: Boolean(taskId),
    queryFn: () => getJson<TaskDetail>(`/api/vuln-tasks/${encodeURIComponent(taskId!)}`),
    staleTime: 10_000
  });
}

export function useCveDetail(cveId: string | null) {
  return useQuery({
    queryKey: ["vc", "cve", cveId],
    enabled: Boolean(cveId),
    queryFn: () => getJson<CveDetail>(`/api/cves/${encodeURIComponent(cveId!)}`),
    staleTime: 15_000
  });
}

export function useTasksForCve(cveId: string | null) {
  return useQuery({
    queryKey: ["vc", "tasks-for", cveId],
    enabled: Boolean(cveId),
    queryFn: () => getJson<{ items: LiveTask[] }>(`/api/vuln-tasks/by-cve/${encodeURIComponent(cveId!)}`),
    staleTime: 15_000
  });
}

export type CveDetail = {
  found: boolean;
  cve?: {
    cve_id: string;
    source: string | null;
    published_at: string | null;
    modified_at: string | null;
    risk_score: number | null;
    epss: number | null;
    cvss_base: number | null;
    exploit_known: boolean;
    has_poc: boolean;
    has_public_exploit: boolean;
    bdu_ids: string[] | null;
    raw?: unknown;
  };
  ai?: { output_text: string | null; output_json: Record<string, unknown> | null };
  vendorProducts?: Array<{ vendor: string; product: string }>;
  vendorAdvisories?: Array<{ id: string; title: string; link: string; vendorSlug: string }>;
  links?: { nvd: string; kev: string; epss: string };
  exploitIntel?: {
    signals: Array<{ signal_type: string; source: string; url: string | null; title: string | null; last_seen_at: string | null }>;
  };
  kev?: {
    dateAdded: string | null;
    dueDate: string | null;
    requiredAction: string | null;
    ransomwareUse: string | null;
    name: string | null;
  } | null;
  bdu?: Array<{
    id: string;
    name: string | null;
    solution: string | null;
    exploitStatus: string | null;
    fixStatus: string | null;
    hasExploit: boolean;
    hasFix: boolean;
  }>;
  contextFacts?: Array<{
    source: string;
    factType: string;
    title: string | null;
    detail: string | null;
    url: string | null;
    updatedAt: string | null;
  }>;
};

export function taskStatusLabel(status: string) {
  const labels: Record<string, string> = {
    new: "Новая",
    in_progress: "В работе",
    closed: "Закрыта",
    needs_info: "Нужны данные",
    fixing: "Устраняется",
    mitigated: "Смягчена",
    risk_accepted: "Риск принят",
    not_applicable: "Неприменима"
  };
  return labels[status] ?? status;
}

export function isOverdue(task: Pick<LiveTask, "due_date" | "status">) {
  if (!task.due_date || task.status === "closed") return false;
  const due = new Date(task.due_date);
  if (Number.isNaN(due.getTime())) return false;
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  return due.getTime() < today.getTime();
}

export type ProductRow = {
  vendorKey: string;
  productKey: string;
  vendor: string;
  product: string;
  cveCount: number;
  maxRisk: number | null;
  maxEpss: number | null;
  kevCount: number;
  exploitCount: number;
  pocCount: number;
};

export type ProductCatalog = {
  catalog: {
    products: number;
    withKev: number;
    withExploit: number;
    risk90: number;
    risk70: number;
    highestRisk: number | null;
    vendors: Array<{ vendorKey: string; vendor: string; count: number }>;
  } | null;
  total: number | null;
  withKev: number | null;
  highestRisk: number | null;
  vendors: Array<{ vendorKey: string; vendor: string; count: number }>;
  items: ProductRow[];
};

export type ProductCve = {
  cve_id: string;
  risk_score: number | null;
  epss: number | null;
  cvss_base: number | null;
  kev: boolean;
  has_poc: boolean;
  has_public_exploit: boolean;
  published_at: string | null;
  version: string | null;
  has_patch: boolean;
};

export type ProductDetail =
  | { found: false }
  | {
      found: true;
      vendorKey: string;
      productKey: string;
      vendor: string | null;
      product: string | null;
      cveCount: number;
      maxRisk: number | null;
      maxEpss: number | null;
      kevCount: number;
      exploitCount: number;
      pocCount: number;
      shown: number;
      versions: string[];
      fixedVersions: string[];
      cves: ProductCve[];
    };

export function useProductCatalog(opts: { q: string; vendor: string; band: string; limit: number; offset: number }) {
  const params = new URLSearchParams();
  params.set("band", opts.band);
  params.set("limit", String(opts.limit));
  if (opts.offset) params.set("offset", String(opts.offset));
  const q = opts.q.trim();
  if (q.length >= 2) params.set("q", q);
  if (opts.vendor && opts.vendor !== "all") params.set("vendor", opts.vendor);
  const url = `/api/products?${params.toString()}`;
  return useQuery({
    queryKey: ["vc", "products", url],
    queryFn: () => getJson<ProductCatalog>(url),
    placeholderData: keepPreviousData,
    staleTime: 20_000
  });
}

export type BduListItem = {
  bduId: string;
  name: string;
  description?: string | null;
  softwareNames?: string | null;
  vendors?: string | null;
  cveIds?: string[];
  linkedCveIds?: string[];
  severity?: string | null;
  severityLevel?: number;
  cvssScore?: number | null;
  identifyDate?: string | null;
  publicationDate?: string | null;
  lastUpdDate?: string | null;
  solution?: string | null;
  status?: string | null;
  exploitStatus?: string | null;
  fixStatus?: string | null;
  hasExploit?: boolean;
  hasFix?: boolean;
  fstecUrl?: string;
};

export type BduDetail =
  | { found: false }
  | {
      found: true;
      bdu: BduListItem;
      links?: {
        fstec?: string | null;
        cves?: Array<{ cveId: string; nvd?: string }>;
      };
    };

export function useBduList(opts: {
  q: string;
  filter: "all" | "linked" | "unlinked" | "urgent" | "day";
  limit: number;
  offset: number;
}) {
  const params = new URLSearchParams();
  params.set("limit", String(opts.limit));
  if (opts.offset) params.set("offset", String(opts.offset));
  const q = opts.q.trim();
  if (q.length >= 2 || /^\d{4}-\d+$/.test(q) || /^bdu:\s*\d{4}-\d+$/i.test(q)) params.set("q", q);
  if (opts.filter === "unlinked") params.set("unlinkedOnly", "true");
  if (opts.filter === "urgent") params.set("urgentOnly", "true");
  if (opts.filter === "day") params.set("publishedLast24h", "true");
  // API умеет unlinkedOnly; «С CVE» фильтруем на клиенте по расширенной странице.
  if (opts.filter === "linked") {
    params.set("limit", String(Math.min(100, Math.max(opts.limit, 50))));
    params.delete("offset");
  }
  const url = `/api/bdu?${params.toString()}`;
  return useQuery({
    queryKey: ["vc", "bdu", url, opts.filter],
    queryFn: async () => {
      const data = await getJson<{ items: BduListItem[]; limit?: number; offset?: number }>(url);
      const items = data.items ?? [];
      const filtered =
        opts.filter === "linked"
          ? items.filter((item) => (item.linkedCveIds?.length ?? 0) > 0 || (item.cveIds?.length ?? 0) > 0)
          : items;
      const start = opts.filter === "linked" ? opts.offset : 0;
      const pageItems = opts.filter === "linked" ? filtered.slice(start, start + opts.limit) : filtered;
      return { items: pageItems, limit: data.limit ?? opts.limit, offset: opts.offset, matched: filtered.length };
    },
    placeholderData: keepPreviousData,
    staleTime: 20_000
  });
}

export function useBduDetail(bduId: string | null) {
  return useQuery({
    queryKey: ["vc", "bdu", bduId],
    enabled: Boolean(bduId),
    queryFn: () => getJson<BduDetail>(`/api/bdu/${encodeURIComponent(bduId!)}`),
    staleTime: 15_000
  });
}

export function useProductDetail(vendorKey: string | null, productKey: string | null) {
  const params = new URLSearchParams();
  if (vendorKey) params.set("vendorKey", vendorKey);
  if (productKey) params.set("productKey", productKey);
  const url = `/api/products/detail?${params.toString()}`;
  return useQuery({
    queryKey: ["vc", "product", vendorKey, productKey],
    enabled: Boolean(vendorKey && productKey),
    queryFn: () => getJson<ProductDetail>(url),
    staleTime: 15_000
  });
}

import { VC_DATA } from "./dataset";
import { applyMutation } from "./mutations";
import type { Product, Severity, VcQuery, VcRange, Vulnerability, VulnerabilityHistory, VulnStatus } from "./types";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

export function formatNum(value: number) {
  return new Intl.NumberFormat("ru-RU").format(value);
}

export function severityLabel(severity: Severity) {
  if (severity === "critical") return "Критическая";
  if (severity === "high") return "Высокая";
  if (severity === "medium") return "Средняя";
  return "Низкая";
}

export function statusLabel(status: VulnStatus) {
  if (status === "open") return "Открыта";
  if (status === "in_progress") return "В работе";
  if (status === "resolved") return "Закрыта";
  if (status === "accepted_risk") return "Принят риск";
  return "Просрочена";
}

export function patchLabel(state: Vulnerability["patchState"]) {
  if (state === "available") return "Доступен";
  if (state === "none") return "Нет";
  if (state === "analysis") return "Анализ";
  return "Не применимо";
}

export function matchesQuery(vuln: Vulnerability, query: VcQuery, withTab = true) {
  if (query.severity !== "all" && vuln.severity !== query.severity) return false;
  if (query.status !== "all" && vuln.status !== query.status) return false;
  if (query.vendor !== "all" && vuln.vendor !== query.vendor) return false;
  if (query.product !== "all" && vuln.product !== query.product && vuln.productId !== query.product) {
    const product = productByName(query.product);
    if (!product || (product.id !== vuln.productId && product.name !== vuln.product)) return false;
  }
  if (query.version !== "all" && vuln.version !== query.version) return false;
  if (query.kev === "yes" && !vuln.kev) return false;
  if (query.kev === "no" && vuln.kev) return false;
  if (query.patch !== "all" && vuln.patchState !== query.patch) return false;
  if (query.epssMin != null && vuln.epss < query.epssMin) return false;
  if (query.epssMax != null && vuln.epss > query.epssMax) return false;
  if (query.riskMin != null && vuln.riskScore < query.riskMin) return false;
  if (query.riskMax != null && vuln.riskScore > query.riskMax) return false;
  if (query.cvssMin != null && vuln.cvss < query.cvssMin) return false;
  if (query.cvssMax != null && vuln.cvss > query.cvssMax) return false;
  if (query.source !== "all" && vuln.source !== query.source) return false;
  if (query.exploit === "exploit" && !vuln.exploitAvailable) return false;
  if (query.exploit === "poc" && !(vuln.pocAvailable && !vuln.exploitAvailable)) return false;
  if (query.exploit === "none" && (vuln.exploitAvailable || vuln.pocAvailable)) return false;
  if (query.discoveredFrom && vuln.discoveredAt.slice(0, 10) < query.discoveredFrom) return false;
  if (query.discoveredTo && vuln.discoveredAt.slice(0, 10) > query.discoveredTo) return false;
  if (query.updatedFrom && vuln.updatedAt.slice(0, 10) < query.updatedFrom) return false;
  if (query.updatedTo && vuln.updatedAt.slice(0, 10) > query.updatedTo) return false;
  if (query.sla === "breach" && vuln.status !== "overdue") return false;
  if (query.sla === "ok" && vuln.status === "overdue") return false;
  if (query.riskAccepted === "yes" && vuln.status !== "accepted_risk") return false;
  if (query.riskAccepted === "no" && vuln.status === "accepted_risk") return false;
  if (query.exploitTrend && !vuln.exploitTrend) return false;
  if (query.exploitOnly && !vuln.exploitAvailable) return false;
  if (query.criticalProduct && !vuln.criticalProduct) return false;
  if (query.q.trim()) {
    const needle = query.q.trim().toLowerCase();
    const hay = [vuln.cve, vuln.title, vuln.product, vuln.vendor, vuln.version, vuln.taskId ?? ""].join(" ").toLowerCase();
    if (!hay.includes(needle)) return false;
  }
  if (!withTab) return true;
  if (query.tab === "attention" && !vuln.attention) return false;
  if (query.tab === "kev" && !vuln.kev) return false;
  if (query.tab === "epss" && vuln.epss < 0.7) return false;
  if (query.tab === "nopatch" && vuln.patchState !== "none") return false;
  if (query.tab === "overdue" && vuln.status !== "overdue") return false;
  return true;
}

export function filterVulns(query: VcQuery, withTab = true) {
  return VC_DATA.vulnerabilities.map(applyMutation).filter((vuln) => matchesQuery(vuln, query, withTab));
}

export function inventoryCounts(query: VcQuery) {
  const base = filterVulns({ ...query, tab: "all", severity: "all" });
  return {
    all: base.length,
    critical: base.filter((vuln) => vuln.severity === "critical").length,
    high: base.filter((vuln) => vuln.severity === "high").length,
    medium: base.filter((vuln) => vuln.severity === "medium").length,
    low: base.filter((vuln) => vuln.severity === "low").length,
    kev: base.filter((vuln) => vuln.kev).length,
    epss: base.filter((vuln) => vuln.epss >= 0.7).length,
    nopatch: base.filter((vuln) => vuln.patchState === "none").length,
    overdue: base.filter((vuln) => vuln.status === "overdue").length
  };
}

export function tabCounts(query: VcQuery) {
  const base = filterVulns({ ...query, tab: "all" }, true);
  return {
    all: base.length,
    attention: base.filter((vuln) => vuln.attention).length,
    kev: base.filter((vuln) => vuln.kev).length,
    epss: base.filter((vuln) => vuln.epss >= 0.7).length,
    nopatch: base.filter((vuln) => vuln.patchState === "none").length,
    overdue: base.filter((vuln) => vuln.status === "overdue").length
  };
}

export function kpis(rows: Vulnerability[]) {
  const total = rows.length || 1;
  const count = (severity: Severity) => rows.filter((row) => row.severity === severity).length;
  return {
    critical: count("critical"),
    high: count("high"),
    medium: count("medium"),
    low: count("low"),
    total: rows.length,
    kev: rows.filter((row) => row.kev).length,
    share: (severity: Severity) => (count(severity) / total) * 100
  };
}

export function donutSeverity(rows: Vulnerability[]) {
  const total = rows.length || 1;
  return SEVERITY_ORDER.map((severity) => {
    const value = rows.filter((row) => row.severity === severity).length;
    return { key: severity, label: severityLabel(severity), value, pct: (value / total) * 100 };
  });
}

export function donutStatus(rows: Vulnerability[]) {
  const total = rows.length || 1;
  const items: Array<{ key: VulnStatus; label: string }> = [
    { key: "resolved", label: "Устранено" },
    { key: "in_progress", label: "В работе" },
    { key: "open", label: "Ожидает" },
    { key: "accepted_risk", label: "Принято в риск" },
    { key: "overdue", label: "Просрочено" }
  ];
  return items.map((item) => {
    const value = rows.filter((row) => row.status === item.key).length;
    return { ...item, value, pct: (value / total) * 100 };
  });
}

export function donutSources(rows: Vulnerability[]) {
  const total = rows.length || 1;
  const order = ["MaxPatrol VM", "Security Vision VM", "NVD / CISA KEV", "FSTEC / БДУ", "Прочие"];
  return order.map((label) => {
    const value = rows.filter((row) => row.source === label).length;
    return { key: label, label, value, pct: (value / total) * 100 };
  });
}

export function formatDate(iso: string) {
  const [year, month, day] = iso.slice(0, 10).split("-");
  if (!year || !month || !day) return iso;
  return `${day}.${month}.${year}`;
}

export function historyFor(vuln: Vulnerability): VulnerabilityHistory[] {
  if (vuln.cve === "CVE-2026-42897") {
    return [
      { id: "h1", vulnerabilityId: vuln.id, at: "2026-10-10", title: "CVE обнаружена" },
      { id: "h2", vulnerabilityId: vuln.id, at: "2026-10-10", title: "Risk Score изменён", detail: "9.4 → 9.8" },
      { id: "h3", vulnerabilityId: vuln.id, at: "2026-10-10", title: "Создана задача VM-12456" },
      { id: "h4", vulnerabilityId: vuln.id, at: "2026-10-11", title: "Изменён статус", detail: "Открыта → В работе" }
    ];
  }
  const day = vuln.discoveredAt.slice(0, 10);
  const events: VulnerabilityHistory[] = [
    { id: `${vuln.id}-found`, vulnerabilityId: vuln.id, at: day, title: "CVE обнаружена", detail: vuln.source },
    { id: `${vuln.id}-risk`, vulnerabilityId: vuln.id, at: day, title: "Risk Score рассчитан", detail: vuln.riskScore.toFixed(1) }
  ];
  if (vuln.taskId) events.push({ id: `${vuln.id}-task`, vulnerabilityId: vuln.id, at: day, title: `Создана задача ${vuln.taskId}` });
  if (vuln.status !== "open") {
    events.push({ id: `${vuln.id}-status`, vulnerabilityId: vuln.id, at: vuln.updatedAt.slice(0, 10), title: "Изменён статус", detail: statusLabel(vuln.status) });
  }
  return events;
}

export function donutPatch(rows: Vulnerability[]) {
  const total = rows.length || 1;
  const items = [
    { key: "available", label: "Доступен патч" },
    { key: "none", label: "Нет исправления" },
    { key: "analysis", label: "Требует анализа" },
    { key: "na", label: "Не применимо" }
  ] as const;
  return items.map((item) => {
    const value = rows.filter((row) => row.patchState === item.key).length;
    return { ...item, value, pct: (value / total) * 100 };
  });
}

const RANGE_DAYS: Record<VcRange, number | null> = { "7d": 7, "30d": 35, "90d": 90, all: null };

export function timeline(rows: Vulnerability[], range: VcRange) {
  const end = new Date("2026-10-12T00:00:00.000Z");
  const days = RANGE_DAYS[range];
  const start = days == null ? new Date("2025-01-01T00:00:00.000Z") : new Date(end.getTime() - days * 86400000);
  const ticks = range === "30d"
    ? ["2026-09-10", "2026-09-15", "2026-09-20", "2026-09-25", "2026-09-30", "2026-10-05", "2026-10-10"]
    : buildTicks(start, end, 7);
  return ticks.map((tick, index) => {
    const from = index === 0 ? start.toISOString().slice(0, 10) : ticks[index - 1]!;
    const bucket = rows.filter((row) => {
      const day = row.discoveredAt.slice(0, 10);
      if (day > tick) return false;
      return index === 0 ? day >= from : day > from;
    });
    return {
      label: tickLabel(tick),
      critical: bucket.filter((row) => row.severity === "critical").length,
      high: bucket.filter((row) => row.severity === "high").length,
      medium: bucket.filter((row) => row.severity === "medium").length,
      low: bucket.filter((row) => row.severity === "low").length
    };
  });
}

function buildTicks(start: Date, end: Date, count: number) {
  const span = end.getTime() - start.getTime();
  return Array.from({ length: count }, (_, index) => {
    const date = new Date(start.getTime() + (span * (index + 1)) / count);
    return date.toISOString().slice(0, 10);
  });
}

function tickLabel(iso: string) {
  const date = new Date(`${iso}T00:00:00.000Z`);
  const months = ["янв", "фев", "мар", "апр", "мая", "июн", "июл", "авг", "сен", "окт", "ноя", "дек"];
  return `${date.getUTCDate()} ${months[date.getUTCMonth()]}`;
}

export function topProducts(rows: Vulnerability[], mode: "count" | "critical") {
  const map = new Map<string, { name: string; chartName: string; value: number }>();
  for (const row of rows) {
    if (mode === "critical" && row.severity !== "critical" && row.severity !== "high") continue;
    const product = VC_DATA.products.find((item) => item.id === row.productId);
    const current = map.get(row.productId) ?? { name: row.product, chartName: product?.chartName ?? row.product, value: 0 };
    current.value += mode === "count" ? 1 : row.severity === "critical" ? 3 : 1;
    map.set(row.productId, current);
  }
  return [...map.values()].sort((a, b) => b.value - a.value).slice(0, 5);
}

export function topVendors(rows: Vulnerability[]) {
  const map = new Map<string, number>();
  for (const row of rows) map.set(row.vendor, (map.get(row.vendor) ?? 0) + 1);
  return [...map.entries()]
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 5);
}

export function versionsFor(query: VcQuery) {
  const rows = VC_DATA.vulnerabilities.filter((vuln) => query.product === "all" || vuln.product === query.product || vuln.productId === query.product);
  return [...new Set(rows.map((row) => row.version))].sort();
}

export function productByName(name: string): Product | undefined {
  return VC_DATA.products.find((product) => product.name === name || product.id === name || product.chartName === name);
}

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "var(--vc-critical)",
  high: "var(--vc-high)",
  medium: "var(--vc-medium)",
  low: "var(--vc-low)"
};

export const STATUS_COLORS = ["#3dd68c", "#60a5fa", "#f5c451", "#a78bfa", "#ff4d5e"];
export const PATCH_COLORS = ["#3dd68c", "#ff4d5e", "#f5c451", "#64748b"];

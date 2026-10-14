export type Severity = "critical" | "high" | "medium" | "low";

export type VulnStatus = "open" | "in_progress" | "resolved" | "accepted_risk" | "overdue";

export type PatchState = "available" | "none" | "analysis" | "na";

export interface Vendor {
  id: string;
  name: string;
}

export interface Product {
  id: string;
  name: string;
  chartName: string;
  vendor: string;
  versions: string[];
  vulnerabilityCount: number;
}

export interface Vulnerability {
  id: string;
  cve: string;
  title: string;
  riskScore: number;
  cvss: number;
  epss: number;
  severity: Severity;
  kev: boolean;
  exploitAvailable: boolean;
  pocAvailable: boolean;
  patchAvailable: boolean;
  patchState: PatchState;
  product: string;
  productId: string;
  version: string;
  vendor: string;
  vendorId: string;
  source: string;
  status: VulnStatus;
  discoveredAt: string;
  updatedAt: string;
  cwe: string;
  taskId?: string;
  attention: boolean;
  exploitTrend: boolean;
  criticalProduct: boolean;
  fixedVersion: string;
  affectedVersions: string[];
  description: string;
}

export interface Patch {
  id: string;
  productId: string;
  product: string;
  vendor: string;
  version: string;
  cveCount: number;
  available: boolean;
}

export interface Task {
  id: string;
  vulnerabilityId: string;
  cve: string;
  title: string;
  product: string;
  status: VulnStatus;
  assignee: string;
  dueAt: string;
}

export interface Remediation {
  vulnerabilityId: string;
  recommendation: string;
  fixedVersion: string;
  progressDone: number;
  progressTotal: number;
}

export interface RiskIndicator {
  id: string;
  label: string;
  value: number;
  delta: number;
  kind: "kev" | "epss" | "exploit" | "nopatch" | "trend" | "criticalProducts" | "product";
  product?: string;
}

export interface VulnerabilitySource {
  id: string;
  name: string;
  coverage: number;
}

export interface VulnerabilityHistory {
  id: string;
  vulnerabilityId: string;
  at: string;
  title: string;
  detail?: string;
}

export type ExploitFilter = "all" | "exploit" | "poc" | "none";

/** Сигнал радара эксплуатации (клик с дашборда / аналитики). */
export type ExploitSignal =
  | "all"
  | "epss_spike"
  | "has_poc"
  | "has_public_exploit"
  | "vckev_only"
  | "new_vckev_7d";

export type VcTab = "all" | "attention" | "kev" | "epss" | "nopatch" | "overdue";

export type VcRange = "7d" | "30d" | "90d" | "all";

export interface VcQuery {
  q: string;
  tab: VcTab;
  severity: Severity | "all";
  status: VulnStatus | "all";
  vendor: string;
  product: string;
  version: string;
  kev: "all" | "yes" | "no";
  /** CVE, добавленные в CISA KEV за N календарных дней (drill из аналитики/дашборда). */
  kevAddedDays: number | null;
  /** CVE с published_at за последние N дней. */
  publishedDays: number | null;
  /** Срез радара: EPSS spike, PoC, публичный эксплойт, VulnCheck KEV. */
  exploitSignal: ExploitSignal;
  patch: PatchState | "all";
  epssMin: number | null;
  exploitTrend: boolean;
  criticalProduct: boolean;
  exploitOnly: boolean;
  range: VcRange;
  source: string;
  riskMin: number | null;
  riskMax: number | null;
  cvssMin: number | null;
  cvssMax: number | null;
  epssMax: number | null;
  exploit: ExploitFilter;
  discoveredFrom: string;
  discoveredTo: string;
  updatedFrom: string;
  updatedTo: string;
  sla: "all" | "breach" | "ok";
  riskAccepted: "all" | "yes" | "no";
}

export const EMPTY_QUERY: VcQuery = {
  q: "",
  tab: "all",
  severity: "all",
  status: "all",
  vendor: "all",
  product: "all",
  version: "all",
  kev: "all",
  kevAddedDays: null,
  publishedDays: null,
  exploitSignal: "all",
  patch: "all",
  epssMin: null,
  exploitTrend: false,
  criticalProduct: false,
  exploitOnly: false,
  range: "30d",
  source: "all",
  riskMin: null,
  riskMax: null,
  cvssMin: null,
  cvssMax: null,
  epssMax: null,
  exploit: "all",
  discoveredFrom: "",
  discoveredTo: "",
  updatedFrom: "",
  updatedTo: "",
  sla: "all",
  riskAccepted: "all"
};

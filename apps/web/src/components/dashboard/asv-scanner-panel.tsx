"use client";

import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Copy, ExternalLink, FileDown, Loader2, Play, Plus, Radar, RefreshCw } from "lucide-react";
import * as Dialog from "@radix-ui/react-dialog";
import { apiFetch } from "@/lib/api-fetch";
import { cn } from "../ui/cn";

type AssetType = "domain" | "ip" | "cidr" | "url";

type AsvAsset = {
  id: string;
  asset_type: AssetType;
  key_norm: string;
  display_name: string;
  scope_policy?: unknown;
  created_at: string;
  updated_at: string;
};

type AsvScanProfile = {
  id: string;
  name: string;
  mode: "safe" | "standard";
  config: unknown;
};

type NucleiProfileConfig = {
  enabled?: boolean;
  tags?: string[];
  severity?: string[];
  rateLimitPerMin?: number;
};

type AsvScanRun = {
  id: string;
  asset_id: string;
  profile_id?: string | null;
  scan_mode?: "safe" | "standard";
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  created_at: string;
  started_at: string | null;
  ended_at: string | null;
  error: string | null;
};

type AsvFinding = {
  id: string;
  asset_id: string;
  scan_run_id: string | null;
  fingerprint: string;
  title: string;
  severity: string;
  confidence: string;
  tool: string;
  external_id?: string | null;
  affected?: unknown;
  evidence?: unknown;
  status: string;
  last_seen: string;
};

type AsvMsfRun = {
  id: string;
  finding_id: string;
  scan_run_id: string | null;
  asset_id: string | null;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  mode: "safe" | "exploit";
  action: "search" | "check" | "run" | "exploit";
  module: string | null;
  options: Record<string, unknown>;
  ack_risks: boolean;
  summary: string;
  error: string | null;
  created_by: string | null;
  started_at: string | null;
  ended_at: string | null;
  created_at: string;
  updated_at: string;
};

type AsvMsfArtifact = {
  id: string;
  run_id: string;
  kind: "msf.stdout" | "msf.stderr" | "msf.rc" | "msf.meta";
  bytes: number;
  sha256: string | null;
  storage: "inline";
  created_at: string;
};

type AsvMsfEvent = {
  id: string;
  run_id: string;
  ts: string;
  actor: string | null;
  action: string;
  before: unknown;
  after: unknown;
  meta: unknown;
};

type AsvNucleiTemplate = {
  template_id: string;
  name: string | null;
  severity: string | null;
  tags: string[] | null;
  description: string | null;
  reference: string[] | null;
  updated_at: string;
};

type AsvPortObservation = {
  id: string;
  asset_id: string;
  scan_run_id: string | null;
  target: string;
  ip: string | null;
  port: number;
  transport: string;
  state: string;
  latency_ms: number | null;
  observed_at: string;
};

type AsvHttpObservation = {
  id: string;
  asset_id: string;
  scan_run_id: string | null;
  url: string;
  final_url: string | null;
  status: number | null;
  title: string | null;
  server: string | null;
  tech: string[];
  latency_ms: number | null;
  observed_at: string;
};

type AsvArtifact = {
  id: string;
  scan_run_id: string;
  kind: string;
  bytes: number;
  sha256: string | null;
  storage: string;
  created_at: string;
};

type AsvArtifactFull = AsvArtifact & {
  content_text?: string | null;
};

type AsvInventory = {
  ports: Array<{ port: number; state: string; n: number; last_observed_at: string }>;
  http: Array<{ url: string; status: number | null; server: string | null; title: string | null; last_observed_at: string }>;
  findingCounts: Array<{ tool: string; severity: string; n: number }>;
};

type AsvIssue = {
  id: string;
  asset_id: string;
  issue_key: string;
  title: string;
  tool: string;
  external_id: string | null;
  endpoint_key: string | null;
  severity: string;
  confidence: string;
  status: "open" | "resolved" | "accepted" | "false_positive";
  first_seen: string;
  last_seen: string;
  last_scan_run_id: string | null;
  occurrences: number;
  fix_guidance?: unknown;
};

function getFindingEndpointKey(f: AsvFinding): string | null {
  const aff = f.affected;
  const affObj = aff && typeof aff === "object" ? (aff as Record<string, unknown>) : null;
  const url = affObj && typeof affObj.url === "string" ? affObj.url : null;
  const matchedAt = affObj && typeof affObj.matchedAt === "string" ? affObj.matchedAt : null;
  return url || matchedAt || null;
}

type FindingEnrichment = {
  cveIds: string[];
  missingInLocalDb: string[];
  matches: Array<{
    cve_id: string;
    published_at: string | null;
    modified_at: string | null;
    cvss_base: number | null;
    severity_hint: string | null;
    description: string | null;
    epss: { score: number; percentile: number | null; scored_at: string | null } | null;
    kev: { date_added: string; required_action: string | null } | null;
  }>;
};

function getFindingEnrichment(f: AsvFinding | null): FindingEnrichment | null {
  if (!f) return null;
  const ev = f.evidence;
  const arr = Array.isArray(ev) ? ev : [];
  const hit = arr.find(
    (x) =>
      x &&
      typeof x === "object" &&
      (x as any).kind === "enrichment" &&
      (x as any).source === "local_cve_db"
  ) as any;
  if (!hit || typeof hit !== "object") return null;
  const cveIds = Array.isArray(hit.cveIds) ? hit.cveIds.map(String) : [];
  const missingInLocalDb = Array.isArray(hit.missingInLocalDb) ? hit.missingInLocalDb.map(String) : [];
  const matches = Array.isArray(hit.matches) ? hit.matches : [];
  return {
    cveIds,
    missingInLocalDb,
    matches: matches
      .filter((m: any) => m && typeof m === "object" && typeof m.cve_id === "string")
      .map((m: any) => ({
        cve_id: String(m.cve_id),
        published_at: typeof m.published_at === "string" ? m.published_at : null,
        modified_at: typeof m.modified_at === "string" ? m.modified_at : null,
        cvss_base: typeof m.cvss_base === "number" ? m.cvss_base : null,
        severity_hint: typeof m.severity_hint === "string" ? m.severity_hint : null,
        description: typeof m.description === "string" ? m.description : null,
        epss:
          m.epss && typeof m.epss === "object" && typeof m.epss.score === "number"
            ? {
                score: Number(m.epss.score),
                percentile: typeof m.epss.percentile === "number" ? Number(m.epss.percentile) : null,
                scored_at: typeof m.epss.scored_at === "string" ? m.epss.scored_at : null
              }
            : null,
        kev:
          m.kev && typeof m.kev === "object" && typeof m.kev.date_added === "string"
            ? {
                date_added: String(m.kev.date_added),
                required_action: typeof m.kev.required_action === "string" ? m.kev.required_action : null
              }
            : null
      }))
  };
}

function parseNucleiDiag(text: string | null | undefined): {
  targets?: string;
  techHints?: string;
  phases?: string;
} {
  const s = text ?? "";
  const lines = s.split("\n").slice(0, 60);
  const targets = lines.find((l) => l.startsWith("[nuclei] targets."));
  const techHints = lines.find((l) => l.startsWith("[nuclei] techHints="));
  const phases = lines.find((l) => l.startsWith("[nuclei] phases="));
  return {
    targets: targets ? targets.replace("[nuclei] ", "") : undefined,
    techHints: techHints ? techHints.replace("[nuclei] ", "") : undefined,
    phases: phases ? phases.replace("[nuclei] ", "") : undefined
  };
}

function safeStringify(x: unknown): string {
  try {
    return JSON.stringify(x, null, 2);
  } catch {
    return String(x);
  }
}

async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Fallback
    const el = document.createElement("textarea");
    el.value = text;
    el.style.position = "fixed";
    el.style.left = "-9999px";
    document.body.appendChild(el);
    el.focus();
    el.select();
    try {
      document.execCommand("copy");
    } finally {
      document.body.removeChild(el);
    }
  }
}

function downloadText(filename: string, content: string) {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function fmtTs(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

function parseTargetHintsFromFinding(f: AsvFinding): {
  rhosts: string | null;
  rport: number | null;
  ssl: boolean | null;
  targetUri: string | null;
  vhost: string | null;
} {
  const aff = f.affected && typeof f.affected === "object" ? (f.affected as Record<string, unknown>) : {};
  const urlRaw =
    (typeof aff.url === "string" ? aff.url : null) ||
    (typeof aff.matchedAt === "string" ? aff.matchedAt : null) ||
    null;

  const candidate = urlRaw?.trim() || "";
  if (!candidate) return { rhosts: null, rport: null, ssl: null, targetUri: null, vhost: null };

  // Try URL parse first (scheme://host:port/path).
  try {
    const u = new URL(candidate.includes("://") ? candidate : `http://${candidate}`);
    const host = u.hostname;
    const port =
      u.port && /^\d{1,5}$/.test(u.port) ? Math.max(1, Math.min(65535, Number(u.port))) : null;
    const ssl = u.protocol === "https:" ? true : u.protocol === "http:" ? false : null;
    const targetUri = u.pathname && u.pathname !== "" ? u.pathname : "/";
    const rhosts = host || null;
    const rport = port;
    return { rhosts, rport, ssl, targetUri, vhost: null };
  } catch {
    // ignore
  }

  // Fallback: host:port
  const m = candidate.match(/^([^/\\s:]+)(?::(\\d{1,5}))?$/);
  const host = m?.[1] ? String(m[1]) : null;
  const port = m?.[2] ? Math.max(1, Math.min(65535, Number(m[2]))) : null;
  return { rhosts: host, rport: Number.isFinite(port) ? port : null, ssl: null, targetUri: null, vhost: null };
}

export function AsvScannerPanel() {
  const [type, setType] = useState<AssetType>("domain");
  const [key, setKey] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [profileId, setProfileId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [templateOpen, setTemplateOpen] = useState(false);
  const [templateId, setTemplateId] = useState<string | null>(null);
  const [findingQ, setFindingQ] = useState("");
  const [toolFilter, setToolFilter] = useState<string>("");
  const [sevFilter, setSevFilter] = useState<string>("");
  const [groupByEndpoint, setGroupByEndpoint] = useState(false);
  const [activeTab, setActiveTab] = useState<"overview" | "endpoints" | "issues">("overview");
  const [diffFrom, setDiffFrom] = useState<string>("");
  const [diffTo, setDiffTo] = useState<string>("");
  const [findingOpen, setFindingOpen] = useState(false);
  const [findingId, setFindingId] = useState<string | null>(null);
  const [artifactOpen, setArtifactOpen] = useState(false);
  const [artifactId, setArtifactId] = useState<string | null>(null);
  const [msfOpen, setMsfOpen] = useState(false);
  const [msfText, setMsfText] = useState<string>("");
  const [msfFindingId, setMsfFindingId] = useState<string | null>(null);
  const [msfMode, setMsfMode] = useState<"safe" | "exploit">("safe");
  const [, setMsfAction] = useState<"search" | "check" | "run" | "exploit">("check");
  const [, setMsfModule] = useState<string>("");
  const [msfAck, setMsfAck] = useState(false);
  const [msfOptRhosts, setMsfOptRhosts] = useState("");
  const [msfOptRport, setMsfOptRport] = useState<string>("443");
  const [msfOptSsl, setMsfOptSsl] = useState(true);
  const [msfOptTargetUri, setMsfOptTargetUri] = useState<string>("/");
  const [msfOptVhost, setMsfOptVhost] = useState<string>("");
  const [msfSelectedRunId, setMsfSelectedRunId] = useState<string | null>(null);
  const [msfArtifactOpen, setMsfArtifactOpen] = useState(false);
  const [msfArtifactTitle, setMsfArtifactTitle] = useState<string>("");
  const [msfArtifactText, setMsfArtifactText] = useState<string>("");
  const [issueAiOpen, setIssueAiOpen] = useState(false);
  const [issueAiId, setIssueAiId] = useState<string | null>(null);
  const [triagePollUntilMs, setTriagePollUntilMs] = useState<number>(0);

  const assetsQuery = useQuery({
    queryKey: ["asv", "assets"],
    queryFn: async () => {
      const res = await apiFetch(`/api/asv/assets?limit=200`, { cache: "no-store" });
      const body = (await res.json()) as { items?: AsvAsset[]; message?: string };
      if (!res.ok) throw new Error(body.message ?? `assets (${res.status})`);
      return body.items ?? [];
    },
    staleTime: 15_000
  });

  useEffect(() => {
    const first = assetsQuery.data?.[0]?.id ?? null;
    if (!selected && first) setSelected(first);
  }, [assetsQuery.data, selected]);

  const runsQuery = useQuery({
    queryKey: ["asv", "scanRuns", selected],
    enabled: selected != null,
    queryFn: async () => {
      const res = await apiFetch(`/api/asv/scan-runs?assetId=${encodeURIComponent(selected!)}`, {
        cache: "no-store"
      });
      const body = (await res.json()) as { items?: AsvScanRun[]; message?: string };
      if (!res.ok) throw new Error(body.message ?? `scan-runs (${res.status})`);
      return body.items ?? [];
    },
    staleTime: 5_000,
    refetchInterval: 5_000
  });

  const msfRunsQuery = useQuery({
    queryKey: ["asv", "msfRunsByFinding", msfFindingId],
    enabled: Boolean(msfFindingId) && msfOpen,
    queryFn: async () => {
      const res = await apiFetch(`/api/asv/findings/${encodeURIComponent(msfFindingId!)}/msf-runs`, {
        cache: "no-store"
      });
      const body = (await res.json()) as { items?: AsvMsfRun[]; message?: string };
      if (!res.ok) throw new Error(body.message ?? `msf-runs (${res.status})`);
      return body.items ?? [];
    },
    staleTime: 1_500,
    refetchInterval: 2_500
  });

  const msfRunQuery = useQuery({
    queryKey: ["asv", "msfRun", msfSelectedRunId],
    enabled: Boolean(msfSelectedRunId) && msfOpen,
    queryFn: async () => {
      const res = await apiFetch(`/api/asv/msf-runs/${encodeURIComponent(msfSelectedRunId!)}`, { cache: "no-store" });
      if (!res.ok) throw new Error(`msf-run (${res.status})`);
      return (await res.json()) as AsvMsfRun;
    },
    staleTime: 1_500,
    refetchInterval: 2_500
  });

  const msfArtifactsQuery = useQuery({
    queryKey: ["asv", "msfArtifacts", msfSelectedRunId],
    enabled: Boolean(msfSelectedRunId) && msfOpen,
    queryFn: async () => {
      const res = await apiFetch(`/api/asv/msf-runs/${encodeURIComponent(msfSelectedRunId!)}/artifacts`, {
        cache: "no-store"
      });
      const body = (await res.json()) as { items?: AsvMsfArtifact[]; message?: string };
      if (!res.ok) throw new Error(body.message ?? `msf-artifacts (${res.status})`);
      return body.items ?? [];
    },
    staleTime: 1_500,
    refetchInterval: 2_500
  });

  const msfEventsQuery = useQuery({
    queryKey: ["asv", "msfEvents", msfSelectedRunId],
    enabled: Boolean(msfSelectedRunId) && msfOpen,
    queryFn: async () => {
      const res = await apiFetch(`/api/asv/msf-runs/${encodeURIComponent(msfSelectedRunId!)}/events`, {
        cache: "no-store"
      });
      const body = (await res.json()) as { items?: AsvMsfEvent[]; message?: string };
      if (!res.ok) throw new Error(body.message ?? `msf-events (${res.status})`);
      return body.items ?? [];
    },
    staleTime: 3_000,
    refetchInterval: 5_000
  });

  const msfConclusion = useMemo(() => {
    const items = msfEventsQuery.data ?? [];
    const latestDone = items.find((e) => e.action === "completed" || e.action === "failed");
    const meta =
      latestDone && latestDone.meta && typeof latestDone.meta === "object" ? (latestDone.meta as Record<string, unknown>) : null;
    if (!meta) return null;
    const best = meta.best && typeof meta.best === "object" ? (meta.best as Record<string, unknown>) : null;
    const verdict = typeof best?.verdict === "string" ? best.verdict : typeof meta.verdict === "string" ? meta.verdict : null;
    const conclusion =
      typeof best?.conclusion === "string" ? best.conclusion : typeof meta.conclusion === "string" ? meta.conclusion : null;
    const sessionsHint =
      typeof best?.sessionsHint === "string" ? best.sessionsHint : typeof meta.sessionsHint === "string" ? meta.sessionsHint : null;
    const lootHint = typeof best?.lootHint === "string" ? best.lootHint : typeof meta.lootHint === "string" ? meta.lootHint : null;
    const highlights = Array.isArray(best?.highlights)
      ? best!.highlights.map(String).filter(Boolean).slice(0, 24)
      : Array.isArray(meta.highlights)
        ? meta.highlights.map(String).filter(Boolean).slice(0, 24)
        : [];
    return { verdict, conclusion, sessionsHint, lootHint, highlights };
  }, [msfEventsQuery.data]);

  const msfSteps = useMemo(() => {
    const events = msfEventsQuery.data ?? [];
    const steps = events
      .filter((e) => e.action === "step_completed")
      .map((e) => (e.meta && typeof e.meta === "object" ? (e.meta as Record<string, unknown>) : null))
      .filter(Boolean)
      .map((m) => ({
        step: typeof m!.step === "number" ? m!.step : null,
        label: typeof m!.label === "string" ? m!.label : "",
        module: typeof m!.module === "string" ? m!.module : "",
        verdict: typeof m!.verdict === "string" ? m!.verdict : "",
        conclusion: typeof m!.conclusion === "string" ? m!.conclusion : "",
        sessionsHint: typeof m!.sessionsHint === "string" ? m!.sessionsHint : null,
        lootHint: typeof m!.lootHint === "string" ? m!.lootHint : null
      }))
      .sort((a, b) => (a.step ?? 999) - (b.step ?? 999));
    return steps.slice(0, 10);
  }, [msfEventsQuery.data]);

  const profilesQuery = useQuery({
    queryKey: ["asv", "profiles"],
    queryFn: async () => {
      const res = await apiFetch(`/api/asv/profiles`, { cache: "no-store" });
      const body = (await res.json()) as { items?: AsvScanProfile[]; message?: string };
      if (!res.ok) throw new Error(body.message ?? `profiles (${res.status})`);
      return body.items ?? [];
    },
    staleTime: 30_000
  });

  const selectedProfile = useMemo(() => {
    if (!profileId) return null;
    return (profilesQuery.data ?? []).find((p) => p.id === profileId) ?? null;
  }, [profileId, profilesQuery.data]);

  const nucleiEnabled = useMemo(() => {
    const cfg = selectedProfile?.config;
    const n = cfg && typeof cfg === "object" ? (cfg as { nuclei?: unknown }).nuclei : undefined;
    return Boolean(n && typeof n === "object" && (n as { enabled?: boolean }).enabled === true);
  }, [selectedProfile?.config]);

  const nucleiCfg = useMemo((): NucleiProfileConfig => {
    const cfg = selectedProfile?.config;
    const n = cfg && typeof cfg === "object" ? (cfg as { nuclei?: unknown }).nuclei : undefined;
    return (n && typeof n === "object" ? (n as NucleiProfileConfig) : {}) as NucleiProfileConfig;
  }, [selectedProfile?.config]);

  const nucleiTagsText = useMemo(() => (nucleiCfg.tags ?? []).join(", "), [nucleiCfg.tags]);
  const nucleiSeverity = useMemo(() => new Set((nucleiCfg.severity ?? []).map((s) => s.toLowerCase())), [nucleiCfg.severity]);
  const nucleiRate = useMemo(() => {
    const n = Number(nucleiCfg.rateLimitPerMin ?? 120);
    return Number.isFinite(n) ? Math.max(1, Math.min(6000, Math.floor(n))) : 120;
  }, [nucleiCfg.rateLimitPerMin]);

  async function setNucleiEnabled(next: boolean) {
    if (!selectedProfile) return;
    setErr(null);
    setBusy(true);
    try {
      const res = await apiFetch(`/api/asv/profiles/${encodeURIComponent(selectedProfile.id)}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ nuclei: { enabled: next } })
      });
      const body = (await res.json()) as { message?: string };
      if (!res.ok) throw new Error(body.message ?? `update profile (${res.status})`);
      await profilesQuery.refetch();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "update profile failed");
    } finally {
      setBusy(false);
    }
  }

  async function saveNucleiTuning(next: { tags?: string[]; severity?: string[]; rateLimitPerMin?: number }) {
    if (!selectedProfile) return;
    setErr(null);
    setBusy(true);
    try {
      const res = await apiFetch(`/api/asv/profiles/${encodeURIComponent(selectedProfile.id)}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ nuclei: next })
      });
      const body = (await res.json()) as { message?: string };
      if (!res.ok) throw new Error(body.message ?? `update profile (${res.status})`);
      await profilesQuery.refetch();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "update profile failed");
    } finally {
      setBusy(false);
    }
  }

  const findingsQuery = useQuery({
    queryKey: ["asv", "findings", selected],
    enabled: selected != null,
    queryFn: async () => {
      const res = await apiFetch(`/api/asv/findings?assetId=${encodeURIComponent(selected!)}`, { cache: "no-store" });
      const body = (await res.json()) as { items?: AsvFinding[]; message?: string };
      if (!res.ok) throw new Error(body.message ?? `findings (${res.status})`);
      return body.items ?? [];
    },
    staleTime: 5_000,
    refetchInterval: 5_000
  });

  const artifactsQuery = useQuery({
    queryKey: ["asv", "artifacts", selected],
    enabled: selected != null,
    queryFn: async () => {
      // Grab latest run id first.
      const runs = runsQuery.data ?? [];
      const latest = runs[0]?.id;
      if (!latest) return [] as AsvArtifact[];
      const res = await apiFetch(`/api/asv/scan-runs/${encodeURIComponent(latest)}/artifacts`, { cache: "no-store" });
      const body = (await res.json()) as { items?: AsvArtifact[]; message?: string };
      if (!res.ok) throw new Error(body.message ?? `artifacts (${res.status})`);
      return body.items ?? [];
    },
    staleTime: 5_000,
    refetchInterval: 5_000
  });

  const portsQuery = useQuery({
    queryKey: ["asv", "obs", "ports", selected],
    enabled: selected != null,
    queryFn: async () => {
      const res = await apiFetch(`/api/asv/observations/ports?assetId=${encodeURIComponent(selected!)}`, {
        cache: "no-store"
      });
      const body = (await res.json()) as { items?: AsvPortObservation[]; message?: string };
      if (!res.ok) throw new Error(body.message ?? `ports (${res.status})`);
      return body.items ?? [];
    },
    staleTime: 5_000,
    refetchInterval: 5_000
  });

  const httpQuery = useQuery({
    queryKey: ["asv", "obs", "http", selected],
    enabled: selected != null,
    queryFn: async () => {
      const res = await apiFetch(`/api/asv/observations/http?assetId=${encodeURIComponent(selected!)}`, {
        cache: "no-store"
      });
      const body = (await res.json()) as { items?: AsvHttpObservation[]; message?: string };
      if (!res.ok) throw new Error(body.message ?? `http (${res.status})`);
      return body.items ?? [];
    },
    staleTime: 5_000,
    refetchInterval: 5_000
  });

  const inventoryQuery = useQuery({
    queryKey: ["asv", "inventory", selected],
    enabled: selected != null,
    queryFn: async () => {
      const res = await apiFetch(`/api/asv/inventory?assetId=${encodeURIComponent(selected!)}`, { cache: "no-store" });
      const body = (await res.json()) as Partial<AsvInventory> & { message?: string };
      if (!res.ok) throw new Error(body.message ?? `inventory (${res.status})`);
      return body as AsvInventory;
    },
    staleTime: 10_000,
    refetchInterval: 10_000
  });

  const issuesQuery = useQuery({
    queryKey: ["asv", "issues", selected],
    enabled: selected != null,
    queryFn: async () => {
      const res = await apiFetch(`/api/asv/issues?assetId=${encodeURIComponent(selected!)}`, { cache: "no-store" });
      const body = (await res.json()) as { items?: AsvIssue[]; message?: string };
      if (!res.ok) throw new Error(body.message ?? `issues (${res.status})`);
      return body.items ?? [];
    },
    staleTime: 5_000,
    refetchInterval: 10_000
  });

  const diffQuery = useQuery({
    queryKey: ["asv", "scanRuns", "diff", diffFrom, diffTo],
    enabled: Boolean(diffFrom && diffTo),
    queryFn: async () => {
      const res = await apiFetch(
        `/api/asv/scan-runs/diff?from=${encodeURIComponent(diffFrom)}&to=${encodeURIComponent(diffTo)}`,
        { cache: "no-store" }
      );
      const body = (await res.json()) as {
        message?: string;
        added?: AsvFinding[];
        resolved?: AsvFinding[];
        changed?: Array<{ fingerprint: string; title: string; fromSeverity: string; toSeverity: string; tool: string }>;
      };
      if (!res.ok) throw new Error(body.message ?? `diff (${res.status})`);
      return body;
    },
    staleTime: 3_000
  });

  const selectedAsset = useMemo(() => {
    return (assetsQuery.data ?? []).find((a) => a.id === selected) ?? null;
  }, [assetsQuery.data, selected]);

  const allowStandard = useMemo(() => {
    const p = selectedAsset?.scope_policy;
    return Boolean(p && typeof p === "object" && (p as { allowStandard?: boolean }).allowStandard === true);
  }, [selectedAsset?.scope_policy]);

  const maxHosts = useMemo(() => {
    const p = selectedAsset?.scope_policy;
    const v = p && typeof p === "object" ? (p as { maxHosts?: unknown }).maxHosts : undefined;
    const n = typeof v === "number" ? v : typeof v === "string" ? Number(v) : NaN;
    if (!Number.isFinite(n) || n <= 0) return 64;
    return Math.max(1, Math.min(256, Math.floor(n)));
  }, [selectedAsset?.scope_policy]);

  useEffect(() => {
    const profiles = profilesQuery.data ?? [];
    if (!profiles.length) return;
    const safe = profiles.find((p) => p.name === "safe")?.id ?? profiles[0]?.id ?? null;
    const standard = profiles.find((p) => p.name === "standard")?.id ?? safe;
    if (!profileId) {
      setProfileId(allowStandard ? standard : safe);
      return;
    }
    // If asset lost allowlist, force safe profile.
    const cur = profiles.find((p) => p.id === profileId) ?? null;
    if (cur?.mode === "standard" && !allowStandard) setProfileId(safe);
  }, [allowStandard, profileId, profilesQuery.data]);

  async function createAsset() {
    setErr(null);
    setBusy(true);
    try {
      const raw = key.trim();
      const hasScheme = /^https?:\/\//i.test(raw);
      const effType: AssetType = hasScheme ? "url" : type;
      const effKey =
        effType === "url" && raw && !hasScheme
          ? `https://${raw}`
          : raw;

      const res = await apiFetch(`/api/asv/assets`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ type: effType, key: effKey })
      });
      const body = (await res.json()) as { message?: string } & Partial<AsvAsset>;
      if (!res.ok) throw new Error(body.message ?? `create asset (${res.status})`);
      if (!body.id) throw new Error("create asset: missing id");
      await assetsQuery.refetch();
      setKey("");
      setSelected(body.id);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "create asset failed");
    } finally {
      setBusy(false);
    }
  }

  async function toggleAllowStandard(next: boolean) {
    if (!selectedAsset) return;
    setErr(null);
    setBusy(true);
    try {
      const res = await apiFetch(`/api/asv/assets/${encodeURIComponent(selectedAsset.id)}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ scopePolicy: { allowStandard: next } })
      });
      const body = (await res.json()) as { message?: string };
      if (!res.ok) throw new Error(body.message ?? `update asset (${res.status})`);
      await assetsQuery.refetch();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "update asset failed");
    } finally {
      setBusy(false);
    }
  }

  async function updateMaxHosts(next: number) {
    if (!selectedAsset) return;
    setErr(null);
    setBusy(true);
    try {
      const res = await apiFetch(`/api/asv/assets/${encodeURIComponent(selectedAsset.id)}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ scopePolicy: { maxHosts: next } })
      });
      const body = (await res.json()) as { message?: string };
      if (!res.ok) throw new Error(body.message ?? `update asset (${res.status})`);
      await assetsQuery.refetch();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "update asset failed");
    } finally {
      setBusy(false);
    }
  }

  async function startScan() {
    if (!selected) return;
    setErr(null);
    setBusy(true);
    try {
      const res = await apiFetch(`/api/asv/scan-runs`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ assetId: selected, profileId })
      });
      const body = (await res.json()) as { message?: string } & Partial<AsvScanRun>;
      if (!res.ok) throw new Error(body.message ?? `start scan (${res.status})`);
      await runsQuery.refetch();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "start scan failed");
    } finally {
      setBusy(false);
    }
  }

  const assets = assetsQuery.data ?? [];
  const runs = useMemo(() => runsQuery.data ?? [], [runsQuery.data]);
  const findings = useMemo(() => findingsQuery.data ?? [], [findingsQuery.data]);
  const issues = useMemo(() => issuesQuery.data ?? [], [issuesQuery.data]);
  const artifacts = useMemo(() => artifactsQuery.data ?? [], [artifactsQuery.data]);
  const ports = portsQuery.data ?? [];
  const httpObs = httpQuery.data ?? [];
  const profiles = profilesQuery.data ?? [];
  const inventory = inventoryQuery.data;

  const nucleiTemplateIds = useMemo(() => {
    const ids = findings
      .filter((f) => f.tool === "nuclei" && typeof f.external_id === "string" && f.external_id.length > 0)
      .map((f) => f.external_id as string);
    return [...new Set(ids)].slice(0, 60);
  }, [findings]);

  const nucleiTemplatesQuery = useQuery({
    queryKey: ["asv", "nuclei", "templates", nucleiTemplateIds.join(",")],
    enabled: nucleiTemplateIds.length > 0,
    queryFn: async () => {
      const res = await apiFetch(
        `/api/asv/nuclei/templates?templateIds=${encodeURIComponent(nucleiTemplateIds.join(","))}`,
        { cache: "no-store" }
      );
      const body = (await res.json()) as { items?: AsvNucleiTemplate[]; message?: string };
      if (!res.ok) throw new Error(body.message ?? `nuclei templates (${res.status})`);
      return body.items ?? [];
    },
    staleTime: 30_000
  });

  const nucleiTemplateMap = useMemo(() => {
    const m = new Map<string, AsvNucleiTemplate>();
    for (const t of nucleiTemplatesQuery.data ?? []) m.set(t.template_id, t);
    return m;
  }, [nucleiTemplatesQuery.data]);

  const tools = useMemo(() => {
    const s = new Set<string>();
    for (const f of findings) if (f.tool) s.add(f.tool);
    return Array.from(s).sort();
  }, [findings]);

  const severities = useMemo(() => {
    const s = new Set<string>();
    for (const f of findings) if (f.severity) s.add(f.severity);
    return Array.from(s).sort();
  }, [findings]);

  const findingsFiltered = useMemo(() => {
    const q = findingQ.trim().toLowerCase();
    return findings.filter((f) => {
      if (toolFilter && f.tool !== toolFilter) return false;
      if (sevFilter && f.severity !== sevFilter) return false;
      if (!q) return true;
      const hay = `${f.title} ${f.tool} ${f.severity} ${f.external_id ?? ""} ${f.fingerprint}`.toLowerCase();
      return hay.includes(q);
    });
  }, [findings, findingQ, toolFilter, sevFilter]);

  const endpointRows = useMemo(() => {
    const http = inventory?.http ?? [];
    return http.map((h) => {
      const url = h.url;
      const n = findingsFiltered.filter((f) => getFindingEndpointKey(f) === url).length;
      const top = (() => {
        const order = ["critical", "high", "medium", "low", "info"];
        for (const sev of order) {
          if (findingsFiltered.some((f) => getFindingEndpointKey(f) === url && f.severity.toLowerCase() === sev)) return sev;
        }
        return "info";
      })();
      return { ...h, findings: n, topSeverity: top };
    });
  }, [inventory?.http, findingsFiltered]);

  const findingsGrouped = useMemo(() => {
    if (!groupByEndpoint) return null;
    const groups = new Map<string, AsvFinding[]>();
    for (const f of findingsFiltered) {
      const key =
        getFindingEndpointKey(f) ||
        (f.tool === "nuclei" && f.external_id ? `template:${f.external_id}` : f.tool) ||
        "other";
      const arr = groups.get(key) ?? [];
      arr.push(f);
      groups.set(key, arr);
    }
    return Array.from(groups.entries()).sort((a, b) => b[1].length - a[1].length);
  }, [groupByEndpoint, findingsFiltered]);

  const selectedFinding = useMemo(() => {
    if (!findingId) return null;
    return findings.find((f) => f.id === findingId) ?? null;
  }, [findingId, findings]);

  const selectedIssue = useMemo(() => {
    if (!issueAiId) return null;
    return issues.find((x) => x.id === issueAiId) ?? null;
  }, [issueAiId, issues]);

  const issuePriorityQuery = useQuery({
    queryKey: ["asv", "issue", "ai-priority", selectedIssue?.id ?? ""],
    enabled: Boolean(selectedIssue?.id && issueAiOpen),
    queryFn: async () => {
      const res = await apiFetch(
        `/api/asv/issues/${encodeURIComponent(selectedIssue!.id)}/ai/priority`,
        { cache: "no-store" }
      );
      const body = (await res.json()) as { item?: any; message?: string };
      if (!res.ok) throw new Error(body.message ?? `ai priority (${res.status})`);
      return body.item ?? null;
    },
    staleTime: 5_000
  });

  const triageQuery = useQuery({
    queryKey: ["asv", "finding", "ai-triage", selectedFinding?.id ?? ""],
    enabled: Boolean(selectedFinding?.id && findingOpen),
    queryFn: async () => {
      const res = await apiFetch(
        `/api/asv/findings/${encodeURIComponent(selectedFinding!.id)}/ai/triage`,
        { cache: "no-store" }
      );
      const body = (await res.json()) as { item?: any; message?: string };
      if (!res.ok) throw new Error(body.message ?? `ai triage (${res.status})`);
      return body.item ?? null;
    },
    staleTime: 5_000,
    refetchInterval: () => {
      if (!findingOpen || !selectedFinding?.id) return false;
      if (!triagePollUntilMs) return false;
      if (Date.now() > triagePollUntilMs) return false;
      return 2000;
    }
  });

  useEffect(() => {
    if (triageQuery.data && triagePollUntilMs) setTriagePollUntilMs(0);
  }, [triageQuery.data, triagePollUntilMs]);

  const findingEndpoint = useMemo(() => {
    if (!selectedFinding) return null;
    return getFindingEndpointKey(selectedFinding);
  }, [selectedFinding]);

  const nucleiCmd = useMemo(() => {
    if (!selectedFinding) return null;
    const endpoint = getFindingEndpointKey(selectedFinding);
    if (!endpoint) return null;
    const tags = (nucleiCfg.tags ?? []).filter(Boolean);
    const sev = (nucleiCfg.severity ?? []).filter(Boolean);
    const rate = nucleiRate;
    const rps = Math.max(1, Math.min(200, Math.ceil(rate / 60)));
    const parts = [
      "nuclei",
      "-jsonl",
      "-u",
      JSON.stringify(endpoint),
      ...(tags.length ? ["-tags", JSON.stringify(tags.join(","))] : []),
      ...(sev.length ? ["-severity", JSON.stringify(sev.join(","))] : []),
      "-rl",
      String(rps)
    ];
    // Render without quotes artifacts from JSON.stringify for terminal copy safety.
    return parts
      .join(" ")
      .replaceAll("\"", "");
  }, [selectedFinding, nucleiCfg.tags, nucleiCfg.severity, nucleiRate]);

  const latestRunId = useMemo(() => (runs.length ? runs[0]!.id : null), [runs]);

  const nucleiArtifacts = useMemo(() => {
    const byKind = new Map<string, AsvArtifact>();
    for (const a of artifacts) byKind.set(a.kind, a);
    return {
      stderr: byKind.get("nuclei.stderr") ?? null,
      stdout: byKind.get("nuclei.stdout") ?? null,
      jsonl: byKind.get("nuclei.jsonl") ?? null
    };
  }, [artifacts]);

  const nucleiStderrDiagQuery = useQuery({
    queryKey: ["asv", "artifact", "nuclei.stderr", latestRunId, nucleiArtifacts.stderr?.id ?? ""],
    enabled: Boolean(latestRunId && nucleiArtifacts.stderr?.id),
    queryFn: async () => {
      const res = await apiFetch(
        `/api/asv/scan-runs/${encodeURIComponent(latestRunId!)}/artifacts/${encodeURIComponent(nucleiArtifacts.stderr!.id)}`,
        { cache: "no-store" }
      );
      const body = (await res.json()) as { content_text?: string | null; message?: string };
      if (!res.ok) throw new Error(body.message ?? `artifact nuclei.stderr (${res.status})`);
      const text = body.content_text ?? "";
      return { text, diag: parseNucleiDiag(text) };
    },
    staleTime: 10_000
  });

  const artifactQuery = useQuery({
    queryKey: ["asv", "artifact", latestRunId, artifactId],
    enabled: artifactOpen && latestRunId != null && artifactId != null,
    queryFn: async () => {
      const res = await apiFetch(
        `/api/asv/scan-runs/${encodeURIComponent(latestRunId!)}/artifacts/${encodeURIComponent(artifactId!)}`,
        { cache: "no-store" }
      );
      const body = (await res.json()) as { content_text?: string; message?: string };
      if (!res.ok) throw new Error(body.message ?? `artifact (${res.status})`);
      return body as AsvArtifactFull;
    },
    staleTime: 30_000
  });

  const severityBadge = (sev: string) => {
    const s = (sev || "info").toLowerCase();
    const base = "inline-flex items-center rounded-lg border px-2 py-0.5 text-[11px] font-medium";
    if (s === "critical")
      return `${base} border-rose-200 bg-rose-50 text-rose-800 dark:border-rose-900/40 dark:bg-rose-950/30 dark:text-rose-200`;
    if (s === "high")
      return `${base} border-orange-200 bg-orange-50 text-orange-800 dark:border-orange-900/40 dark:bg-orange-950/30 dark:text-orange-200`;
    if (s === "medium")
      return `${base} border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-900/40 dark:bg-amber-950/30 dark:text-amber-200`;
    if (s === "low")
      return `${base} border-sky-200 bg-sky-50 text-sky-800 dark:border-sky-900/40 dark:bg-sky-950/30 dark:text-sky-200`;
    return `${base} border-slate-200 bg-slate-50 text-slate-700 dark:border-border dark:bg-black/30 dark:text-slate-200`;
  };

  const priorityBadge = (p: string) => {
    const v = (p || "").toLowerCase();
    const base = "inline-flex items-center rounded-lg border px-2 py-0.5 text-[11px] font-medium";
    if (v === "p0")
      return `${base} border-rose-200 bg-rose-50 text-rose-800 dark:border-rose-900/40 dark:bg-rose-950/30 dark:text-rose-200`;
    if (v === "p1")
      return `${base} border-orange-200 bg-orange-50 text-orange-800 dark:border-orange-900/40 dark:bg-orange-950/30 dark:text-orange-200`;
    if (v === "p2")
      return `${base} border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-900/40 dark:bg-amber-950/30 dark:text-amber-200`;
    return `${base} border-slate-200 bg-slate-50 text-slate-700 dark:border-border dark:bg-black/30 dark:text-slate-200`;
  };

  const confidenceBadge = (c: string) => {
    const v = (c || "").toLowerCase();
    const base = "inline-flex items-center rounded-lg border px-2 py-0.5 text-[11px] font-medium";
    if (v === "high")
      return `${base} border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-900/40 dark:bg-emerald-950/30 dark:text-emerald-200`;
    if (v === "medium")
      return `${base} border-sky-200 bg-sky-50 text-sky-900 dark:border-sky-900/40 dark:bg-sky-950/30 dark:text-sky-200`;
    return `${base} border-slate-200 bg-slate-50 text-slate-700 dark:border-border dark:bg-black/30 dark:text-slate-200`;
  };

  const templateQuery = useQuery({
    queryKey: ["asv", "nuclei", "template", templateId],
    enabled: templateId != null && templateOpen,
    queryFn: async () => {
      const res = await apiFetch(`/api/asv/nuclei/templates/${encodeURIComponent(templateId!)}`, { cache: "no-store" });
      const body = (await res.json()) as Partial<AsvNucleiTemplate> & { message?: string };
      if (!res.ok) throw new Error(body.message ?? `template (${res.status})`);
      return body as AsvNucleiTemplate;
    },
    staleTime: 30_000
  });

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Radar className="h-4 w-4 text-fg/80" />
            <div className="text-sm font-semibold tracking-tight">ASV Scanner</div>
          </div>
          <div className="mt-1 text-xs text-muted">
            Активы → запуск сканов → история. Движок сканирования подключим следующим шагом (очередь + воркер).
          </div>
        </div>
        <button
          type="button"
          onClick={() => void assetsQuery.refetch()}
          className={cn(
            "inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-xs",
            "border-slate-200 bg-white hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
          )}
        >
          <RefreshCw className={cn("h-4 w-4", assetsQuery.isFetching ? "animate-spin" : "")} />
          Обновить
        </button>
      </div>

      {err ? (
        <div className="rounded-xl border border-rose-200 bg-rose-50 p-3 text-xs text-rose-800 dark:border-rose-900/40 dark:bg-rose-950/30 dark:text-rose-200">
          {err}
        </div>
      ) : null}

      <div className="grid grid-cols-12 gap-5">
        <section className="col-span-12 lg:col-span-4">
          <div className="rounded-2xl border border-slate-200 bg-white/70 p-4 backdrop-blur dark:border-border dark:bg-black/20">
            <div className="text-xs font-medium">Assets</div>
            <div className="mt-3 flex gap-2">
              <select
                value={type}
                onChange={(e) => setType(e.target.value as AssetType)}
                className="h-9 w-[110px] rounded-xl border border-slate-200 bg-white px-2 text-xs dark:border-border dark:bg-black/20"
              >
                <option value="domain">domain</option>
                <option value="ip">ip</option>
                <option value="cidr">cidr</option>
                <option value="url">url</option>
              </select>
              <input
                value={key}
                onChange={(e) => setKey(e.target.value)}
                placeholder={type === "url" ? "https://example.com" : type === "domain" ? "example.com" : "1.2.3.4"}
                className="h-9 min-w-0 flex-1 rounded-xl border border-slate-200 bg-white px-3 text-xs dark:border-border dark:bg-black/20"
              />
              <button
                type="button"
                onClick={() => void createAsset()}
                disabled={busy || !key.trim()}
                className={cn(
                  "inline-flex h-9 items-center gap-2 rounded-xl border px-3 text-xs",
                  "border-slate-200 bg-slate-50 hover:bg-slate-100 disabled:opacity-50 dark:border-border dark:bg-black/30 dark:hover:bg-black/40"
                )}
                title="Добавить актив"
              >
                <Plus className="h-4 w-4" />
              </button>
            </div>

            <div className="mt-3 max-h-[520px] overflow-auto pr-1">
              {assetsQuery.isLoading ? (
                <div className="flex items-center gap-2 py-3 text-xs text-muted">
                  <Loader2 className="h-4 w-4 animate-spin" /> загрузка…
                </div>
              ) : assets.length === 0 ? (
                <div className="py-3 text-xs text-muted">Пока нет активов. Добавь домен/IP/CIDR/URL выше.</div>
              ) : (
                <div className="space-y-2">
                  {assets.map((a) => (
                    <button
                      key={a.id}
                      type="button"
                      onClick={() => setSelected(a.id)}
                      className={cn(
                        "w-full rounded-xl border p-3 text-left text-xs",
                        selected === a.id
                          ? "border-accent/40 bg-accent/10"
                          : "border-slate-200 bg-white hover:bg-slate-50 dark:border-border dark:bg-black/10 dark:hover:bg-black/20"
                      )}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <div className="truncate font-medium text-fg/90">{a.display_name}</div>
                          <div className="mt-1 truncate text-[11px] text-muted">
                            {a.asset_type} • updated {fmtTs(a.updated_at)}
                          </div>
                        </div>
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>

            <div className="mt-4 rounded-xl border border-slate-200/90 bg-slate-50 p-3 text-[11px] text-muted dark:border-white/[0.06] dark:bg-black/20">
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-[11px] font-medium text-fg/80">Allowlist</div>
                  <div className="mt-0.5 text-[11px]">
                    Standard‑режим доступен только для allowlist активов (ручное включение).
                  </div>
                </div>
                <button
                  type="button"
                  disabled={!selectedAsset || busy}
                  onClick={() => void toggleAllowStandard(!allowStandard)}
                  className={cn(
                    "inline-flex items-center rounded-xl border px-3 py-2 text-xs",
                    allowStandard
                      ? "border-emerald-200 bg-emerald-50 text-emerald-900 hover:bg-emerald-100 dark:border-emerald-900/40 dark:bg-emerald-950/30 dark:text-emerald-200"
                      : "border-slate-200 bg-white text-fg/85 hover:bg-slate-50 dark:border-border dark:bg-black/20"
                  )}
                  title={selectedAsset ? "Переключить allowlist для выбранного актива" : "Выбери актив"}
                >
                  {allowStandard ? "Allowlisted" : "Not allowlisted"}
                </button>
              </div>

              <div className="mt-3 flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-[11px] font-medium text-fg/80">CIDR expansion</div>
                  <div className="mt-0.5 text-[11px]">Лимит хостов (hard cap 256). Работает только для allowlisted.</div>
                </div>
                <input
                  type="number"
                  min={1}
                  max={256}
                  value={maxHosts}
                  disabled={!selectedAsset || busy}
                  onChange={(e) => void updateMaxHosts(Number(e.target.value))}
                  className="h-9 w-[96px] rounded-xl border border-slate-200 bg-white px-3 text-xs disabled:opacity-60 dark:border-border dark:bg-black/20"
                  title="Максимум адресов из CIDR"
                />
              </div>
            </div>
          </div>
        </section>

        <section className="col-span-12 lg:col-span-8">
          <div className="mb-4 flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setActiveTab("overview")}
              className={cn(
                "rounded-xl border px-3 py-2 text-xs",
                activeTab === "overview"
                  ? "border-accent/40 bg-accent/10"
                  : "border-slate-200 bg-white hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
              )}
            >
              Обзор
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("endpoints")}
              className={cn(
                "rounded-xl border px-3 py-2 text-xs",
                activeTab === "endpoints"
                  ? "border-accent/40 bg-accent/10"
                  : "border-slate-200 bg-white hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
              )}
            >
              Эндпоинты
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("issues")}
              className={cn(
                "rounded-xl border px-3 py-2 text-xs",
                activeTab === "issues"
                  ? "border-accent/40 bg-accent/10"
                  : "border-slate-200 bg-white hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
              )}
            >
              Проблемы
            </button>
          </div>

          {activeTab === "endpoints" ? (
            <div className="rounded-2xl border border-slate-200 bg-white/70 p-4 backdrop-blur dark:border-border dark:bg-black/20">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-xs font-medium">Эндпоинты</div>
                  <div className="mt-1 text-[11px] text-muted">HTTP endpoints + найденные проблемы по URL.</div>
                </div>
                <button
                  type="button"
                  onClick={() => void inventoryQuery.refetch()}
                  disabled={!selectedAsset}
                  className={cn(
                    "inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-xs",
                    "border-slate-200 bg-white hover:bg-slate-50 disabled:opacity-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                  )}
                >
                  <RefreshCw className={cn("h-4 w-4", inventoryQuery.isFetching ? "animate-spin" : "")} />
                  Обновить
                </button>
              </div>

              <div className="mt-3 space-y-2">
                {endpointRows.length === 0 ? (
                  <div className="py-3 text-xs text-muted">Пока нет HTTP endpoints. Запусти скан.</div>
                ) : (
                  endpointRows.slice(0, 80).map((e) => (
                    <div
                      key={`${e.url}:${e.status ?? "?"}`}
                      className="rounded-xl border border-slate-200 bg-white p-3 text-xs dark:border-border dark:bg-black/10"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="truncate font-medium text-fg/90">{e.url}</div>
                          <div className="mt-1 text-[11px] text-muted">
                            {e.status ?? "—"} • {e.server ?? "—"} {e.title ? `• ${e.title}` : ""} •{" "}
                            <span className={severityBadge(e.topSeverity)}>{e.topSeverity}</span>
                            <span className="ml-2 tabular-nums">{e.findings} findings</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <a
                            href={e.url}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-fg/80 hover:bg-slate-100 dark:border-border dark:bg-black/30 dark:hover:bg-black/40"
                          >
                            Открыть <ExternalLink className="h-3 w-3" />
                          </a>
                          <button
                            type="button"
                            onClick={() => {
                              setFindingQ(e.url);
                              setToolFilter("");
                              setSevFilter("");
                              setGroupByEndpoint(true);
                              setActiveTab("overview");
                            }}
                            className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-fg/80 hover:bg-slate-100 dark:border-border dark:bg-black/30 dark:hover:bg-black/40"
                            title="Показать findings для этого URL"
                          >
                            В findings
                          </button>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          ) : null}

          {activeTab === "overview" ? (
          <div className="rounded-2xl border border-slate-200 bg-white/70 p-4 backdrop-blur dark:border-border dark:bg-black/20">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <div className="text-xs font-medium">Запуски скана</div>
                <div className="mt-1 text-[11px] text-muted">
                  {selectedAsset ? (
                    <span className="truncate">
                      Актив: <span className="text-fg/85">{selectedAsset.display_name}</span>
                    </span>
                  ) : (
                    "Выбери актив слева."
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <select
                  value={profileId ?? ""}
                  onChange={(e) => setProfileId(e.target.value || null)}
                  disabled={!selectedAsset || profiles.length === 0}
                  className="h-9 rounded-xl border border-slate-200 bg-white px-2 text-xs disabled:opacity-60 dark:border-border dark:bg-black/20"
                  title={allowStandard ? "Профиль скана" : "Standard доступен только для allowlist активов"}
                >
                  {profiles.map((p) => (
                    <option key={p.id} value={p.id} disabled={p.mode === "standard" && !allowStandard}>
                      {p.name} ({p.mode})
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  onClick={() => void startScan()}
                  disabled={!selectedAsset || busy || !profileId}
                  className={cn(
                    "inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-xs",
                    "border-slate-200 bg-slate-50 hover:bg-slate-100 disabled:opacity-50 dark:border-border dark:bg-black/30 dark:hover:bg-black/40"
                  )}
                  title="Поставить скан в очередь"
                >
                  <Play className="h-4 w-4" />
                  Запустить скан
                </button>
                <button
                  type="button"
                  onClick={() => void runsQuery.refetch()}
                  disabled={!selectedAsset}
                  className={cn(
                    "inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-xs",
                    "border-slate-200 bg-white hover:bg-slate-50 disabled:opacity-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                  )}
                >
                  <RefreshCw className={cn("h-4 w-4", runsQuery.isFetching ? "animate-spin" : "")} />
                  Обновить
                </button>
              </div>
            </div>

            <div className="mt-4 space-y-2">
              {!selectedAsset ? null : runsQuery.isLoading ? (
                <div className="flex items-center gap-2 py-3 text-xs text-muted">
                  <Loader2 className="h-4 w-4 animate-spin" /> загрузка…
                </div>
              ) : runs.length === 0 ? (
                <div className="py-3 text-xs text-muted">Запусков пока нет. Нажми “Запустить скан”.</div>
              ) : (
                runs.map((r) => (
                  <div
                    key={r.id}
                    className="rounded-xl border border-slate-200 bg-white p-3 text-xs dark:border-border dark:bg-black/10"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="font-medium text-fg/90">Запуск {r.id.slice(0, 8)}</div>
                        <div className="mt-1 text-[11px] text-muted">
                          статус: <span className="text-fg/80">{r.status}</span>
                          {" • "}
                          режим: <span className="text-fg/80">{r.scan_mode ?? "safe"}</span>
                          {" • "}
                          в очереди {fmtTs(r.created_at)}
                        </div>
                        {r.error ? <div className="mt-2 text-[11px] text-rose-700">{r.error}</div> : null}
                      </div>
                      <a
                        className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-fg/80 hover:bg-slate-100 dark:border-border dark:bg-black/30 dark:hover:bg-black/40"
                        href="#"
                        onClick={(e) => e.preventDefault()}
                        title="Детали запуска появятся в следующем шаге"
                      >
                        Детали <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                  </div>
                ))
              )}
            </div>

            <div className="mt-5 rounded-xl border border-slate-200/90 bg-slate-50 p-3 text-[11px] text-muted dark:border-white/[0.06] dark:bg-black/20">
              Следующий шаг: подключаем воркер (очередь) и складываем результаты (hosts/services/http tech + nuclei
              findings) в `asv_finding` с дедупом по fingerprint.
            </div>
          </div>
          ) : null}

          {activeTab === "issues" ? (
            <div className="rounded-2xl border border-slate-200 bg-white/70 p-4 backdrop-blur dark:border-border dark:bg-black/20">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-xs font-medium">Проблемы</div>
                  <div className="mt-1 text-[11px] text-muted">
                    Аггрегированные проблемы (dedup поверх findings) + базовые рекомендации по фиксу.
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => void issuesQuery.refetch()}
                  disabled={!selectedAsset}
                  className={cn(
                    "inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-xs",
                    "border-slate-200 bg-white hover:bg-slate-50 disabled:opacity-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                  )}
                >
                  <RefreshCw className={cn("h-4 w-4", issuesQuery.isFetching ? "animate-spin" : "")} />
                  Обновить
                </button>
              </div>

              <div className="mt-4 rounded-xl border border-slate-200 bg-white p-3 text-xs dark:border-border dark:bg-black/10">
                <div className="text-[11px] font-medium text-fg/80">Сравнить запуски</div>
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <select
                    value={diffFrom}
                    onChange={(e) => setDiffFrom(e.target.value)}
                    disabled={!selectedAsset}
                    className="h-9 rounded-xl border border-slate-200 bg-white px-2 text-xs disabled:opacity-60 dark:border-border dark:bg-black/20"
                    title="From scan run"
                  >
                    <option value="">from…</option>
                    {runs.map((r) => (
                      <option key={r.id} value={r.id}>
                        {r.created_at ? new Date(r.created_at).toLocaleString() : r.id.slice(0, 8)} ({r.status})
                      </option>
                    ))}
                  </select>
                  <select
                    value={diffTo}
                    onChange={(e) => setDiffTo(e.target.value)}
                    disabled={!selectedAsset}
                    className="h-9 rounded-xl border border-slate-200 bg-white px-2 text-xs disabled:opacity-60 dark:border-border dark:bg-black/20"
                    title="To scan run"
                  >
                    <option value="">to…</option>
                    {runs.map((r) => (
                      <option key={r.id} value={r.id}>
                        {r.created_at ? new Date(r.created_at).toLocaleString() : r.id.slice(0, 8)} ({r.status})
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    onClick={() => void diffQuery.refetch()}
                    disabled={!diffFrom || !diffTo}
                    className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs hover:bg-slate-100 disabled:opacity-50 dark:border-border dark:bg-black/30 dark:hover:bg-black/40"
                  >
                    {diffQuery.isFetching ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
                    Сравнить
                  </button>
                </div>
                {diffQuery.isError ? (
                  <div className="mt-2 text-[11px] text-red-600">{(diffQuery.error as Error).message}</div>
                ) : diffQuery.data ? (
                  <div className="mt-2 text-[11px] text-muted">
                    Добавлено: <span className="tabular-nums text-fg/80">{diffQuery.data.added?.length ?? 0}</span> • Решено:{" "}
                    <span className="tabular-nums text-fg/80">{diffQuery.data.resolved?.length ?? 0}</span> • Изменилось:{" "}
                    <span className="tabular-nums text-fg/80">{diffQuery.data.changed?.length ?? 0}</span>
                  </div>
                ) : null}
              </div>

              <div className="mt-3 space-y-2">
                {!selectedAsset ? null : issuesQuery.isLoading ? (
                  <div className="py-3 text-xs text-muted">Загружаю issues…</div>
                ) : issuesQuery.isError ? (
                  <div className="py-3 text-xs text-red-600">{(issuesQuery.error as Error).message}</div>
                ) : issues.length === 0 ? (
                  <div className="py-3 text-xs text-muted">Пока нет issues. Запусти скан.</div>
                ) : (
                  issues.slice(0, 120).map((it) => {
                    const fg =
                      it.fix_guidance && typeof it.fix_guidance === "object"
                        ? (it.fix_guidance as Record<string, unknown>)
                        : null;
                    const summary = typeof fg?.summary === "string" ? fg.summary : null;
                    const fix = typeof fg?.fix === "string" ? fg.fix : null;
                    const verify = typeof fg?.verify === "string" ? fg.verify : null;
                    const endpoint = typeof it.endpoint_key === "string" ? it.endpoint_key : null;
                    return (
                      <div
                        key={it.id}
                        className="rounded-xl border border-slate-200 bg-white p-3 text-xs dark:border-border dark:bg-black/10"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className={severityBadge(it.severity)}>{it.severity}</span>
                              <span className="truncate font-medium text-fg/90">{it.title}</span>
                            </div>
                            <div className="mt-1 text-[11px] text-muted">
                              {it.tool}
                              {it.external_id ? ` • ${it.external_id}` : ""} • last: {fmtTs(it.last_seen)} •{" "}
                              <span className="tabular-nums">{it.occurrences}</span>x
                            </div>
                            {endpoint ? (
                              <div className="mt-1 truncate text-[11px] text-muted">Endpoint: {endpoint}</div>
                            ) : null}
                            {summary ? <div className="mt-2 text-[11px] text-fg/80">{summary}</div> : null}
                            {fix ? <div className="mt-1 text-[11px] text-fg/80">Fix: {fix}</div> : null}
                            {verify ? <div className="mt-1 text-[11px] text-fg/70">Verify: {verify}</div> : null}
                          </div>
                          <div className="flex shrink-0 flex-col gap-2">
                            <button
                              type="button"
                              onClick={() => {
                                setIssueAiId(it.id);
                                setIssueAiOpen(true);
                              }}
                              className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-fg/80 hover:bg-slate-100 dark:border-border dark:bg-black/30 dark:hover:bg-black/40"
                              title="AI приоритизация"
                            >
                              AI <span className="font-mono">prio</span>
                            </button>
                            {endpoint ? (
                              <a
                                href={endpoint}
                                target="_blank"
                                rel="noreferrer"
                                className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-fg/80 hover:bg-slate-100 dark:border-border dark:bg-black/30 dark:hover:bg-black/40"
                              >
                                Открыть <ExternalLink className="h-3 w-3" />
                              </a>
                            ) : null}
                            <button
                              type="button"
                              onClick={() => {
                                const text = [
                                  `Issue: ${it.title}`,
                                  `Severity: ${it.severity}`,
                                  endpoint ? `Endpoint: ${endpoint}` : null,
                                  summary ? `Summary: ${summary}` : null,
                                  fix ? `Fix: ${fix}` : null,
                                  verify ? `Verify: ${verify}` : null
                                ]
                                  .filter(Boolean)
                                  .join("\n");
                                void copyText(text);
                              }}
                              className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-fg/80 hover:bg-slate-100 dark:border-border dark:bg-black/30 dark:hover:bg-black/40"
                              title="Скопировать рекомендации"
                            >
                              Копировать <Copy className="h-3 w-3" />
                            </button>
                            {endpoint ? (
                              <button
                                type="button"
                                onClick={() => {
                                  setFindingQ(endpoint);
                                  setToolFilter("");
                                  setSevFilter("");
                                  setGroupByEndpoint(true);
                                  setActiveTab("overview");
                                }}
                                className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-fg/80 hover:bg-slate-100 dark:border-border dark:bg-black/30 dark:hover:bg-black/40"
                                title="Показать findings для этого эндпоинта"
                              >
                                В findings
                              </button>
                            ) : null}
                          </div>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          ) : null}

          <div className="mt-5 rounded-2xl border border-slate-200 bg-white/70 p-4 backdrop-blur dark:border-border dark:bg-black/20">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="text-xs font-medium">Инвентарь</div>
                <div className="mt-1 text-[11px] text-muted">Сводка: порты/HTTP/Findings по severity.</div>
              </div>
              <button
                type="button"
                onClick={() => void inventoryQuery.refetch()}
                disabled={!selectedAsset}
                className={cn(
                  "inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-xs",
                  "border-slate-200 bg-white hover:bg-slate-50 disabled:opacity-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                )}
              >
                <RefreshCw className={cn("h-4 w-4", inventoryQuery.isFetching ? "animate-spin" : "")} />
                Обновить
              </button>
            </div>

            {!selectedAsset ? null : inventoryQuery.isLoading ? (
              <div className="mt-3 flex items-center gap-2 text-xs text-muted">
                <Loader2 className="h-4 w-4 animate-spin" /> загрузка…
              </div>
            ) : inventory ? (
              <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
                <div className="rounded-xl border border-slate-200 bg-white p-3 text-xs dark:border-border dark:bg-black/10">
                  <div className="text-[11px] text-muted">Открытые порты (по порту/состоянию)</div>
                  <div className="mt-2 max-h-40 space-y-1 overflow-auto pr-1">
                    {inventory.ports.length ? (
                      inventory.ports.slice(0, 40).map((p) => (
                        <div key={`${p.port}:${p.state}`} className="flex items-center justify-between gap-3">
                          <div className="font-mono text-[11px] text-fg/85">
                            {p.port}/{p.state}
                          </div>
                          <div className="tabular-nums text-muted">{p.n}</div>
                        </div>
                      ))
                    ) : (
                      <div className="text-muted">—</div>
                    )}
                  </div>
                </div>
                <div className="rounded-xl border border-slate-200 bg-white p-3 text-xs dark:border-border dark:bg-black/10">
                  <div className="text-[11px] text-muted">HTTP эндпоинты (последние)</div>
                  <div className="mt-2 max-h-40 space-y-2 overflow-auto pr-1">
                    {inventory.http.length ? (
                      inventory.http.slice(0, 12).map((h) => (
                        <div key={`${h.url}:${h.status ?? "?"}`} className="min-w-0">
                          <div className="truncate font-medium text-fg/90">{h.url}</div>
                          <div className="mt-0.5 truncate text-[11px] text-muted">
                            {h.status ?? "—"} • {h.server ?? "—"} {h.title ? `• ${h.title}` : ""}
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="text-muted">—</div>
                    )}
                  </div>
                </div>
                <div className="rounded-xl border border-slate-200 bg-white p-3 text-xs dark:border-border dark:bg-black/10">
                  <div className="text-[11px] text-muted">Нахождения (tool × severity)</div>
                  <div className="mt-2 max-h-40 space-y-1 overflow-auto pr-1">
                    {inventory.findingCounts.length ? (
                      inventory.findingCounts.map((c) => (
                        <div key={`${c.tool}:${c.severity}`} className="flex items-center justify-between gap-3">
                          <div className="truncate text-[11px] text-fg/85">
                            {c.tool} • {c.severity}
                          </div>
                          <div className="tabular-nums text-muted">{c.n}</div>
                        </div>
                      ))
                    ) : (
                      <div className="text-muted">—</div>
                    )}
                  </div>
                </div>
              </div>
            ) : inventoryQuery.isError ? (
              <div className="mt-3 rounded-xl border border-rose-200 bg-rose-50 p-3 text-xs text-rose-800 dark:border-rose-900/40 dark:bg-rose-950/30 dark:text-rose-200">
                {(inventoryQuery.error as Error).message}
              </div>
            ) : null}
          </div>

          <div className="mt-5 grid grid-cols-1 gap-5 lg:grid-cols-2">
            <div className="rounded-2xl border border-slate-200 bg-white/70 p-4 backdrop-blur dark:border-border dark:bg-black/20">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-xs font-medium">Порты</div>
                  <div className="mt-1 text-[11px] text-muted">Результаты tcp‑проб (safe).</div>
                </div>
                <button
                  type="button"
                  onClick={() => void portsQuery.refetch()}
                  disabled={!selectedAsset}
                  className={cn(
                    "inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-xs",
                    "border-slate-200 bg-white hover:bg-slate-50 disabled:opacity-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                  )}
                >
                  <RefreshCw className={cn("h-4 w-4", portsQuery.isFetching ? "animate-spin" : "")} />
                  Обновить
                </button>
              </div>
              <div className="mt-3 space-y-2">
                {!selectedAsset ? null : portsQuery.isLoading ? (
                  <div className="flex items-center gap-2 py-3 text-xs text-muted">
                    <Loader2 className="h-4 w-4 animate-spin" /> загрузка…
                  </div>
                ) : ports.length === 0 ? (
                  <div className="py-3 text-xs text-muted">Пока нет данных. Запусти скан.</div>
                ) : (
                  ports.slice(0, 40).map((p) => (
                    <div
                      key={p.id}
                      className="flex items-start justify-between gap-3 rounded-xl border border-slate-200 bg-white p-3 text-xs dark:border-border dark:bg-black/10"
                    >
                      <div className="min-w-0">
                        <div className="font-medium text-fg/90">
                          {p.target}
                          {p.ip ? <span className="ml-2 font-mono text-[10px] text-muted/80">{p.ip}</span> : null}
                        </div>
                        <div className="mt-1 text-[11px] text-muted">
                          tcp/{p.port} • {p.state} • {p.latency_ms != null ? `${p.latency_ms}ms` : "—"}
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="rounded-2xl border border-slate-200 bg-white/70 p-4 backdrop-blur dark:border-border dark:bg-black/20">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-xs font-medium">HTTP</div>
                  <div className="mt-1 text-[11px] text-muted">Снапшоты статуса/заголовка/Server.</div>
                </div>
                <button
                  type="button"
                  onClick={() => void httpQuery.refetch()}
                  disabled={!selectedAsset}
                  className={cn(
                    "inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-xs",
                    "border-slate-200 bg-white hover:bg-slate-50 disabled:opacity-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                  )}
                >
                  <RefreshCw className={cn("h-4 w-4", httpQuery.isFetching ? "animate-spin" : "")} />
                  Обновить
                </button>
              </div>
              <div className="mt-3 space-y-2">
                {!selectedAsset ? null : httpQuery.isLoading ? (
                  <div className="flex items-center gap-2 py-3 text-xs text-muted">
                    <Loader2 className="h-4 w-4 animate-spin" /> загрузка…
                  </div>
                ) : httpObs.length === 0 ? (
                  <div className="py-3 text-xs text-muted">Пока нет данных. Запусти скан.</div>
                ) : (
                  httpObs.slice(0, 30).map((h) => (
                    <div
                      key={h.id}
                      className="rounded-xl border border-slate-200 bg-white p-3 text-xs dark:border-border dark:bg-black/10"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="truncate font-medium text-fg/90">{h.url}</div>
                          <div className="mt-1 text-[11px] text-muted">
                            {h.status ?? "—"} • {h.server ?? "—"} • {fmtTs(h.observed_at)}
                          </div>
                          {h.title ? <div className="mt-1 truncate text-[11px] text-fg/75">{h.title}</div> : null}
                        </div>
                        <a
                          className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-fg/80 hover:bg-slate-100 dark:border-border dark:bg-black/30 dark:hover:bg-black/40"
                          href={h.final_url || h.url}
                          target="_blank"
                          rel="noreferrer"
                          title="Открыть в новой вкладке"
                        >
                          Открыть <ExternalLink className="h-3 w-3" />
                        </a>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          <div className="mt-5 rounded-2xl border border-slate-200 bg-white/70 p-4 backdrop-blur dark:border-border dark:bg-black/20">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="text-xs font-medium">Нахождения</div>
                <div className="mt-1 text-[11px] text-muted">Дедуп по fingerprint, сортировка по last_seen.</div>
              </div>
              <button
                type="button"
                onClick={() => void findingsQuery.refetch()}
                disabled={!selectedAsset}
                className={cn(
                  "inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-xs",
                  "border-slate-200 bg-white hover:bg-slate-50 disabled:opacity-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                )}
              >
                <RefreshCw className={cn("h-4 w-4", findingsQuery.isFetching ? "animate-spin" : "")} />
                Обновить
              </button>
            </div>

            <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-3">
              <input
                value={findingQ}
                onChange={(e) => setFindingQ(e.target.value)}
                placeholder="поиск: title/template/fingerprint…"
                className="h-9 rounded-xl border border-slate-200 bg-white px-3 text-xs dark:border-border dark:bg-black/20"
              />
              <select
                value={toolFilter}
                onChange={(e) => setToolFilter(e.target.value)}
                className="h-9 rounded-xl border border-slate-200 bg-white px-2 text-xs dark:border-border dark:bg-black/20"
              >
                <option value="">all tools</option>
                {tools.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
              <select
                value={sevFilter}
                onChange={(e) => setSevFilter(e.target.value)}
                className="h-9 rounded-xl border border-slate-200 bg-white px-2 text-xs dark:border-border dark:bg-black/20"
              >
                <option value="">all severity</option>
                {severities.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </div>

            <div className="mt-2 flex items-center justify-between">
              <button
                type="button"
                onClick={() => setGroupByEndpoint((v) => !v)}
                className={cn(
                  "rounded-xl border px-3 py-2 text-xs",
                  groupByEndpoint
                    ? "border-accent/40 bg-accent/10"
                    : "border-slate-200 bg-white hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                )}
              >
                {groupByEndpoint ? "Группировать по эндпоинту" : "Плоский список"}
              </button>
              <div className="text-[11px] text-muted tabular-nums">{findingsFiltered.length} items</div>
            </div>

            <div className="mt-3 space-y-2">
              {!selectedAsset ? null : findingsQuery.isLoading ? (
                <div className="flex items-center gap-2 py-3 text-xs text-muted">
                  <Loader2 className="h-4 w-4 animate-spin" /> загрузка…
                </div>
              ) : findingsFiltered.length === 0 ? (
                <div className="py-3 text-xs text-muted">Пока нет findings. Запусти скан выше.</div>
              ) : groupByEndpoint && findingsGrouped ? (
                findingsGrouped.map(([key, items]) => (
                  <div key={key} className="rounded-2xl border border-slate-200 bg-white/50 p-3 dark:border-border dark:bg-black/10">
                    <div className="flex items-center justify-between gap-3">
                      <div className="truncate text-xs font-medium text-fg/85">{key}</div>
                      <div className="text-[11px] text-muted tabular-nums">{items.length}</div>
                    </div>
                    <div className="mt-2 space-y-2">
                      {items.map((f) => (
                        <button
                          key={f.id}
                          type="button"
                          onClick={() => {
                            setFindingId(f.id);
                            setFindingOpen(true);
                          }}
                          className="w-full rounded-xl border border-slate-200 bg-white p-3 text-left text-xs hover:bg-slate-50 dark:border-border dark:bg-black/10 dark:hover:bg-black/20"
                        >
                          <div className="truncate font-medium text-fg/90">{f.title}</div>
                          <div className="mt-1 text-[11px] text-muted">
                            <span className={severityBadge(f.severity)}>{f.severity}</span>
                            <span className="ml-2">{f.tool}</span>
                            <span className="ml-2">last_seen {fmtTs(f.last_seen)}</span>
                          </div>
                        </button>
                      ))}
                    </div>
                  </div>
                ))
              ) : (
                findingsFiltered.map((f) => (
                  <div
                    key={f.id}
                    className="rounded-xl border border-slate-200 bg-white p-3 text-xs dark:border-border dark:bg-black/10"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div
                        role="button"
                        tabIndex={0}
                        onClick={() => {
                          setFindingId(f.id);
                          setFindingOpen(true);
                        }}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            setFindingId(f.id);
                            setFindingOpen(true);
                          }
                        }}
                        className="min-w-0 cursor-pointer text-left outline-none"
                      >
                        <div className="truncate font-medium text-fg/90">{f.title}</div>
                        <div className="mt-1 text-[11px] text-muted">
                          <span className={severityBadge(f.severity)}>{f.severity}</span>
                          <span className="ml-2">{f.tool}</span>
                          <span className="ml-2">last_seen {fmtTs(f.last_seen)}</span>
                        </div>
                        {f.tool === "nuclei" && f.external_id ? (
                          <div className="mt-1 text-[11px] text-muted">
                            template:{" "}
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                setTemplateId(f.external_id ?? null);
                                setTemplateOpen(true);
                              }}
                              className="rounded-md border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[10px] text-fg/80 hover:bg-slate-100 dark:border-border dark:bg-black/30 dark:hover:bg-black/40"
                              title="Открыть детали шаблона"
                            >
                              {f.external_id}
                            </button>
                            {(() => {
                              const t = nucleiTemplateMap.get(f.external_id ?? "");
                              return t?.name ? <span className="ml-2 text-fg/75">· {t.name}</span> : null;
                            })()}
                          </div>
                        ) : null}
                        <div className="mt-1 font-mono text-[10px] text-muted/80">{f.fingerprint}</div>
                      </div>
                      <button
                        type="button"
                        className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-fg/80 hover:bg-slate-100 dark:border-border dark:bg-black/30 dark:hover:bg-black/40"
                        onClick={() => {
                          const t = f.tool === "nuclei" && f.external_id ? nucleiTemplateMap.get(f.external_id) : undefined;
                          const blob = [
                            f.title,
                            f.external_id ?? "",
                            t?.name ?? "",
                            t?.description ?? "",
                            ...(t?.reference ?? []),
                            ...(t?.tags ?? [])
                          ]
                            .filter(Boolean)
                            .join("\n");
                          const m = blob.match(/CVE-\\d{4}-\\d{4,7}/i);
                          const cve = m?.[0]?.toUpperCase() ?? "";

                          const lines: string[] = [];
                          lines.push("## Metasploit (Docker)");
                          lines.push("Run interactive console:");
                          lines.push("docker run --rm -it metasploitframework/metasploit-framework msfconsole");
                          lines.push("");
                          lines.push("Inside msfconsole (search only, no auto-exploit):");
                          if (cve) lines.push(`search cve:${cve}`);
                          if (f.external_id) lines.push(`search ${f.external_id}`);
                          lines.push("search type:auxiliary name:scanner");
                          lines.push("");
                          lines.push("Context:");
                          if (cve) lines.push(`- ${cve}`);
                          if (f.external_id) lines.push(`- template: ${f.external_id}`);
                          if (t?.name) lines.push(`- ${t.name}`);

                          setMsfText(lines.join("\n"));
                          setMsfFindingId(f.id);
                          const hints = parseTargetHintsFromFinding(f);
                          setMsfOptRhosts(hints.rhosts ?? "");
                          setMsfOptRport(String(hints.rport ?? 443));
                          setMsfOptSsl(hints.ssl ?? true);
                          setMsfOptTargetUri(hints.targetUri ?? "/");
                          setMsfOptVhost(hints.vhost ?? "");
                          setMsfMode("safe");
                          setMsfAction("check");
                          setMsfModule("");
                          setMsfAck(false);
                          setMsfSelectedRunId(null);
                          setMsfOpen(true);
                        }}
                        title="Открыть Metasploit helper (docker)"
                      >
                        Metasploit <ExternalLink className="h-3 w-3" />
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="mt-5 rounded-2xl border border-slate-200 bg-white/70 p-4 backdrop-blur dark:border-border dark:bg-black/20">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="text-xs font-medium">Nuclei readiness</div>
                <div className="mt-1 text-[11px] text-muted">
                  Артефакты + конфиг профиля. Nuclei запускается, когда включён в профиле и выставлен `ASV_NUCLEI_ENABLED=1`.
                </div>
              </div>
              <button
                type="button"
                onClick={() => void artifactsQuery.refetch()}
                disabled={!selectedAsset}
                className={cn(
                  "inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-xs",
                  "border-slate-200 bg-white hover:bg-slate-50 disabled:opacity-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                )}
              >
                <RefreshCw className={cn("h-4 w-4", artifactsQuery.isFetching ? "animate-spin" : "")} />
                Артефакты
              </button>
            </div>

            <div className="mt-3 flex items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white p-3 text-xs dark:border-border dark:bg-black/10">
              <div className="min-w-0">
                <div className="font-medium text-fg/90">Nuclei</div>
                <div className="mt-1 text-[11px] text-muted">
                  Включение в профиле. Фактический запуск включается переменной окружения `ASV_NUCLEI_ENABLED=1`.
                </div>
                {nucleiArtifacts.stderr ? (
                  <div className="mt-2 text-[11px] text-muted tabular-nums">
                    last run artifacts:{" "}
                    <span className="font-mono">
                      stderr={nucleiArtifacts.stderr.bytes}B stdout={nucleiArtifacts.stdout?.bytes ?? 0}B jsonl=
                      {nucleiArtifacts.jsonl?.bytes ?? 0}B
                    </span>
                  </div>
                ) : (
                  <div className="mt-2 text-[11px] text-muted">Нет nuclei artifacts для последнего run.</div>
                )}
              </div>
              <button
                type="button"
                disabled={!selectedProfile || busy || (selectedProfile.mode === "standard" && !allowStandard)}
                onClick={() => void setNucleiEnabled(!nucleiEnabled)}
                className={cn(
                  "inline-flex items-center rounded-xl border px-3 py-2 text-xs",
                  nucleiEnabled
                    ? "border-emerald-200 bg-emerald-50 text-emerald-900 hover:bg-emerald-100 dark:border-emerald-900/40 dark:bg-emerald-950/30 dark:text-emerald-200"
                    : "border-slate-200 bg-white text-fg/85 hover:bg-slate-50 dark:border-border dark:bg-black/20"
                )}
                title={
                  selectedProfile?.mode === "standard" && !allowStandard
                    ? "Standard‑профиль требует allowlist актива"
                    : "Переключить nuclei.enabled в профиле"
                }
              >
                {nucleiEnabled ? "Enabled" : "Disabled"}
              </button>
            </div>

            {nucleiStderrDiagQuery.data?.diag ? (
              <div className="mt-3 rounded-xl border border-slate-200 bg-white p-3 text-xs dark:border-border dark:bg-black/10">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="text-[11px] font-medium text-fg/80">Diagnostics (from nuclei.stderr)</div>
                    <div className="mt-2 space-y-1 font-mono text-[11px] text-fg/85">
                      {nucleiStderrDiagQuery.data.diag.targets ? <div>{nucleiStderrDiagQuery.data.diag.targets}</div> : null}
                      {nucleiStderrDiagQuery.data.diag.techHints ? <div>{nucleiStderrDiagQuery.data.diag.techHints}</div> : null}
                      {nucleiStderrDiagQuery.data.diag.phases ? <div className="break-words">{nucleiStderrDiagQuery.data.diag.phases}</div> : null}
                    </div>
                    {nucleiArtifacts.jsonl && nucleiArtifacts.jsonl.bytes === 0 ? (
                      <div className="mt-2 text-[11px] text-muted">
                        `nuclei.jsonl` пустой → матчей не было или всё ушло в таймаут/ошибку (смотри stderr).
                      </div>
                    ) : null}
                  </div>
                  {nucleiArtifacts.stderr ? (
                    <button
                      type="button"
                      onClick={() => {
                        setArtifactId(nucleiArtifacts.stderr!.id);
                        setArtifactOpen(true);
                      }}
                      className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                      title="Открыть полный nuclei.stderr"
                    >
                      Открыть stderr
                    </button>
                  ) : null}
                </div>
              </div>
            ) : nucleiStderrDiagQuery.isLoading ? (
              <div className="mt-3 flex items-center gap-2 text-xs text-muted">
                <Loader2 className="h-4 w-4 animate-spin" /> читаю nuclei.stderr…
              </div>
            ) : null}

            <div className="mt-3 rounded-xl border border-slate-200 bg-white p-3 text-xs dark:border-border dark:bg-black/10">
              <div className="text-[11px] font-medium text-fg/80">Tuning</div>
              <div className="mt-2 grid grid-cols-1 gap-3 sm:grid-cols-3">
                <label className="space-y-1">
                  <div className="text-[11px] text-muted">tags (comma)</div>
                  <input
                    defaultValue={nucleiTagsText}
                    onBlur={(e) => {
                      const tags = e.target.value
                        .split(",")
                        .map((s) => s.trim())
                        .filter(Boolean)
                        .slice(0, 64);
                      void saveNucleiTuning({ tags });
                    }}
                    className="h-9 w-full rounded-xl border border-slate-200 bg-white px-3 text-xs dark:border-border dark:bg-black/20"
                    placeholder="cve, misconfiguration, exposed-panels"
                  />
                </label>
                <label className="space-y-1">
                  <div className="text-[11px] text-muted">rateLimitPerMin</div>
                  <input
                    type="number"
                    min={1}
                    max={6000}
                    defaultValue={nucleiRate}
                    onBlur={(e) => void saveNucleiTuning({ rateLimitPerMin: Number(e.target.value) })}
                    className="h-9 w-full rounded-xl border border-slate-200 bg-white px-3 text-xs dark:border-border dark:bg-black/20"
                  />
                </label>
                <div className="space-y-1">
                  <div className="text-[11px] text-muted">severity</div>
                  <div className="flex flex-wrap gap-2">
                    {["critical", "high", "medium", "low", "info"].map((s) => {
                      const checked = nucleiSeverity.has(s);
                      return (
                        <button
                          key={s}
                          type="button"
                          onClick={() => {
                            const next = new Set(nucleiSeverity);
                            if (next.has(s)) next.delete(s);
                            else next.add(s);
                            void saveNucleiTuning({ severity: Array.from(next) });
                          }}
                          disabled={!selectedProfile || busy}
                          className={cn(
                            "rounded-lg border px-2 py-1 text-[11px]",
                            checked
                              ? "border-accent/40 bg-accent/10 text-fg/90"
                              : "border-slate-200 bg-slate-50 text-fg/75 hover:bg-slate-100 dark:border-border dark:bg-black/30 dark:hover:bg-black/40"
                          )}
                        >
                          {s}
                        </button>
                      );
                    })}
                  </div>
                </div>
              </div>
              <div className="mt-2 text-[11px] text-muted">
                Изменения сохраняются при потере фокуса / клике по severity. Для запуска нужен `ASV_NUCLEI_ENABLED=1`.
              </div>
            </div>

            <div className="mt-3 space-y-2">
              {!selectedAsset ? null : artifactsQuery.isLoading ? (
                <div className="flex items-center gap-2 py-3 text-xs text-muted">
                  <Loader2 className="h-4 w-4 animate-spin" /> загрузка…
                </div>
              ) : artifacts.length === 0 ? (
                <div className="py-3 text-xs text-muted">Артефактов пока нет. Запусти скан, появится `scanner.log`.</div>
              ) : (
                artifacts.slice(0, 8).map((a) => (
                  <div
                    key={a.id}
                    className="flex items-start justify-between gap-3 rounded-xl border border-slate-200 bg-white p-3 text-xs dark:border-border dark:bg-black/10"
                  >
                    <div className="min-w-0">
                      <div className="font-medium text-fg/90">{a.kind}</div>
                      <div className="mt-1 text-[11px] text-muted">
                        {a.bytes} bytes • {fmtTs(a.created_at)}
                      </div>
                      {a.sha256 ? <div className="mt-1 font-mono text-[10px] text-muted/80">{a.sha256.slice(0, 16)}…</div> : null}
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        setArtifactId(a.id);
                        setArtifactOpen(true);
                      }}
                      className="rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-fg/80 hover:bg-slate-100 dark:border-border dark:bg-black/30 dark:hover:bg-black/40"
                      title="Просмотреть содержимое"
                    >
                      Просмотр
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </section>
      </div>

      <Dialog.Root open={templateOpen} onOpenChange={setTemplateOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content
            className={cn(
              "fixed left-1/2 top-1/2 z-50 w-[min(720px,calc(100vw-24px))] -translate-x-1/2 -translate-y-1/2",
              "rounded-2xl border border-border bg-white shadow-2xl backdrop-blur-xl dark:bg-black/60",
              "outline-none"
            )}
          >
            <div className="glass rounded-2xl p-5">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <Dialog.Title className="truncate text-sm font-semibold tracking-tight">
                    Nuclei template
                  </Dialog.Title>
                  <Dialog.Description className="mt-1 text-xs text-muted">
                    {templateId ? <span className="font-mono text-[11px]">{templateId}</span> : "—"}
                  </Dialog.Description>
                </div>
                <Dialog.Close asChild>
                  <button className="rounded-lg border border-slate-200 bg-slate-100 px-3 py-1.5 text-xs text-fg/90 hover:bg-slate-200/80 dark:border-border dark:bg-black/30 dark:hover:bg-black/40">
                    Закрыть
                  </button>
                </Dialog.Close>
              </div>

              <div className="mt-4 space-y-3 text-xs">
                {templateQuery.isLoading ? (
                  <div className="flex items-center gap-2 text-muted">
                    <Loader2 className="h-4 w-4 animate-spin" /> загрузка…
                  </div>
                ) : templateQuery.isError ? (
                  <div className="rounded-xl border border-rose-200 bg-rose-50 p-3 text-rose-800 dark:border-rose-900/40 dark:bg-rose-950/30 dark:text-rose-200">
                    {(templateQuery.error as Error).message}
                  </div>
                ) : templateQuery.data ? (
                  <div className="space-y-3">
                    <div className="rounded-xl border border-slate-200 bg-white/70 p-3 dark:border-border dark:bg-black/10">
                      <div className="text-[11px] text-muted">name</div>
                      <div className="mt-1 text-fg/90">{templateQuery.data.name ?? "—"}</div>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="rounded-xl border border-slate-200 bg-white/70 p-3 dark:border-border dark:bg-black/10">
                        <div className="text-[11px] text-muted">severity</div>
                        <div className="mt-1 text-fg/90">{templateQuery.data.severity ?? "—"}</div>
                      </div>
                      <div className="rounded-xl border border-slate-200 bg-white/70 p-3 dark:border-border dark:bg-black/10">
                        <div className="text-[11px] text-muted">updated</div>
                        <div className="mt-1 text-fg/90">{fmtTs(templateQuery.data.updated_at)}</div>
                      </div>
                    </div>
                    <div className="rounded-xl border border-slate-200 bg-white/70 p-3 dark:border-border dark:bg-black/10">
                      <div className="text-[11px] text-muted">tags</div>
                      <div className="mt-1 text-fg/90">
                        {(templateQuery.data.tags ?? []).length ? (templateQuery.data.tags ?? []).join(", ") : "—"}
                      </div>
                    </div>
                    <div className="rounded-xl border border-slate-200 bg-white/70 p-3 dark:border-border dark:bg-black/10">
                      <div className="text-[11px] text-muted">description</div>
                      <div className="mt-1 whitespace-pre-wrap text-fg/90">{templateQuery.data.description ?? "—"}</div>
                    </div>
                    <div className="rounded-xl border border-slate-200 bg-white/70 p-3 dark:border-border dark:bg-black/10">
                      <div className="text-[11px] text-muted">reference</div>
                      <div className="mt-1 space-y-1">
                        {(templateQuery.data.reference ?? []).length ? (
                          (templateQuery.data.reference ?? []).slice(0, 10).map((r) => (
                            <a
                              key={r}
                              href={r}
                              target="_blank"
                              rel="noreferrer"
                              className="block truncate text-fg/85 underline-offset-2 hover:underline"
                            >
                              {r}
                            </a>
                          ))
                        ) : (
                          <div className="text-fg/90">—</div>
                        )}
                      </div>
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      <Dialog.Root open={findingOpen} onOpenChange={setFindingOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content
            className={cn(
              "fixed left-1/2 top-1/2 z-50 w-[min(820px,calc(100vw-24px))] -translate-x-1/2 -translate-y-1/2",
              "rounded-2xl border border-border bg-white shadow-2xl backdrop-blur-xl dark:bg-black/60",
              "outline-none"
            )}
          >
            <div className="glass rounded-2xl p-5">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <Dialog.Title className="truncate text-sm font-semibold tracking-tight">Находка</Dialog.Title>
                  <Dialog.Description className="mt-1 text-xs text-muted">
                    {selectedFinding ? (
                      <>
                        <span className={severityBadge(selectedFinding.severity)}>{selectedFinding.severity}</span>
                        <span className="ml-2">{selectedFinding.tool}</span>
                        <span className="ml-2">last_seen {fmtTs(selectedFinding.last_seen)}</span>
                      </>
                    ) : (
                      "—"
                    )}
                  </Dialog.Description>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={!selectedFinding}
                    className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-fg/80 hover:bg-slate-100 disabled:opacity-50 dark:border-border dark:bg-black/30 dark:hover:bg-black/40"
                    onClick={() => {
                      if (!selectedFinding) return;
                      const hints = parseTargetHintsFromFinding(selectedFinding);
                      setMsfText([
                        "## Metasploit (Docker)",
                        "Run interactive console:",
                        "docker run --rm -it metasploitframework/metasploit-framework msfconsole",
                        "",
                        "Inside msfconsole (search only, no auto-exploit):",
                        "search type:auxiliary name:scanner",
                        "",
                        "Context:",
                        `- finding: ${selectedFinding.id}`,
                        `- tool: ${selectedFinding.tool}`,
                        `- severity: ${selectedFinding.severity}`
                      ].join("\\n"));
                      setMsfFindingId(selectedFinding.id);
                      setMsfOptRhosts(hints.rhosts ?? "");
                      setMsfOptRport(String(hints.rport ?? 443));
                      setMsfOptSsl(hints.ssl ?? true);
                      setMsfOptTargetUri(hints.targetUri ?? "/");
                      setMsfOptVhost(hints.vhost ?? "");
                      setMsfMode("safe");
                      setMsfAction("check");
                      setMsfModule("");
                      setMsfAck(false);
                      setMsfSelectedRunId(null);
                      setMsfOpen(true);
                    }}
                    title="Открыть Metasploit помощник и запустить ручную проверку"
                  >
                    Metasploit <ExternalLink className="h-3 w-3" />
                  </button>
                  <Dialog.Close asChild>
                    <button className="rounded-lg border border-slate-200 bg-slate-100 px-3 py-1.5 text-xs text-fg/90 hover:bg-slate-200/80 dark:border-border dark:bg-black/30 dark:hover:bg-black/40">
                      Закрыть
                    </button>
                  </Dialog.Close>
                </div>
              </div>

              {selectedFinding ? (
                <div className="mt-4 space-y-3 text-xs">
                  {selectedFinding ? (
                    <div className="rounded-xl border border-slate-200 bg-white/70 p-3 dark:border-border dark:bg-black/10">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="text-[11px] text-muted">AI triage</div>
                          {triageQuery.isLoading ? (
                            <div className="mt-2 flex items-center gap-2 text-xs text-muted">
                          <Loader2 className="h-4 w-4 animate-spin" /> генерирую / загружаю…
                            </div>
                          ) : triageQuery.data ? (
                            (() => {
                              const raw = (triageQuery.data?.output_json ?? {}) as any;
                              const summary = typeof raw?.summary === "string" ? raw.summary : null;
                              const why = Array.isArray(raw?.why_it_matters) ? raw.why_it_matters.map(String).filter(Boolean) : [];
                              const ver = Array.isArray(raw?.verification_steps)
                                ? raw.verification_steps.map(String).filter(Boolean)
                                : [];
                              const rem = Array.isArray(raw?.remediation) ? raw.remediation.map(String).filter(Boolean) : [];
                              const fp = Array.isArray(raw?.false_positive_risks)
                                ? raw.false_positive_risks.map(String).filter(Boolean)
                                : [];
                              const prio = typeof raw?.priority === "string" ? raw.priority : null;
                              const conf = typeof raw?.confidence === "string" ? raw.confidence : null;
                              const fallbackText =
                                typeof triageQuery.data?.output_text === "string" ? triageQuery.data.output_text : null;

                              return (
                                <div className="mt-2 space-y-3">
                                  <div className="flex flex-wrap items-center gap-2">
                                    {prio ? <span className={priorityBadge(prio)}>priority {prio}</span> : null}
                                    {conf ? <span className={confidenceBadge(conf)}>confidence {conf}</span> : null}
                                    {summary ? null : (
                                      <span className="text-[11px] text-muted">Нет структурированного summary.</span>
                                    )}
                                  </div>

                                  {summary ? (
                                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-2 text-[11px] text-fg/85 dark:border-border dark:bg-black/30">
                                      <div className="text-[10px] font-medium text-muted">Кратко</div>
                                      <div className="mt-1 whitespace-pre-wrap">{summary}</div>
                                    </div>
                                  ) : null}

                                  {why.length ? (
                                    <div className="rounded-lg border border-slate-200 bg-white p-2 text-[11px] dark:border-border dark:bg-black/20">
                                      <div className="text-[10px] font-medium text-muted">Почему важно</div>
                                      <ul className="mt-1 list-disc space-y-1 pl-4">
                                        {why.slice(0, 12).map((x: string, i: number) => (
                                          <li key={i} className="text-fg/85">
                                            {x}
                                          </li>
                                        ))}
                                      </ul>
                                    </div>
                                  ) : null}

                                  {ver.length ? (
                                    <div className="rounded-lg border border-slate-200 bg-white p-2 text-[11px] dark:border-border dark:bg-black/20">
                                      <div className="text-[10px] font-medium text-muted">Проверка (безопасно)</div>
                                      <ol className="mt-1 list-decimal space-y-1 pl-4">
                                        {ver.slice(0, 14).map((x: string, i: number) => (
                                          <li key={i} className="text-fg/85">
                                            {x}
                                          </li>
                                        ))}
                                      </ol>
                                    </div>
                                  ) : null}

                                  {rem.length ? (
                                    <div className="rounded-lg border border-slate-200 bg-white p-2 text-[11px] dark:border-border dark:bg-black/20">
                                      <div className="text-[10px] font-medium text-muted">Рекомендации</div>
                                      <ul className="mt-1 list-disc space-y-1 pl-4">
                                        {rem.slice(0, 14).map((x: string, i: number) => (
                                          <li key={i} className="text-fg/85">
                                            {x}
                                          </li>
                                        ))}
                                      </ul>
                                    </div>
                                  ) : null}

                                  {fp.length ? (
                                    <div className="rounded-lg border border-slate-200 bg-white p-2 text-[11px] dark:border-border dark:bg-black/20">
                                      <div className="text-[10px] font-medium text-muted">Риски ложного срабатывания</div>
                                      <ul className="mt-1 list-disc space-y-1 pl-4">
                                        {fp.slice(0, 10).map((x: string, i: number) => (
                                          <li key={i} className="text-fg/85">
                                            {x}
                                          </li>
                                        ))}
                                      </ul>
                                    </div>
                                  ) : null}

                                  {!summary && fallbackText ? (
                                    <pre className="rounded-lg border border-slate-200 bg-slate-50 p-2 text-[11px] text-fg/85 dark:border-border dark:bg-black/30">
                                      {fallbackText}
                                    </pre>
                                  ) : null}
                                </div>
                              );
                            })()
                          ) : (
                            <div className="mt-2 text-[11px] text-muted">Пока нет AI triage.</div>
                          )}
                        </div>
                        <button
                          type="button"
                          onClick={async () => {
                            const res = await apiFetch(
                              `/api/asv/findings/${encodeURIComponent(selectedFinding.id)}/ai/triage`,
                              { method: "POST", headers: { "content-type": "application/json" } }
                            );
                            const body = (await res.json()) as { ok?: boolean; message?: string };
                            if (!res.ok) throw new Error(body.message ?? `ai triage start (${res.status})`);
                            // Worker is async; poll for a short window.
                            setTriagePollUntilMs(Date.now() + 90_000);
                            await triageQuery.refetch();
                          }}
                          className="inline-flex shrink-0 items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                          title="Запросить AI triage"
                        >
                          Запросить
                        </button>
                      </div>
                    </div>
                  ) : null}

                  {(() => {
                    const enr = getFindingEnrichment(selectedFinding);
                    if (!enr) return null;
                    const has = enr.cveIds.length > 0 || enr.matches.length > 0 || enr.missingInLocalDb.length > 0;
                    if (!has) return null;
                    const kev = enr.matches.filter((m) => Boolean(m.kev)).map((m) => m.cve_id);
                    const epssTop = enr.matches
                      .filter((m) => m.epss && typeof m.epss.score === "number")
                      .sort((a, b) => (b.epss?.score ?? 0) - (a.epss?.score ?? 0))
                      .slice(0, 3);
                    return (
                      <div className="rounded-xl border border-slate-200 bg-white/70 p-3 dark:border-border dark:bg-black/10">
                        <div className="text-[11px] text-muted">enrichment</div>
                        {enr.cveIds.length ? (
                          <div className="mt-2 flex flex-wrap items-center gap-2">
                            <div className="text-[11px] text-muted">CVE:</div>
                            {enr.cveIds.map((id) => (
                              <span
                                key={id}
                                className="rounded-lg border border-slate-200 bg-slate-50 px-2 py-1 font-mono text-[11px] text-fg/85 dark:border-border dark:bg-black/30"
                              >
                                {id}
                              </span>
                            ))}
                          </div>
                        ) : null}
                        {kev.length ? (
                          <div className="mt-2 text-[11px]">
                            <span className="text-muted">KEV:</span>{" "}
                            <span className="font-mono text-fg/85">{kev.join(", ")}</span>
                          </div>
                        ) : null}
                        {epssTop.length ? (
                          <div className="mt-2 text-[11px]">
                            <span className="text-muted">EPSS top:</span>{" "}
                            <span className="font-mono text-fg/85">
                              {epssTop
                                .map((m) => `${m.cve_id}=${(m.epss!.score * 100).toFixed(1)}%`)
                                .join(" · ")}
                            </span>
                          </div>
                        ) : null}
                        {enr.missingInLocalDb.length ? (
                          <div className="mt-2 text-[11px] text-muted">
                            missing in local DB: <span className="font-mono">{enr.missingInLocalDb.join(", ")}</span>
                          </div>
                        ) : null}
                      </div>
                    );
                  })()}

                  <div className="rounded-xl border border-slate-200 bg-white/70 p-3 dark:border-border dark:bg-black/10">
                    <div className="text-[11px] text-muted">title</div>
                    <div className="mt-1 text-fg/90">{selectedFinding.title}</div>
                    {selectedFinding.external_id ? (
                      <div className="mt-2 text-[11px] text-muted">
                        external_id: <span className="font-mono text-[10px] text-fg/80">{selectedFinding.external_id}</span>
                      </div>
                    ) : null}
                    <div className="mt-2 text-[11px] text-muted">
                      fingerprint: <span className="font-mono text-[10px] text-fg/80">{selectedFinding.fingerprint}</span>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={() => void copyText(safeStringify(selectedFinding))}
                        className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                        title="Скопировать finding JSON"
                      >
                        <Copy className="h-4 w-4" /> Копировать JSON
                      </button>
                      {findingEndpoint ? (
                        <a
                          href={findingEndpoint}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                          title="Открыть endpoint"
                        >
                          <ExternalLink className="h-4 w-4" /> Открыть
                        </a>
                      ) : null}
                      {nucleiCmd ? (
                        <button
                          type="button"
                          onClick={() => void copyText(nucleiCmd)}
                          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                          title="Скопировать команду nuclei под текущий профиль"
                        >
                          <Copy className="h-4 w-4" /> Копировать команду nuclei
                        </button>
                      ) : null}
                      {selectedFinding.tool === "nuclei" && selectedFinding.external_id ? (
                        <button
                          type="button"
                          onClick={() => {
                            setTemplateId(selectedFinding.external_id ?? null);
                            setTemplateOpen(true);
                          }}
                          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                          title="Открыть шаблон nuclei"
                        >
                          Шаблон
                        </button>
                      ) : null}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
                    <div className="rounded-xl border border-slate-200 bg-white/70 p-3 dark:border-border dark:bg-black/10">
                      <div className="text-[11px] text-muted">affected</div>
                      <pre className="mt-2 max-h-56 overflow-auto rounded-lg bg-slate-50 p-2 text-[11px] text-fg/85 dark:bg-black/30">
                        {JSON.stringify(selectedFinding.affected ?? {}, null, 2)}
                      </pre>
                    </div>
                    <div className="rounded-xl border border-slate-200 bg-white/70 p-3 dark:border-border dark:bg-black/10">
                      <div className="text-[11px] text-muted">evidence</div>
                      <pre className="mt-2 max-h-56 overflow-auto rounded-lg bg-slate-50 p-2 text-[11px] text-fg/85 dark:bg-black/30">
                        {JSON.stringify(selectedFinding.evidence ?? [], null, 2)}
                      </pre>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="mt-4 text-xs text-muted">Не найдено.</div>
              )}
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      <Dialog.Root open={artifactOpen} onOpenChange={setArtifactOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content
            className={cn(
              "fixed left-1/2 top-1/2 z-50 w-[min(900px,calc(100vw-24px))] -translate-x-1/2 -translate-y-1/2",
              "rounded-2xl border border-border bg-white shadow-2xl backdrop-blur-xl dark:bg-black/60",
              "outline-none"
            )}
          >
            <div className="glass rounded-2xl p-5">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <Dialog.Title className="truncate text-sm font-semibold tracking-tight">Артефакт</Dialog.Title>
                  <Dialog.Description className="mt-1 text-xs text-muted">
                    {artifactId ? <span className="font-mono text-[11px]">{artifactId}</span> : "—"}
                  </Dialog.Description>
                </div>
                <Dialog.Close asChild>
                  <button className="rounded-lg border border-slate-200 bg-slate-100 px-3 py-1.5 text-xs text-fg/90 hover:bg-slate-200/80 dark:border-border dark:bg-black/30 dark:hover:bg-black/40">
                    Закрыть
                  </button>
                </Dialog.Close>
              </div>

              <div className="mt-4">
                {artifactQuery.isLoading ? (
                  <div className="flex items-center gap-2 text-xs text-muted">
                    <Loader2 className="h-4 w-4 animate-spin" /> загрузка…
                  </div>
                ) : artifactQuery.isError ? (
                  <div className="rounded-xl border border-rose-200 bg-rose-50 p-3 text-xs text-rose-800 dark:border-rose-900/40 dark:bg-rose-950/30 dark:text-rose-200">
                    {(artifactQuery.error as Error).message}
                  </div>
                ) : artifactQuery.data?.content_text ? (
                  <div className="space-y-3">
                    <div className="flex flex-wrap items-center justify-end gap-2">
                      <button
                        type="button"
                        onClick={() => void copyText(artifactQuery.data?.content_text ?? "")}
                        className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                      >
                        <Copy className="h-4 w-4" /> Копировать
                      </button>
                      <button
                        type="button"
                        onClick={() => downloadText(`artifact-${artifactId ?? "log"}.txt`, artifactQuery.data?.content_text ?? "")}
                        className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                      >
                        <FileDown className="h-4 w-4" /> Скачать
                      </button>
                    </div>
                    <pre className="max-h-[70vh] overflow-auto rounded-xl border border-slate-200 bg-slate-50 p-3 text-[11px] text-fg/85 dark:border-border dark:bg-black/30">
                      {artifactQuery.data.content_text}
                    </pre>
                  </div>
                ) : (
                  <div className="text-xs text-muted">Нет содержимого.</div>
                )}
              </div>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      <Dialog.Root open={msfOpen} onOpenChange={setMsfOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content
            className={cn(
              "fixed left-1/2 top-1/2 z-50 w-[min(900px,calc(100vw-24px))] -translate-x-1/2 -translate-y-1/2",
              "rounded-2xl border border-border bg-white shadow-2xl backdrop-blur-xl dark:bg-black/60",
              "outline-none"
            )}
          >
            <div className="glass rounded-2xl p-5">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <Dialog.Title className="truncate text-sm font-semibold tracking-tight">Metasploit помощник</Dialog.Title>
                  <Dialog.Description className="mt-1 text-xs text-muted">
                    Ручная проверка через контейнер Metasploit: по умолчанию безопасный режим. Эксплойт — только по явному подтверждению.
                  </Dialog.Description>
                </div>
                <Dialog.Close asChild>
                  <button className="rounded-lg border border-slate-200 bg-slate-100 px-3 py-1.5 text-xs text-fg/90 hover:bg-slate-200/80 dark:border-border dark:bg-black/30 dark:hover:bg-black/40">
                    Закрыть
                  </button>
                </Dialog.Close>
              </div>

              <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-2">
                <div className="rounded-xl border border-slate-200 bg-white/70 p-3 text-xs dark:border-border dark:bg-black/10">
                  <div className="flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-fg/90">Запуск проверки</div>
                      <div className="mt-1 text-[11px] text-muted">
                        Одна кнопка: система сама подберёт модуль (по CVE/порту/контексту), выполнит check/run и даст итог.
                      </div>
                    </div>
                    <button
                      type="button"
                      disabled={!msfFindingId}
                      onClick={async () => {
                        if (!msfFindingId) return;
                        setBusy(true);
                        setErr(null);
                        try {
                          const payload = {
                            mode: msfMode,
                            action: msfMode === "exploit" ? "exploit" : "check",
                            module: null,
                            autoPick: true,
                            ackRisks: msfMode === "exploit" ? msfAck : false,
                            options: {
                              RHOSTS: msfOptRhosts.trim() ? msfOptRhosts.trim() : undefined,
                              RPORT: Number(msfOptRport) || undefined,
                              SSL: Boolean(msfOptSsl),
                              TARGETURI: msfOptTargetUri.trim() ? msfOptTargetUri.trim() : undefined,
                              VHOST: msfOptVhost.trim() ? msfOptVhost.trim() : undefined
                            }
                          };
                          const res = await apiFetch(`/api/asv/findings/${encodeURIComponent(msfFindingId)}/msf-runs`, {
                            method: "POST",
                            headers: { "content-type": "application/json" },
                            body: JSON.stringify(payload),
                            cache: "no-store"
                          });
                          const body = (await res.json()) as { id?: string; message?: string };
                          if (!res.ok) throw new Error(body.message ?? `msf create (${res.status})`);
                          if (body.id) setMsfSelectedRunId(body.id);
                          await msfRunsQuery.refetch();
                        } catch (e) {
                          setErr(e instanceof Error ? e.message : String(e));
                        } finally {
                          setBusy(false);
                        }
                      }}
                      className={cn(
                        "inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-xs",
                        "border-slate-200 bg-white hover:bg-slate-50 disabled:opacity-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                      )}
                      title="Запустить контейнер Metasploit для валидации"
                    >
                      <Play className="h-4 w-4" />
                      Проверить применимость
                    </button>
                  </div>

                  <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
                    <label className="block">
                      <div className="text-[11px] text-muted">Режим</div>
                      <select
                        value={msfMode}
                        onChange={(e) => {
                          const v = e.target.value === "exploit" ? "exploit" : "safe";
                          setMsfMode(v);
                          if (v === "exploit") setMsfAction("exploit");
                        }}
                        className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-xs dark:border-border dark:bg-black/20"
                      >
                        <option value="safe">safe (detector/check)</option>
                        <option value="exploit">exploit (требует подтверждения)</option>
                      </select>
                    </label>

                    <div className="block sm:col-span-1">
                      <div className="text-[11px] text-muted">Module</div>
                      <div className="mt-1 rounded-lg border border-slate-200 bg-slate-50 px-2 py-1.5 text-[11px] text-fg/80 dark:border-border dark:bg-black/20">
                        подбирается автоматически
                      </div>
                    </div>

                    <label className="block">
                      <div className="text-[11px] text-muted">RHOSTS</div>
                      <input
                        value={msfOptRhosts}
                        onChange={(e) => setMsfOptRhosts(e.target.value)}
                        placeholder="1.2.3.4 или host"
                        className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-xs font-mono dark:border-border dark:bg-black/20"
                      />
                    </label>
                    <label className="block">
                      <div className="text-[11px] text-muted">RPORT</div>
                      <input
                        value={msfOptRport}
                        onChange={(e) => setMsfOptRport(e.target.value)}
                        className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-xs font-mono dark:border-border dark:bg-black/20"
                      />
                    </label>

                    <label className="block">
                      <div className="text-[11px] text-muted">SSL</div>
                      <select
                        value={msfOptSsl ? "1" : "0"}
                        onChange={(e) => setMsfOptSsl(e.target.value === "1")}
                        className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-xs dark:border-border dark:bg-black/20"
                      >
                        <option value="1">true</option>
                        <option value="0">false</option>
                      </select>
                    </label>
                    <label className="block">
                      <div className="text-[11px] text-muted">TARGETURI</div>
                      <input
                        value={msfOptTargetUri}
                        onChange={(e) => setMsfOptTargetUri(e.target.value)}
                        placeholder="/"
                        className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-xs font-mono dark:border-border dark:bg-black/20"
                      />
                    </label>

                    <label className="block sm:col-span-2">
                      <div className="text-[11px] text-muted">VHOST (опционально)</div>
                      <input
                        value={msfOptVhost}
                        onChange={(e) => setMsfOptVhost(e.target.value)}
                        placeholder="host.example.com"
                        className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-xs font-mono dark:border-border dark:bg-black/20"
                      />
                    </label>
                  </div>

                  {msfMode === "exploit" ? (
                    <div className="mt-3 rounded-xl border border-amber-200 bg-amber-50 p-3 text-[11px] text-amber-950 dark:border-amber-900/40 dark:bg-amber-950/20 dark:text-amber-200">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="mt-0.5 h-4 w-4" />
                        <div className="min-w-0">
                          <div className="font-medium">Exploit mode</div>
                          <div className="mt-1 opacity-90">
                            Запуск exploit может повлиять на целевую систему. Используйте только на разрешённых целях.
                          </div>
                          <label className="mt-2 flex items-center gap-2">
                            <input type="checkbox" checked={msfAck} onChange={(e) => setMsfAck(e.target.checked)} />
                            <span>Понимаю риски и подтверждаю запуск exploit</span>
                          </label>
                        </div>
                      </div>
                    </div>
                  ) : null}

                  {err ? <div className="mt-3 text-[11px] text-rose-600 dark:text-rose-300">{err}</div> : null}
                </div>

                <div className="rounded-xl border border-slate-200 bg-white/70 p-3 text-xs dark:border-border dark:bg-black/10">
                  <div className="flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-fg/90">История запусков</div>
                      <div className="mt-1 text-[11px] text-muted">Последние ручные проверки по этой находке.</div>
                    </div>
                    <button
                      type="button"
                      onClick={() => void msfRunsQuery.refetch()}
                      disabled={!msfFindingId}
                      className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs hover:bg-slate-50 disabled:opacity-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                    >
                      <RefreshCw className={cn("h-4 w-4", msfRunsQuery.isFetching ? "animate-spin" : "")} /> Обновить
                    </button>
                  </div>

                  <div className="mt-3 space-y-2">
                    {msfRunsQuery.isLoading ? (
                      <div className="flex items-center gap-2 text-[11px] text-muted">
                        <Loader2 className="h-4 w-4 animate-spin" /> загружаю…
                      </div>
                    ) : msfRunsQuery.data && msfRunsQuery.data.length ? (
                      msfRunsQuery.data.slice(0, 10).map((r) => (
                        <button
                          key={r.id}
                          type="button"
                          onClick={() => setMsfSelectedRunId(r.id)}
                          className={cn(
                            "w-full rounded-xl border p-2 text-left text-[11px] hover:bg-slate-50 dark:hover:bg-black/30",
                            r.id === msfSelectedRunId
                              ? "border-indigo-200 bg-indigo-50 dark:border-indigo-900/40 dark:bg-indigo-950/20"
                              : "border-slate-200 bg-white dark:border-border dark:bg-black/20"
                          )}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <div className="min-w-0 truncate font-mono">{r.id.slice(0, 8)}</div>
                            <div className="shrink-0">
                              <span
                                className={cn(
                                  "rounded-md px-2 py-0.5",
                                  r.status === "completed"
                                    ? "bg-emerald-100 text-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-200"
                                    : r.status === "failed"
                                      ? "bg-rose-100 text-rose-900 dark:bg-rose-950/30 dark:text-rose-200"
                                      : r.status === "running"
                                        ? "bg-amber-100 text-amber-900 dark:bg-amber-950/30 dark:text-amber-200"
                                        : "bg-slate-100 text-slate-800 dark:bg-black/30 dark:text-slate-200"
                                )}
                              >
                                {r.status}
                              </span>
                            </div>
                          </div>
                          <div className="mt-1 text-muted">
                            {fmtTs(r.created_at)} · {r.mode}/{r.action}
                            {r.module ? <span className="ml-2 font-mono text-fg/80">· {r.module}</span> : null}
                          </div>
                          {r.summary ? <div className="mt-1 truncate text-fg/80">{r.summary}</div> : null}
                          {r.error ? <div className="mt-1 truncate text-rose-600 dark:text-rose-300">{r.error}</div> : null}
                        </button>
                      ))
                    ) : (
                      <div className="text-[11px] text-muted">Пока запусков не было.</div>
                    )}
                  </div>

                  {msfSelectedRunId ? (
                    <div className="mt-3 space-y-2">
                      <div className="rounded-xl border border-slate-200 bg-white p-3 text-[11px] dark:border-border dark:bg-black/20">
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="text-[10px] font-medium text-muted">Итог</div>
                            <div className="mt-1 text-fg/90">
                              {msfConclusion?.conclusion ?? msfRunQuery.data?.summary ?? "—"}
                            </div>
                            <div className="mt-2 flex flex-wrap items-center gap-2">
                              {msfConclusion?.verdict ? (
                                <span className="rounded-md bg-slate-100 px-2 py-0.5 text-[10px] text-slate-800 dark:bg-black/30 dark:text-slate-200">
                                  verdict {msfConclusion.verdict}
                                </span>
                              ) : null}
                              {msfConclusion?.sessionsHint ? (
                                <span className="rounded-md bg-emerald-50 px-2 py-0.5 text-[10px] text-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-200">
                                  sessions: {msfConclusion.sessionsHint.slice(0, 120)}
                                </span>
                              ) : null}
                              {msfConclusion?.lootHint ? (
                                <span className="rounded-md bg-indigo-50 px-2 py-0.5 text-[10px] text-indigo-900 dark:bg-indigo-950/30 dark:text-indigo-200">
                                  loot: {msfConclusion.lootHint.slice(0, 120)}
                                </span>
                              ) : null}
                            </div>
                          </div>
                        </div>
                        {msfSteps.length ? (
                          <div className="mt-3">
                            <div className="text-[10px] font-medium text-muted">Цепочка (шаги)</div>
                            <div className="mt-2 space-y-2">
                              {msfSteps.map((s) => (
                                <div
                                  key={`${s.step ?? "?"}-${s.module}`}
                                  className="rounded-lg border border-slate-200 bg-slate-50 p-2 text-[10px] text-fg/85 dark:border-border dark:bg-black/30"
                                >
                                  <div className="flex flex-wrap items-center gap-2">
                                    <span className="rounded-md bg-white px-2 py-0.5 font-mono text-[10px] dark:bg-black/30">
                                      шаг {s.step ?? "?"}
                                    </span>
                                    <span className="rounded-md bg-slate-100 px-2 py-0.5 text-[10px] dark:bg-black/30">
                                      {s.label || "—"}
                                    </span>
                                    {s.verdict ? (
                                      <span className="rounded-md bg-indigo-50 px-2 py-0.5 text-[10px] text-indigo-900 dark:bg-indigo-950/30 dark:text-indigo-200">
                                        {s.verdict}
                                      </span>
                                    ) : null}
                                  </div>
                                  <div className="mt-1 font-mono text-[10px] text-fg/80">{s.module || "—"}</div>
                                  {s.conclusion ? <div className="mt-1 text-fg/80">{s.conclusion}</div> : null}
                                  <div className="mt-1 flex flex-wrap items-center gap-2 text-[10px] text-muted">
                                    {s.sessionsHint ? <span>sessions: {s.sessionsHint.slice(0, 80)}</span> : null}
                                    {s.lootHint ? <span>loot: {s.lootHint.slice(0, 80)}</span> : null}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        ) : null}
                        {msfConclusion?.highlights?.length ? (
                          <pre className="mt-3 max-h-40 overflow-auto rounded-lg border border-slate-200 bg-slate-50 p-2 text-[10px] text-fg/85 dark:border-border dark:bg-black/30">
                            {msfConclusion.highlights.join("\n")}
                          </pre>
                        ) : (
                          <div className="mt-2 text-[10px] text-muted">Highlights появятся после завершения run (completed/failed).</div>
                        )}
                      </div>

                      <div className="text-[11px] font-medium">Артефакты</div>
                      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                        {(msfArtifactsQuery.data ?? []).map((a) => (
                          <button
                            key={a.id}
                            type="button"
                            onClick={async () => {
                              setBusy(true);
                              setErr(null);
                              try {
                                const res = await apiFetch(
                                  `/api/asv/msf-runs/${encodeURIComponent(msfSelectedRunId)}/artifacts/${encodeURIComponent(a.id)}`,
                                  { cache: "no-store" }
                                );
                                const body = (await res.json()) as { content_text?: string; message?: string };
                                if (!res.ok) throw new Error(body.message ?? `artifact (${res.status})`);
                                setMsfArtifactTitle(`${a.kind} · ${a.bytes}B`);
                                setMsfArtifactText(body.content_text ?? "");
                                setMsfArtifactOpen(true);
                              } catch (e) {
                                setErr(e instanceof Error ? e.message : String(e));
                              } finally {
                                setBusy(false);
                              }
                            }}
                            className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-left text-[11px] hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                          >
                            <div className="font-mono">{a.kind}</div>
                            <div className="mt-1 text-muted">{a.bytes}B · {fmtTs(a.created_at)}</div>
                          </button>
                        ))}
                      </div>

                      <div className="mt-3 text-[11px] font-medium">События</div>
                      <div className="max-h-40 overflow-auto rounded-xl border border-slate-200 bg-white p-2 text-[11px] dark:border-border dark:bg-black/20">
                        {(msfEventsQuery.data ?? []).slice(0, 50).map((ev) => (
                          <div key={ev.id} className="flex items-center justify-between gap-2 border-b border-slate-100 py-1 last:border-b-0 dark:border-border/40">
                            <div className="min-w-0 truncate">
                              <span className="font-mono">{fmtTs(ev.ts)}</span>
                              <span className="ml-2">{ev.action}</span>
                              {ev.actor ? <span className="ml-2 text-muted">· {ev.actor}</span> : null}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
              </div>

              <Dialog.Root open={msfArtifactOpen} onOpenChange={setMsfArtifactOpen}>
                <Dialog.Portal>
                  <Dialog.Overlay className="fixed inset-0 z-[60] bg-black/60 backdrop-blur-sm" />
                  <Dialog.Content
                    className={cn(
                      "fixed left-1/2 top-1/2 z-[60] w-[min(980px,calc(100vw-24px))] -translate-x-1/2 -translate-y-1/2",
                      "rounded-2xl border border-border bg-white shadow-2xl backdrop-blur-xl dark:bg-black/60",
                      "outline-none"
                    )}
                  >
                    <div className="glass rounded-2xl p-5">
                      <div className="flex items-start justify-between gap-4">
                        <div className="min-w-0">
                          <Dialog.Title className="truncate text-sm font-semibold tracking-tight">MSF artifact</Dialog.Title>
                          <Dialog.Description className="mt-1 text-xs text-muted">{msfArtifactTitle}</Dialog.Description>
                        </div>
                        <Dialog.Close asChild>
                          <button className="rounded-lg border border-slate-200 bg-slate-100 px-3 py-1.5 text-xs text-fg/90 hover:bg-slate-200/80 dark:border-border dark:bg-black/30 dark:hover:bg-black/40">
                            Закрыть
                          </button>
                        </Dialog.Close>
                      </div>

                      <div className="mt-4 flex items-center justify-end gap-2">
                        <button
                          type="button"
                          onClick={() => void copyText(msfArtifactText)}
                          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                        >
                          <Copy className="h-4 w-4" /> Копировать
                        </button>
                        <button
                          type="button"
                          onClick={() => downloadText(`msf-${Date.now()}.txt`, msfArtifactText)}
                          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                        >
                          <FileDown className="h-4 w-4" /> Скачать
                        </button>
                      </div>

                      <pre className="mt-4 max-h-[70vh] overflow-auto rounded-xl border border-slate-200 bg-slate-50 p-3 text-[11px] text-fg/85 dark:border-border dark:bg-black/30">
                        {msfArtifactText || "—"}
                      </pre>
                    </div>
                  </Dialog.Content>
                </Dialog.Portal>
              </Dialog.Root>

              <div className="mt-4 flex flex-wrap items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => void copyText(msfText)}
                  className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                >
                  <Copy className="h-4 w-4" /> Копировать
                </button>
                <button
                  type="button"
                  onClick={() => downloadText(`metasploit-${Date.now()}.txt`, msfText)}
                  className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                >
                  <FileDown className="h-4 w-4" /> Скачать
                </button>
              </div>

              <pre className="mt-4 max-h-[70vh] overflow-auto rounded-xl border border-slate-200 bg-slate-50 p-3 text-[11px] text-fg/85 dark:border-border dark:bg-black/30">
                {msfText}
              </pre>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      <Dialog.Root open={issueAiOpen} onOpenChange={setIssueAiOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content
            className={cn(
              "fixed left-1/2 top-1/2 z-50 w-[min(820px,calc(100vw-24px))] -translate-x-1/2 -translate-y-1/2",
              "rounded-2xl border border-border bg-white shadow-2xl backdrop-blur-xl dark:bg-black/60",
              "outline-none"
            )}
          >
            <div className="glass rounded-2xl p-5">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <Dialog.Title className="truncate text-sm font-semibold tracking-tight">AI приоритизация проблемы</Dialog.Title>
                  <Dialog.Description className="mt-1 text-xs text-muted">
                    {selectedIssue ? (
                      <>
                        <span className={severityBadge(selectedIssue.severity)}>{selectedIssue.severity}</span>
                        <span className="ml-2">{selectedIssue.tool}</span>
                        <span className="ml-2">last_seen {fmtTs(selectedIssue.last_seen)}</span>
                      </>
                    ) : (
                      "—"
                    )}
                  </Dialog.Description>
                </div>
                <Dialog.Close asChild>
                  <button className="rounded-lg border border-slate-200 bg-slate-100 px-3 py-1.5 text-xs text-fg/90 hover:bg-slate-200/80 dark:border-border dark:bg-black/30 dark:hover:bg-black/40">
                    Закрыть
                  </button>
                </Dialog.Close>
              </div>

              {selectedIssue ? (
                <div className="mt-4 space-y-3 text-xs">
                  <div className="rounded-xl border border-slate-200 bg-white/70 p-3 dark:border-border dark:bg-black/10">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="text-[11px] text-muted">AI priority</div>
                        {issuePriorityQuery.isLoading ? (
                          <div className="mt-2 flex items-center gap-2 text-xs text-muted">
                            <Loader2 className="h-4 w-4 animate-spin" /> генерирую / загружаю…
                          </div>
                        ) : issuePriorityQuery.data ? (
                          <pre className="mt-2 max-h-72 overflow-auto rounded-lg bg-slate-50 p-2 text-[11px] text-fg/85 dark:bg-black/30">
                            {safeStringify(issuePriorityQuery.data.output_json ?? { summary: issuePriorityQuery.data.output_text })}
                          </pre>
                        ) : (
                          <div className="mt-2 text-[11px] text-muted">Пока нет AI priority.</div>
                        )}
                      </div>
                      <button
                        type="button"
                        onClick={async () => {
                          const res = await apiFetch(
                            `/api/asv/issues/${encodeURIComponent(selectedIssue.id)}/ai/priority`,
                            { method: "POST", headers: { "content-type": "application/json" } }
                          );
                          const body = (await res.json()) as { ok?: boolean; message?: string };
                          if (!res.ok) throw new Error(body.message ?? `ai priority start (${res.status})`);
                          await issuePriorityQuery.refetch();
                        }}
                        className="inline-flex shrink-0 items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs hover:bg-slate-50 dark:border-border dark:bg-black/20 dark:hover:bg-black/30"
                        title="Запросить AI priority"
                      >
                        Запросить
                      </button>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="mt-4 text-xs text-muted">Не найдено.</div>
              )}
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}


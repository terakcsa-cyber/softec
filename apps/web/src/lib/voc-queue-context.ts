import type { VocQueueItem } from "./voc-api";

export type VocContextChip = {
  key: string;
  label: string;
  tone?: "danger" | "warn" | "muted";
};

export type VocIntelContext = {
  vendor: string | null;
  product: string | null;
  description: string | null;
  chips: VocContextChip[];
};

function str(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const t = v.trim();
  return t ? t : null;
}

function num(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim()) {
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

function fmtEpss(v: number): string {
  if (v <= 1) return `${Math.round(v * 1000) / 10}%`;
  return String(Math.round(v));
}

/** Контекст CVE/БДУ для очереди смены (TG не трогаем — там свой текст поста). */
export function vocIntelContext(item: VocQueueItem): VocIntelContext | null {
  if (item.source === "tg") return null;
  const p = item.payload ?? {};

  if (item.source === "cve") {
    const vendor = str(p.vp_vendor);
    const product = str(p.vp_product);
    const description =
      str(p.enrich_summary) || str(p.short_description) || (vendor || product ? null : str(item.subtitle));
    const cvss = num(p.cvss_base);
    const epss = num(p.epss);
    const chips: VocContextChip[] = [];
    if (cvss != null) chips.push({ key: "cvss", label: `CVSS ${cvss.toFixed(1)}`, tone: cvss >= 9 ? "danger" : cvss >= 7 ? "warn" : "muted" });
    if (epss != null && epss > 0) chips.push({ key: "epss", label: `EPSS ${fmtEpss(epss)}`, tone: epss >= 0.5 ? "warn" : "muted" });
    if (p.exploit_known || p.vulncheck_kev) chips.push({ key: "kev", label: "KEV", tone: "danger" });
    if (p.has_public_exploit) chips.push({ key: "exploit", label: "Exploit", tone: "danger" });
    else if (p.has_poc) chips.push({ key: "poc", label: "PoC", tone: "warn" });
    if (p.epss_spike) chips.push({ key: "spike", label: "EPSS↑", tone: "warn" });
    const klass = str(p.vuln_class);
    if (klass) chips.push({ key: "class", label: klass, tone: "muted" });
    return { vendor, product, description, chips };
  }

  const vendor = null;
  const product = null;
  const description = str(p.name) || str(item.subtitle);
  const cvss = num(p.cvss_score);
  const chips: VocContextChip[] = [];
  if (cvss != null) chips.push({ key: "cvss", label: `CVSS ${cvss.toFixed(1)}`, tone: cvss >= 9 ? "danger" : cvss >= 7 ? "warn" : "muted" });
  if (p.has_exploit) chips.push({ key: "exploit", label: "Exploit", tone: "danger" });
  if (p.linked_hot) chips.push({ key: "hot", label: "горячий CVE", tone: "warn" });
  const linked = num(p.linked_count);
  if (linked != null && linked > 0) chips.push({ key: "cves", label: `CVE ${linked}`, tone: "muted" });
  const ids = Array.isArray(p.cve_ids) ? p.cve_ids.map(String).filter(Boolean).slice(0, 3) : [];
  for (const id of ids) chips.push({ key: id, label: id, tone: "muted" });
  return { vendor, product, description, chips };
}

export function vocChipClass(tone: VocContextChip["tone"]) {
  if (tone === "danger") return "border-danger/35 bg-danger/10 text-danger";
  if (tone === "warn") return "border-warn/35 bg-warn/10 text-warn";
  return "border-border bg-slate-50 text-fg/70 dark:bg-white/[0.04]";
}

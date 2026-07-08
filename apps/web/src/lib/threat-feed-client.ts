/** Threat feed UI helpers (localStorage + VOC integration). */

const WATCHLIST_VENDOR_KEY = "vip:threatFeedVendorFilter";
const LAST_VISIT_KEY = "vip:threatFeedLastVisit";

export function readThreatVendorFilter(): string[] {
  try {
    const raw = localStorage.getItem(WATCHLIST_VENDOR_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.map(String).filter(Boolean) : [];
  } catch {
    return [];
  }
}

export function writeThreatVendorFilter(vendors: string[]) {
  try {
    localStorage.setItem(WATCHLIST_VENDOR_KEY, JSON.stringify(vendors));
  } catch {
    // ignore
  }
}

export function readThreatLastVisit(): string | null {
  try {
    return localStorage.getItem(LAST_VISIT_KEY);
  } catch {
    return null;
  }
}

export function writeThreatLastVisit(iso: string) {
  try {
    localStorage.setItem(LAST_VISIT_KEY, iso);
  } catch {
    // ignore
  }
}

export function threatToVocPriority(score: number): import("./voc-api").VocPriority {
  if (score >= 75) return "p1";
  if (score >= 55) return "p2";
  if (score >= 35) return "p3";
  return "p4";
}

export function buildThreatVocReasons(item: {
  signal_type: string;
  vckev_only?: boolean;
  epss_spike?: boolean;
  has_public_exploit?: boolean;
  has_poc?: boolean;
  cisa_kev?: boolean;
}): string[] {
  const out: string[] = [`threat:${item.signal_type}`];
  if (item.vckev_only) out.push("threat:vckev_only");
  if (item.epss_spike) out.push("threat:epss_spike");
  if (item.has_public_exploit) out.push("threat:public_exploit");
  else if (item.has_poc) out.push("threat:poc");
  if (item.cisa_kev) out.push("threat:cisa_kev");
  return out;
}

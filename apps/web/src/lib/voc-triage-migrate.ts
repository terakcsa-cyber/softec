const PROCESSED_KEY = "vip:processed";
const LEGACY_TRIAGE_KEY = "vip:triageStatus";

type LegacyMap = Record<string, number>;

function cveKey(cveId: string): string {
  const id = cveId.trim().toUpperCase();
  return id.startsWith("CVE:") ? id : `CVE:${id}`;
}

/** One-time keys from localStorage to import into server triage. */
export function loadLegacyProcessedRefKeys(): string[] {
  if (typeof window === "undefined") return [];
  const keys = new Set<string>();

  try {
    const raw = localStorage.getItem(PROCESSED_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as LegacyMap;
      for (const k of Object.keys(parsed ?? {})) {
        if (parsed[k]) keys.add(k);
      }
    }
  } catch {
    // ignore
  }

  try {
    const raw = localStorage.getItem(LEGACY_TRIAGE_KEY);
    if (raw) {
      const legacy = JSON.parse(raw) as Record<string, string>;
      for (const [k, v] of Object.entries(legacy)) {
        if (v !== "done") continue;
        if (k.startsWith("BDU:") || k.startsWith("CVE:") || k.startsWith("TG:")) keys.add(k);
        else keys.add(cveKey(k));
      }
    }
  } catch {
    // ignore
  }

  return [...keys];
}

export function clearLegacyProcessedStorage(): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.removeItem(PROCESSED_KEY);
    localStorage.removeItem(LEGACY_TRIAGE_KEY);
  } catch {
    // ignore
  }
}

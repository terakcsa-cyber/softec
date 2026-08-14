export const VOC_SOURCES = ["cve", "bdu", "tg"] as const;
export type VocSource = (typeof VOC_SOURCES)[number];

export const VOC_TRIAGE_STATUSES = ["open", "claimed", "done", "dismissed"] as const;
export type VocTriageStatus = (typeof VOC_TRIAGE_STATUSES)[number];

export const VOC_PRIORITIES = ["p1", "p2", "p3", "p4"] as const;
export type VocPriority = (typeof VOC_PRIORITIES)[number];

export function vocRefKey(source: VocSource, refId: string): string {
  const id = refId.trim();
  if (source === "cve") {
    const u = id.toUpperCase();
    return u.startsWith("CVE:") ? u : `CVE:${u}`;
  }
  if (source === "bdu") {
    return id.startsWith("BDU:") ? id : `BDU:${id}`;
  }
  return id.startsWith("TG:") ? id : `TG:${id}`;
}

export function vocPriorityLabel(p: VocPriority): string {
  switch (p) {
    case "p1":
      return "P1";
    case "p2":
      return "P2";
    case "p3":
      return "P3";
    default:
      return "P4";
  }
}

export function vocStatusLabel(s: VocTriageStatus): string {
  switch (s) {
    case "open":
      return "В очереди";
    case "claimed":
      return "В работе";
    case "done":
      return "Обработано";
    case "dismissed":
      return "Не актуально";
  }
}

/** Карточка линзы «Сейчас»: P1, SLA, watchlist или БДУ P2. */
export function isVocNowItem(item: {
  status?: string | null;
  vocPriority?: string | null;
  slaBreached?: boolean | null;
  source?: string | null;
  vocReasons?: string[] | null;
}): boolean {
  if (item.status === "done" || item.status === "dismissed") return false;
  if (item.vocPriority === "p1" || item.slaBreached) return true;
  if ((item.vocReasons ?? []).some((r) => r.startsWith("watchlist:"))) return true;
  return item.source === "bdu" && item.vocPriority === "p2";
}

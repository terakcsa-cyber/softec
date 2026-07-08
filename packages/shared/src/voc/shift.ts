export const VOC_ALERT_CONDITIONS = [
  "p1_open",
  "sla_breach",
  "watchlist_p1",
  "case_exposed"
] as const;

export type VocAlertCondition = (typeof VOC_ALERT_CONDITIONS)[number];

export const VOC_ALERT_CHANNELS = ["telegram", "webhook"] as const;
export type VocAlertChannel = (typeof VOC_ALERT_CHANNELS)[number];

export function vocAlertConditionLabel(c: VocAlertCondition): string {
  switch (c) {
    case "p1_open":
      return "P1 в очереди";
    case "sla_breach":
      return "Просрочен SLA кейса";
    case "watchlist_p1":
      return "Watchlist + P1/P2";
    case "case_exposed":
      return "Исход: экспозиция подтверждена";
  }
}

export type VocKpiSnapshot = {
  windowHours: number;
  generatedAt: string;
  triage: {
    open: number;
    claimed: number;
    done: number;
    dismissed: number;
  };
  cases: {
    active: number;
    slaBreached: number;
    resolvedInWindow: number;
    avgResolutionHours: number | null;
  };
  outcomes: Record<string, number>;
  queue: {
    p1Open: number;
    p2Open: number;
    watchlistHits: number;
  };
  tg: {
    total24h: number;
    dismissed: number;
    noiseRatio: number | null;
  };
};

export type VocHandoverReport = {
  windowHours: number;
  generatedAt: string;
  authorEmail?: string | null;
  kpi: VocKpiSnapshot;
  markdown: string;
  openHotItems: Array<{ title: string; refKey: string; priority: string; slaDueAt?: string | null }>;
  resolvedItems: Array<{ title: string; outcome: string; resolvedAt: string }>;
};

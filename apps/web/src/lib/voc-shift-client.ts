export type VocAlertCondition = "p1_open" | "sla_breach" | "watchlist_p1" | "case_exposed";

export const VOC_ALERT_CONDITIONS: VocAlertCondition[] = [
  "p1_open",
  "sla_breach",
  "watchlist_p1",
  "case_exposed"
];

export function vocAlertConditionLabel(c: VocAlertCondition): string {
  switch (c) {
    case "p1_open":
      return "P1 в очереди";
    case "sla_breach":
      return "Просрочен SLA";
    case "watchlist_p1":
      return "Watchlist P1/P2";
    case "case_exposed":
      return "Экспозиция в кейсе";
  }
}

export type VocKpiSnapshot = {
  windowHours: number;
  generatedAt: string;
  triage: { open: number; claimed: number; done: number; dismissed: number };
  cases: {
    active: number;
    slaBreached: number;
    resolvedInWindow: number;
    avgResolutionHours: number | null;
  };
  outcomes: Record<string, number>;
  queue: { p1Open: number; p2Open: number; watchlistHits: number };
  tg: { total24h: number; dismissed: number; noiseRatio: number | null };
};

export type VocHandoverReport = {
  windowHours: number;
  generatedAt: string;
  authorEmail?: string | null;
  kpi: VocKpiSnapshot;
  markdown: string;
};

export type VocAlertRuleRow = {
  id: string;
  name: string;
  active: boolean;
  condition: VocAlertCondition;
  channel: "telegram" | "webhook";
  webhookUrl: string | null;
  createdAt: string;
  updatedAt: string;
};

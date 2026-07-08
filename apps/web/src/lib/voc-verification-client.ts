export type VocOutcome =
  | "not_affected"
  | "exposed"
  | "monitoring"
  | "patched"
  | "accepted_risk"
  | "needs_more_info";

export type VocPlaybookStep = {
  id: string;
  label: string;
  done: boolean;
  doneAt?: string | null;
  doneBy?: string | null;
};

export type VocPlaybook = {
  version: 1;
  steps: VocPlaybookStep[];
  generatedAt: string;
  aiGenerated?: boolean;
  contextSummary?: string | null;
};

export const VOC_OUTCOMES: VocOutcome[] = [
  "not_affected",
  "exposed",
  "monitoring",
  "patched",
  "accepted_risk",
  "needs_more_info"
];

export function vocOutcomeLabel(outcome: VocOutcome): string {
  switch (outcome) {
    case "not_affected":
      return "Не затрагивает";
    case "exposed":
      return "Экспозиция подтверждена";
    case "monitoring":
      return "На мониторинге";
    case "patched":
      return "Устранено / патч";
    case "accepted_risk":
      return "Принят риск";
    case "needs_more_info":
      return "Нужны данные";
  }
}

export function playbookProgress(playbook: VocPlaybook | null | undefined): { done: number; total: number } {
  const steps = playbook?.steps ?? [];
  return { done: steps.filter((s) => s.done).length, total: steps.length };
}

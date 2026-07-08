import type { VocPriority, VocSource } from "./triage.js";

export const VOC_OUTCOMES = [
  "not_affected",
  "exposed",
  "monitoring",
  "patched",
  "accepted_risk",
  "needs_more_info"
] as const;

export type VocOutcome = (typeof VOC_OUTCOMES)[number];

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

export function buildVocPlaybook(input: {
  source: VocSource;
  vocPriority: VocPriority;
  vocReasons?: string[];
  hasCve?: boolean;
}): VocPlaybook {
  const steps: VocPlaybookStep[] = [
    { id: "scope", label: "Определить затронутые системы и версии ПО в инвентаре", done: false },
    { id: "exposure", label: "Проверить экспозицию: периметр, VPN, публичные сервисы, сегменты", done: false },
    { id: "advisory", label: "Сверить с vendor advisory / БДУ / NVD и зафиксировать версию/патч", done: false }
  ];

  if (input.source === "cve" || input.hasCve) {
    steps.push({
      id: "kev_epss",
      label: "Проверить KEV/EPSS/PoC и необходимость срочной реакции",
      done: false
    });
  }
  if (input.source === "bdu") {
    steps.push({
      id: "fstec",
      label: "Проверить требования ФСТЭК/БДУ и сроки реагирования",
      done: false
    });
  }
  if (input.source === "tg") {
    steps.push({
      id: "tg_context",
      label: "Оценить достоверность TG-сигнала и связать с официальными источниками",
      done: false
    });
  }
  if (input.vocPriority === "p1" || input.vocPriority === "p2") {
    steps.push({
      id: "escalate",
      label: "При подтверждении — эскалировать дежурной смене / в TG",
      done: false
    });
  }
  steps.push({
    id: "evidence",
    label: "Зафиксировать evidence: версия, тикет, ссылка или причина неприменимости",
    done: false
  });

  const hot = (input.vocReasons ?? []).some((r) => /kev|epss|exploit|watchlist|p1/i.test(r));
  if (hot) {
    steps.unshift({
      id: "hot_signal",
      label: "Приоритетный сигнал: начать проверку в течение SLA",
      done: false
    });
  }

  return {
    version: 1,
    steps,
    generatedAt: new Date().toISOString()
  };
}

export function playbookProgress(playbook: VocPlaybook | null | undefined): { done: number; total: number } {
  const steps = playbook?.steps ?? [];
  const done = steps.filter((s) => s.done).length;
  return { done, total: steps.length };
}

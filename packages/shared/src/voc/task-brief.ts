import type { VocPriority, VocSource } from "./triage.js";

export type VocTaskBriefInput = {
  caseId: string;
  refKey: string;
  source: VocSource;
  refId: string;
  title: string;
  subtitle?: string | null;
  vocPriority: VocPriority;
  vocReasons?: string[];
  cveIds?: string[];
  vendorDisplay?: string | null;
  productDisplay?: string | null;
  bduName?: string | null;
  tgChannel?: string | null;
  assigneeEmail?: string | null;
};

export type VocTaskBriefOutput = {
  notesMd: string;
  evidence: string;
  taskTitle?: string;
  aiGenerated: boolean;
};

function sourceLabel(source: VocSource): string {
  if (source === "bdu") return "БДУ ФСТЭК";
  if (source === "tg") return "Telegram OSINT";
  return "NVD/CVE";
}

export function buildVocTaskBriefFallback(input: VocTaskBriefInput): VocTaskBriefOutput {
  const cveIds = (input.cveIds ?? []).filter(Boolean);
  const product =
    input.vendorDisplay && input.productDisplay
      ? `${input.vendorDisplay} / ${input.productDisplay}`
      : input.vendorDisplay || input.productDisplay || "целевой стек";
  const reasons = (input.vocReasons ?? []).slice(0, 8);
  const cveLine = cveIds.length > 0 ? cveIds.slice(0, 6).join(", ") : "—";

  const notesMd = [
    `## VOC-кейс`,
    ``,
    `**Сигнал:** ${input.title}`,
    input.subtitle?.trim() ? `**Контекст:** ${input.subtitle.trim()}` : null,
    `**Источник:** ${sourceLabel(input.source)} · ${input.refKey}`,
    `**Приоритет VOC:** ${input.vocPriority.toUpperCase()}`,
    reasons.length ? `**Почему в очереди:** ${reasons.join("; ")}` : null,
    cveIds.length ? `**Связанные CVE:** ${cveLine}` : null,
    input.bduName ? `**БДУ:** ${input.bduName}` : null,
    input.tgChannel ? `**Канал TG:** ${input.tgChannel}` : null,
    ``,
    `### Что сделать аналитику`,
    `1. Подтвердить применимость к инфраструктуре (${product}).`,
    `2. Проверить версии/экспозицию на периметре и внутри сегментов.`,
    `3. Сверить с vendor advisory / БДУ / NVD и зафиксировать план реакции.`,
    `4. После проверки — исход в кейсе VOC и закрытие задачи.`
  ]
    .filter(Boolean)
    .join("\n");

  const evidence = [
    `Проверить применимость ${cveIds.length ? cveIds.slice(0, 5).join(", ") : input.refKey} к ${product}.`,
    "Найти уязвимые версии в инвентаре / на периметре (VPN, edge, публичные сервисы).",
    "Проверить наличие патча, workaround или официального advisory.",
    "Оценить признаки эксплуатации (KEV, публичные PoC, активность в TG).",
    "Зафиксировать результат: версия, тикет, ссылка на advisory или причина неприменимости."
  ].join("\n");

  return {
    notesMd,
    evidence,
    taskTitle: `VOC: ${input.title}`,
    aiGenerated: false
  };
}

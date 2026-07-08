import type { VocPriority, VocSource } from "./triage.js";
import type { VocPlaybook, VocPlaybookStep } from "./verification.js";

export type VocPlaybookContextInput = {
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
  tgChannel?: string | null;
  cveDetails?: Array<{
    cveId: string;
    cvss?: number | null;
    epss?: number | null;
    kev?: boolean;
    vckevOnly?: boolean;
    vulncheckKev?: boolean;
    epssSpike?: boolean;
    hasPoc?: boolean;
    hasPublicExploit?: boolean;
    description?: string | null;
    vendor?: string | null;
    product?: string | null;
  }>;
  bdu?: {
    bduId?: string;
    name?: string | null;
    description?: string | null;
    vendors?: string | null;
    softwareNames?: string | null;
    solution?: string | null;
    cvss?: number | null;
    hasExploit?: boolean;
    severity?: string | null;
  };
  signals?: {
    kev?: boolean;
    vckevOnly?: boolean;
    vulncheckKev?: boolean;
    epssSpike?: boolean;
    hasPoc?: boolean;
    hasPublicExploit?: boolean;
    highEpss?: boolean;
    hasExploit?: boolean;
    watchlist?: boolean;
    fstec?: boolean;
  };
};

function slugStepId(label: string, index: number): string {
  const base = label
    .toLowerCase()
    .replace(/[^a-z0-9а-яё]+/gi, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 36);
  return `s${index + 1}-${base || "step"}`;
}

export function playbookFromStepLabels(
  labels: string[],
  opts?: { aiGenerated?: boolean; contextSummary?: string | null }
): VocPlaybook {
  const steps: VocPlaybookStep[] = labels
    .map((label) => label.trim())
    .filter(Boolean)
    .slice(0, 12)
    .map((label, i) => ({
      id: slugStepId(label, i),
      label,
      done: false
    }));

  if (!steps.some((s) => /evidence|зафиксир|документ/i.test(s.label))) {
    steps.push({
      id: "evidence",
      label: "Зафиксировать evidence: версия, тикет, ссылка или причина неприменимости",
      done: false
    });
  }

  return {
    version: 1,
    steps,
    generatedAt: new Date().toISOString(),
    aiGenerated: opts?.aiGenerated ?? false,
    contextSummary: opts?.contextSummary ?? null
  };
}

export function buildVocPlaybookFromContext(input: VocPlaybookContextInput): VocPlaybook {
  const labels: string[] = [];
  const product =
    input.vendorDisplay && input.productDisplay
      ? `${input.vendorDisplay} / ${input.productDisplay}`
      : input.vendorDisplay || input.productDisplay || "целевой стек";

  labels.push(`Определить наличие ${product} в инвентаре и актуальные версии`);

  const topCve = input.cveDetails?.[0];
  if (topCve?.kev || input.signals?.kev) {
    labels.push(`Срочно: ${topCve?.cveId ?? "CVE"} в KEV — проверить экспозицию на периметре в первую очередь`);
  }
  if (topCve?.vckevOnly || input.signals?.vckevOnly) {
    labels.push(
      `VulnCheck KEV (не CISA): ${topCve?.cveId ?? "CVE"} — проверить эксплуатацию в дикой природе до появления в CISA KEV`
    );
  } else if (topCve?.vulncheckKev || input.signals?.vulncheckKev) {
    labels.push(`VulnCheck KEV: ${topCve?.cveId ?? "CVE"} — сверить evidence и приоритет патча`);
  }
  if (topCve?.epssSpike || input.signals?.epssSpike) {
    labels.push(
      `EPSS spike у ${topCve?.cveId ?? "CVE"} — пересмотреть окно патча, вероятность эксплуатации выросла`
    );
  }
  if (topCve?.hasPublicExploit || input.signals?.hasPublicExploit) {
    labels.push(`Публичный эксплойт для ${topCve?.cveId ?? "CVE"} — проверить WAF/IDS и сегменты с доступом извне`);
  } else if (topCve?.hasPoc || input.signals?.hasPoc) {
    labels.push(`PoC для ${topCve?.cveId ?? "CVE"} — оценить простоту воспроизведения на стенде`);
  }
  if (topCve?.epss != null && topCve.epss >= 0.3) {
    labels.push(`Учесть EPSS ${topCve.epss.toFixed(2)} для ${topCve.cveId}: приоритет сегментов с сетевым доступом`);
  }

  if (input.source === "bdu" && input.bdu) {
    labels.push(
      `Сверить БДУ ${input.bdu.bduId ?? input.refId}: ${(input.bdu.name ?? "").slice(0, 120)} с регламентом ФСТЭК`
    );
    if (input.bdu.solution) {
      labels.push(`Проверить выполнимость мер: ${input.bdu.solution.slice(0, 160)}`);
    }
  }

  if (input.source === "tg") {
    labels.push(
      `Валидировать TG-сигнал${input.tgChannel ? ` (@${input.tgChannel})` : ""} по NVD/БДУ/vendor advisory`
    );
  }

  if (topCve?.description) {
    labels.push(`Проверить вектор из описания CVE: ${topCve.description.slice(0, 180)}`);
  }

  if (input.vocPriority === "p1" || input.vocPriority === "p2") {
    labels.push("При подтверждении экспозиции — эскалировать дежурной смене и зафиксировать в TG");
  }

  if (input.signals?.watchlist) {
    labels.push("Watchlist: проверить все системы, где встречается вендор/продукт из правил смены");
  }

  return playbookFromStepLabels(labels, {
    aiGenerated: false,
    contextSummary: input.subtitle ?? input.title
  });
}

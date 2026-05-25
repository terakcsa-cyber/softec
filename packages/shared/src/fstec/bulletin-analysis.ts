import type { FstecBulletinParsed, FstecBulletinParsedItem } from "./bulletin-parse.js";

export type BulletinAnalysisContextItem = {
  ordinal: number;
  bduId: string;
  headline: string;
  cvssFromBulletin: string;
  cvssRegistry: number | null;
  severityRegistry: string | null;
  hasExploit: boolean;
  hasFix: boolean;
  inRegistry: boolean;
  linkedCves: string[];
  maxCveRiskScore: number | null;
  urgencyScore: number;
  urgencyLabel: "critical" | "high" | "medium" | "low";
  bodyExcerpt: string;
  remediationExcerpt: string | null;
  compensatingExcerpt: string | null;
};

export type BulletinAnalysisContext = {
  bulletin: {
    title: string | null;
    referenceNo: string | null;
    itemCount: number;
  };
  introExcerpt: string | null;
  stats: {
    totalItems: number;
    inRegistry: number;
    missingFromRegistry: number;
    highOrCriticalBulletin: number;
    withExploit: number;
    withLinkedCve: number;
  };
  items: BulletinAnalysisContextItem[];
  precomputedPriorityOrder: string[];
};

function cvssNum(label: string, registry: number | null): number {
  if (registry != null && Number.isFinite(registry)) return registry;
  const l = label.toLowerCase();
  if (l.includes("крит")) return 9.5;
  if (l.includes("высок")) return 8;
  if (l.includes("средн")) return 5.5;
  if (l.includes("низк")) return 3;
  return 5;
}

function urgencyFromScore(score: number): BulletinAnalysisContextItem["urgencyLabel"] {
  if (score >= 85) return "critical";
  if (score >= 65) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function excerpt(s: string | null | undefined, max: number): string {
  const t = (s ?? "").replace(/\s+/g, " ").trim();
  if (t.length <= max) return t;
  return `${t.slice(0, max - 1)}…`;
}

export function buildBulletinAnalysisContext(input: {
  bulletin: {
    title?: string | null;
    referenceNo?: string | null;
  };
  parsed: FstecBulletinParsed;
  registry: Array<{
    bduId: string;
    found: boolean;
    name?: string | null;
    cvssScore?: number | null;
    severity?: string | null;
    hasExploit?: boolean;
    hasFix?: boolean;
    linkedCves?: Array<{ cveId: string; riskScore?: number | null }>;
  }>;
}): BulletinAnalysisContext {
  const regMap = new Map(input.registry.map((r) => [r.bduId, r]));
  const items: BulletinAnalysisContextItem[] = (input.parsed.items ?? []).map((it) => {
    const reg = regMap.get(it.bduId);
    const linked = reg?.linkedCves ?? [];
    const maxRisk = linked.reduce<number | null>((m, c) => {
      const rs = c.riskScore;
      if (rs == null || !Number.isFinite(rs)) return m;
      return m == null ? rs : Math.max(m, rs);
    }, null);
    const cvssR = reg?.cvssScore ?? null;
    const cvssB = it.cvssLabel ?? "неизвестный";
    let score = cvssNum(cvssB, cvssR) * 8;
    if (reg?.hasExploit) score += 22;
    if (maxRisk != null) score += Math.min(25, maxRisk * 0.25);
    if (cvssB.toLowerCase().includes("крит")) score += 12;
    if (!reg?.hasFix) score += 5;
    score = Math.min(100, Math.round(score));

    return {
      ordinal: it.ordinal,
      bduId: it.bduId,
      headline: it.headline || reg?.name || `BDU:${it.bduId}`,
      cvssFromBulletin: cvssB,
      cvssRegistry: cvssR,
      severityRegistry: reg?.severity ?? null,
      hasExploit: Boolean(reg?.hasExploit),
      hasFix: Boolean(reg?.hasFix),
      inRegistry: Boolean(reg?.found),
      linkedCves: linked.map((c) => c.cveId),
      maxCveRiskScore: maxRisk,
      urgencyScore: score,
      urgencyLabel: urgencyFromScore(score),
      bodyExcerpt: excerpt(it.body, 520),
      remediationExcerpt: it.remediation ? excerpt(it.remediation, 380) : null,
      compensatingExcerpt: it.compensatingMeasures ? excerpt(it.compensatingMeasures, 320) : null
    };
  });

  items.sort((a, b) => b.urgencyScore - a.urgencyScore);
  const precomputedPriorityOrder = items.map((i) => `BDU:${i.bduId}`);

  const highOrCritical = items.filter(
    (i) =>
      i.urgencyLabel === "critical" ||
      i.urgencyLabel === "high" ||
      i.cvssFromBulletin.toLowerCase().includes("крит") ||
      i.cvssFromBulletin.toLowerCase().includes("высок")
  ).length;

  return {
    bulletin: {
      title: input.bulletin.title ?? input.parsed.title ?? null,
      referenceNo: input.bulletin.referenceNo ?? input.parsed.referenceHint ?? null,
      itemCount: items.length
    },
    introExcerpt: input.parsed.intro ? excerpt(input.parsed.intro, 1200) : null,
    stats: {
      totalItems: items.length,
      inRegistry: items.filter((i) => i.inRegistry).length,
      missingFromRegistry: items.filter((i) => !i.inRegistry).length,
      highOrCriticalBulletin: highOrCritical,
      withExploit: items.filter((i) => i.hasExploit).length,
      withLinkedCve: items.filter((i) => i.linkedCves.length > 0).length
    },
    items,
    precomputedPriorityOrder
  };
}

type LlmJson = Record<string, unknown>;

function asStr(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v.trim() : null;
}

function asStrArr(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.map((x) => String(x).trim()).filter(Boolean);
}

function deriveGraphFromItems(
  items: BulletinAnalysisContextItem[],
  themes: string[]
): { nodes: { id: string; label: string; type: string }[]; edges: { from: string; to: string; label: string }[] } {
  const nodes: { id: string; label: string; type: string }[] = [
    { id: "attacker", label: "Внешний/внутренний нарушитель", type: "attacker" }
  ];
  const edges: { from: string; to: string; label: string }[] = [];

  const top = items.slice(0, 4);
  top.forEach((it, idx) => {
    const vid = `vector_${idx + 1}`;
    nodes.push({
      id: vid,
      label: `Эксплуатация: ${it.headline.slice(0, 48)}`,
      type: "vector"
    });
    edges.push({ from: "attacker", to: vid, label: "доступ / ввод" });
    const aid = `asset_${idx + 1}`;
    nodes.push({
      id: aid,
      label: it.linkedCves[0] ? `ПО / CVE ${it.linkedCves[0]}` : "Уязвимый компонент",
      type: "asset"
    });
    edges.push({ from: vid, to: aid, label: `BDU:${it.bduId}` });
    const iid = `impact_${idx + 1}`;
    nodes.push({
      id: iid,
      label: it.hasExploit ? "Компрометация / RCE" : "Нарушение КБ / DoS",
      type: "impact"
    });
    edges.push({ from: aid, to: iid, label: "воздействие" });
  });

  if (themes.length > 0) {
    nodes.push({ id: "theme", label: themes[0]!.slice(0, 60), type: "service" });
    edges.push({ from: "attacker", to: "theme", label: "общий вектор" });
  }

  return { nodes, edges };
}

/** Дополняет и выравнивает ответ LLM по бюллетеню. */
export function normalizeFstecBulletinAnalysis(
  raw: LlmJson,
  ctx: BulletinAnalysisContext
): LlmJson {
  const out: LlmJson = { ...raw };

  if (!asStr(out.title)) {
    out.title = ctx.bulletin.title ?? `Бюллетень ФСТЭК (${ctx.stats.totalItems} BDU)`;
  }

  const keyFindings = asStrArr(out.keyFindings);
  if (keyFindings.length === 0 && asStr(out.executiveSummary)) {
    out.keyFindings = asStr(out.executiveSummary)!
      .split(/(?<=[.!?])\s+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 20)
      .slice(0, 5);
  }

  const rm = (out.riskMatrix && typeof out.riskMatrix === "object" ? out.riskMatrix : {}) as LlmJson;
  out.riskMatrix = {
    itemCount: Number(rm.itemCount) || ctx.stats.totalItems,
    highOrCriticalCount: Number(rm.highOrCriticalCount) || ctx.stats.highOrCriticalBulletin,
    withPublicExploit: Number(rm.withPublicExploit) || ctx.stats.withExploit,
    needsImmediatePatch: Number(rm.needsImmediatePatch) || ctx.items.filter((i) => i.urgencyScore >= 65).length,
    inRegistry: ctx.stats.inRegistry,
    missingFromRegistry: ctx.stats.missingFromRegistry,
    withLinkedCve: ctx.stats.withLinkedCve
  };

  let priorityOrder = asStrArr(out.priorityOrder);
  if (priorityOrder.length === 0) priorityOrder = ctx.precomputedPriorityOrder;
  out.priorityOrder = priorityOrder;

  const itemSummaries = Array.isArray(out.itemSummaries) ? out.itemSummaries : [];
  if (itemSummaries.length < ctx.items.length) {
    const byBdu = new Map<string, LlmJson>();
    for (const rawItem of itemSummaries) {
      if (!rawItem || typeof rawItem !== "object") continue;
      const row = rawItem as LlmJson;
      const id = asStr(row.bduId)?.replace(/^BDU:/i, "");
      if (id) byBdu.set(id, row);
    }
    out.itemSummaries = ctx.items.map((it) => {
      const existing = byBdu.get(it.bduId);
      if (existing) {
        return {
          ...existing,
          ordinal: existing.ordinal ?? it.ordinal,
          bduId: it.bduId,
          priority: existing.priority ?? Math.max(1, Math.min(5, Math.ceil((100 - it.urgencyScore) / 20))),
          cvssFromBulletin: existing.cvssFromBulletin ?? it.cvssFromBulletin,
          registryCvss: existing.registryCvss ?? it.cvssRegistry,
          linkedCves: asStrArr(existing.linkedCves).length ? existing.linkedCves : it.linkedCves
        };
      }
      return {
        ordinal: it.ordinal,
        bduId: it.bduId,
        priority: Math.max(1, Math.min(5, Math.ceil((100 - it.urgencyScore) / 20))),
        headline: it.headline,
        summary: it.bodyExcerpt,
        cvssFromBulletin: it.cvssFromBulletin,
        registryCvss: it.cvssRegistry,
        exploitUrgency:
          it.urgencyLabel === "critical" || it.urgencyLabel === "high" ? "immediate" : it.urgencyLabel === "medium" ? "soon" : "planned",
        attackFlow: [],
        remediation: it.remediationExcerpt ? [it.remediationExcerpt] : [],
        compensatingIfAny: it.compensatingExcerpt ? [it.compensatingExcerpt] : [],
        linkedCves: it.linkedCves,
        urgencyScore: it.urgencyScore
      };
    });
  }

  const graph = out.combinedGraph;
  const graphOk =
    graph &&
    typeof graph === "object" &&
    Array.isArray((graph as LlmJson).nodes) &&
    ((graph as LlmJson).nodes as unknown[]).length > 0;
  if (!graphOk) {
    out.combinedGraph = deriveGraphFromItems(ctx.items, asStrArr(out.crossCuttingThemes));
  }

  if (!asStr(out.bulletinContext) && ctx.introExcerpt) {
    out.bulletinContext = ctx.introExcerpt;
  }

  if (!asStr(out.executiveSummary) && asStr(out.managementBrief)) {
    out.executiveSummary = asStr(out.managementBrief);
  }

  const actionPlan = buildStructuredActionPlan(ctx);
  out.actionPlan = actionPlan;
  out.combinedRemediationPlan = flattenActionPlan(actionPlan);

  const llmPhases = Array.isArray(out.timelinePhases) ? out.timelinePhases : [];
  if (llmPhases.length > 0 && Array.isArray((llmPhases[0] as LlmJson)?.actions)) {
    out.timelinePhases = llmPhases;
  } else {
    out.timelinePhases = actionPlan.phases.map((ph) => ({
      phase: ph.title,
      horizon: ph.horizon,
      actions: ph.steps.map((s) =>
        s.bduId ? `BDU:${s.bduId} — ${s.title}` : s.title
      )
    }));
  }

  return out;
}

export type BulletinActionStep = {
  order: number;
  bduId: string | null;
  title: string;
  detail: string;
  actionType: "patch" | "compensate" | "inventory" | "governance" | "monitor";
};

export type BulletinActionPhase = {
  id: string;
  title: string;
  horizon: string;
  owner: string;
  goal: string;
  steps: BulletinActionStep[];
};

export type BulletinActionPlan = {
  introduction: string;
  phases: BulletinActionPhase[];
  complianceNote: string | null;
};

const ACTION_TYPE_LABEL: Record<BulletinActionStep["actionType"], string> = {
  patch: "Установка обновления",
  compensate: "Компенсирующая мера",
  inventory: "Инвентаризация / проверка",
  governance: "Организационные меры",
  monitor: "Мониторинг"
};

/** Понятный пофазовый план: кто, когда, что делать по каждой BDU из бюллетеня. */
export function buildStructuredActionPlan(ctx: BulletinAnalysisContext): BulletinActionPlan {
  const ref = ctx.bulletin.referenceNo ? ` (${ctx.bulletin.referenceNo})` : "";
  const introduction =
    `План сформирован по официальному бюллетеню ФСТЭК${ref}: ${ctx.stats.totalItems} уязвимостей (БДУ). ` +
    `Цель — выполнить требования по снижению риска в инфраструктуре оператора КИИ: ` +
    `сначала закрыть критичные и эксплуатируемые, затем остальные, зафиксировать результат для ИБ и руководства.`;

  const complianceNote =
    ctx.stats.missingFromRegistry > 0
      ? `Внимание: ${ctx.stats.missingFromRegistry} позиций не найдены в локальной БДУ — уточните идентификаторы и карточки на bdu.fstec.ru перед отчётом.`
      : null;

  const mkStep = (
    it: BulletinAnalysisContextItem,
    order: number,
    actionType: BulletinActionStep["actionType"]
  ): BulletinActionStep => {
    let detail = it.remediationExcerpt ?? "";
    if (!detail && it.compensatingExcerpt) {
      detail = it.compensatingExcerpt;
      actionType = "compensate";
    }
    if (!detail) {
      detail =
        it.hasExploit
          ? "Подтвердить наличие уязвимого ПО в инвентаризации. При экспозиции — установить обновление из бюллетеня/вендора или изолировать систему до патча."
          : "Сверить версии ПО с бюллетенем. При наличии в контуре — запланировать и установить обновление по рекомендации ФСТЭК.";
    }
    const typeLabel = ACTION_TYPE_LABEL[actionType];
    return {
      order,
      bduId: it.bduId,
      title: `${typeLabel}: ${it.headline}`,
      detail,
      actionType
    };
  };

  const immediate = ctx.items.filter((i) => i.urgencyScore >= 65);
  const shortTerm = ctx.items.filter((i) => i.urgencyScore >= 40 && i.urgencyScore < 65);
  const planned = ctx.items.filter((i) => i.urgencyScore < 40);

  const phases: BulletinActionPhase[] = [];

  if (immediate.length > 0) {
    phases.push({
      id: "immediate",
      title: "Фаза 1 — Срочно (0–72 часа)",
      horizon: "0–72 ч",
      owner: "Владельцы систем + ИБ + эксплуатация",
      goal:
        "Устранить или изолировать уязвимости с высоким CVSS/признаками эксплуатации, чтобы исключить немедленный риск для КИИ.",
      steps: immediate.map((it, idx) =>
        mkStep(it, idx + 1, it.compensatingExcerpt && !it.remediationExcerpt ? "compensate" : "patch")
      )
    });
  }

  if (shortTerm.length > 0) {
    phases.push({
      id: "short",
      title: "Фаза 2 — Краткосрочно (до 2 недель)",
      horizon: "3–14 дней",
      owner: "Владельцы продуктов + ИБ",
      goal: "Закрыть оставшиеся уязвимости средней срочности в плановых окнах обслуживания.",
      steps: shortTerm.map((it, idx) => mkStep(it, idx + 1, "patch"))
    });
  }

  if (planned.length > 0) {
    phases.push({
      id: "planned",
      title: "Фаза 3 — Плановое устранение",
      horizon: "до 30 дней",
      owner: "Владельцы систем",
      goal: "Завершить устранение низкоприоритетных позиций после оценки фактической экспозиции.",
      steps: planned.map((it, idx) => mkStep(it, idx + 1, "patch"))
    });
  }

  phases.push({
    id: "verify",
    title: "Фаза 4 — Подтверждение и отчётность",
    horizon: "после патчей",
    owner: "ИБ + GRC / комплаенс",
    goal: "Доказать выполнение мер по бюллетеню и зафиксировать остаточные риски.",
    steps: [
      {
        order: 1,
        bduId: null,
        title: "Инвентаризация: сопоставить все BDU бюллетеня с CMDB/учётом активов",
        detail:
          "По каждой позиции зафиксировать: затронуто ли ПО, версия, сегмент сети, владелец, статус (устранено / не применимо / компенсация).",
        actionType: "inventory"
      },
      {
        order: 2,
        bduId: null,
        title: "Повторная проверка устранения (сканер/версии/контроль целостности)",
        detail: "Для закрытых BDU — подтвердить версию патча или применённые компенсирующие меры.",
        actionType: "monitor"
      },
      {
        order: 3,
        bduId: null,
        title: "Отчёт руководству и внутренний тикет на закрытие",
        detail:
          "Краткая сводка: сколько BDU устранено, что в работе, что не применимо; приложить ссылки на BDU и CVE.",
        actionType: "governance"
      }
    ]
  });

  return { introduction, phases, complianceNote };
}

function flattenActionPlan(plan: BulletinActionPlan): string[] {
  const lines: string[] = [plan.introduction];
  for (const ph of plan.phases) {
    lines.push(`[${ph.horizon}] ${ph.title} — ${ph.goal}`);
    for (const s of ph.steps) {
      const bdu = s.bduId ? `BDU:${s.bduId} — ` : "";
      lines.push(`${bdu}${s.title}. ${s.detail}`);
    }
  }
  if (plan.complianceNote) lines.push(plan.complianceNote);
  return lines;
}

export const FSTEC_BULLETIN_PROMPT_VERSION = "fstec-bulletin-v3";

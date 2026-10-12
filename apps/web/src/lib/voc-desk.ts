import type { VocDeskDecision, VocQueueItem } from "./voc-api";
import { slaRemainingLabel } from "./voc-case-client";
import { vocIntelContext } from "./voc-queue-context";
import { hasWatchlistHit } from "./voc-watchlist-client";

export type DeskFilter = "desk" | "burning" | "ours" | "bdu" | "history";

export type DeskRow = {
  key: string;
  primary: VocQueueItem;
  members: VocQueueItem[];
  product: string;
  ident: string;
  phrase: string;
  evidence: string[];
  ours: boolean;
  burning: boolean;
  bduOnWatch: boolean;
  onDesk: boolean;
  when: string;
};

const CVE_RE = /^CVE-\d{4}-\d+/i;

function cveIdsOf(item: VocQueueItem): string[] {
  const ids: string[] = [];
  if (item.source === "cve") ids.push(item.refId);
  const payload = item.payload ?? {};
  for (const key of ["cveIds", "cve_ids", "criticalCveIds"]) {
    const raw = payload[key];
    if (!Array.isArray(raw)) continue;
    for (const value of raw) ids.push(String(value));
  }
  return [...new Set(ids.map((id) => id.trim().toUpperCase()).filter((id) => CVE_RE.test(id)))];
}

function groupKey(item: VocQueueItem): string {
  const cve = cveIdsOf(item)[0];
  if (cve) return `CVE:${cve}`;
  return item.refKey;
}

function sourceRank(source: string): number {
  if (source === "cve") return 0;
  if (source === "bdu") return 1;
  return 2;
}

function isOpenStatus(status: string): boolean {
  return status === "open" || status === "claimed";
}

function pickPrimary(members: VocQueueItem[]): VocQueueItem {
  const open = members.filter((item) => isOpenStatus(item.status));
  const pool = open.length ? open : members;
  return [...pool].sort((a, b) => sourceRank(a.source) - sourceRank(b.source) || b.vocScore - a.vocScore)[0]!;
}

function flagsOf(item: VocQueueItem): { kev: boolean; exploit: boolean; fix: boolean | null } {
  const payload = item.payload ?? {};
  const reasons = item.vocReasons.join(" ").toLowerCase();
  const kev = Boolean(payload.exploit_known || payload.vulncheck_kev || payload.vckev_only) || reasons.includes("kev");
  const exploit =
    Boolean(payload.has_public_exploit || payload.has_poc || payload.has_exploit) ||
    reasons.includes("эксплойт") ||
    reasons.includes("poc");
  const fix =
    typeof payload.has_fix === "boolean"
      ? payload.has_fix
      : payload.fix_status === "yes" || payload.fix_status === "available"
        ? true
        : payload.fix_status === "no" || payload.fix_status === "none"
          ? false
          : null;
  return { kev, exploit, fix };
}

function productOf(item: VocQueueItem): string {
  const intel = vocIntelContext(item);
  const named = [intel?.product, intel?.vendor].filter(Boolean).join(" · ");
  if (named) return named;
  const title = item.title?.trim();
  if (title && title !== item.refId) return title;
  return item.refId;
}

function phraseOf(input: {
  ours: boolean;
  kev: boolean;
  exploit: boolean;
  slaBreached: boolean;
  hasCase: boolean;
  hasBdu: boolean;
  fix: boolean | null;
}): string {
  if (input.slaBreached && input.hasCase) return "SLA вышел. Решение уже «чиним».";
  if (input.ours && (input.kev || input.exploit)) return "Наш продукт, эксплуатация публичная.";
  if (input.ours && input.hasBdu) return "Бюллетень ФСТЭК на продукт из контура.";
  if (input.ours && input.fix === false) return "Наш продукт, исправления ещё нет.";
  if (input.ours) return "Совпало с контуром. Нужно решение.";
  if (input.kev || input.exploit) return "Громкое, в контуре не найдено.";
  if (input.hasBdu) return "Бюллетень ФСТЭК без совпадения с контуром.";
  return "Нужно решение: наше это или нет.";
}

function evidenceOf(members: VocQueueItem[], primary: VocQueueItem): string[] {
  const chips: string[] = [];
  const intel = vocIntelContext(primary);
  if (intel) {
    for (const chip of intel.chips) chips.push(chip.label);
  }
  const bdu = members.find((item) => item.source === "bdu");
  if (bdu) chips.push(bdu.refId);
  const tg = members.filter((item) => item.source === "tg").length;
  if (tg > 0) chips.push(tg === 1 ? "1 пост" : `${tg} поста`);
  const cve = members.find((item) => item.source === "cve");
  if (cve && primary.source !== "cve") chips.unshift(cve.refId);
  return [...new Set(chips)].slice(0, 5);
}

export function buildDeskRows(items: VocQueueItem[]): DeskRow[] {
  const groups = new Map<string, VocQueueItem[]>();
  for (const item of items) {
    const key = groupKey(item);
    const list = groups.get(key);
    if (list) list.push(item);
    else groups.set(key, [item]);
  }

  const rows: DeskRow[] = [];
  for (const [key, members] of groups) {
    const primary = pickPrimary(members);
    const ours = members.some((item) => hasWatchlistHit(item));
    const signal = members.reduce(
      (acc, item) => {
        const flags = flagsOf(item);
        return {
          kev: acc.kev || flags.kev,
          exploit: acc.exploit || flags.exploit,
          fix: acc.fix === false || flags.fix === false ? false : acc.fix ?? flags.fix
        };
      },
      { kev: false, exploit: false, fix: null as boolean | null }
    );
    const hasCase = members.some((item) => Boolean(item.caseId));
    const slaBreached = members.some((item) => Boolean(item.slaBreached) && Boolean(item.caseId));
    const hasBdu = members.some((item) => item.source === "bdu");
    const onDesk = members.some((item) => isOpenStatus(item.status));
    const burning = (slaBreached && hasCase) || (ours && (signal.kev || signal.exploit));
    const when = slaBreached
      ? "просрочен"
      : primary.caseId && primary.slaDueAt
        ? slaRemainingLabel(primary.slaDueAt)
        : "";
    rows.push({
      key,
      primary,
      members,
      product: productOf(primary),
      ident: primary.refId,
      phrase: phraseOf({
        ours,
        kev: signal.kev,
        exploit: signal.exploit,
        slaBreached,
        hasCase,
        hasBdu,
        fix: signal.fix
      }),
      evidence: evidenceOf(members, primary),
      ours,
      burning,
      bduOnWatch: hasBdu && ours,
      onDesk,
      when
    });
  }

  return rows.sort((a, b) => deskRank(a) - deskRank(b) || String(b.primary.publishedAt ?? "").localeCompare(String(a.primary.publishedAt ?? "")));
}

function deskRank(row: DeskRow): number {
  if (row.primary.slaBreached && row.primary.caseId) return 0;
  if (row.ours && row.burning) return 1;
  if (row.bduOnWatch) return 2;
  if (row.ours) return 3;
  if (row.primary.vocPriority === "p1" || row.primary.vocPriority === "p2") return 4;
  return 5;
}

export function deskStats(rows: DeskRow[]) {
  const live = rows.filter((row) => row.onDesk);
  return {
    burning: live.filter((row) => row.burning).length,
    ours: live.filter((row) => row.ours && !row.primary.caseId && row.primary.status === "open").length,
    bdu: live.filter((row) => row.bduOnWatch).length
  };
}

export function filterDeskRows(rows: DeskRow[], filter: DeskFilter): DeskRow[] {
  if (filter === "history") return rows.filter((row) => !row.onDesk);
  const live = rows.filter((row) => row.onDesk);
  if (filter === "burning") return live.filter((row) => row.burning);
  if (filter === "ours") return live.filter((row) => row.ours && !row.primary.caseId && row.primary.status === "open");
  if (filter === "bdu") return live.filter((row) => row.bduOnWatch);
  return live;
}

export function deskDecisionLabel(decision: VocDeskDecision | null | undefined): string {
  if (decision === "fixing") return "Чиним";
  if (decision === "waiting_patch") return "Ждём патч";
  if (decision === "not_ours") return "Не наше";
  if (decision === "accepted_risk") return "Принятый риск";
  return "";
}

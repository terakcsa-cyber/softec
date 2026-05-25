import { extractBduIds } from "./bdu-extract.js";

export type FstecBulletinCvssLabel =
  | "критический"
  | "высокий"
  | "средний"
  | "низкий"
  | "неизвестный";

export type FstecBulletinParsedItem = {
  ordinal: number;
  bduId: string;
  cvssLabel: FstecBulletinCvssLabel;
  headline: string;
  body: string;
  remediation: string | null;
  compensatingMeasures: string | null;
};

export type FstecBulletinParsed = {
  title: string | null;
  subject: string | null;
  referenceHint: string | null;
  intro: string | null;
  items: FstecBulletinParsedItem[];
  orphanBduIds: string[];
};

const ITEM_START_RE = /(?:^|\n)\s*(\d{1,3})\.\s*Уязвимость/gi;
const CVSS_LABEL_RE =
  /уровень\s+опасности\s+по\s+CVSS\s+3\.1\s*[—–-]\s*(критический|высокий|средний|низкий)/i;
const REMEDIATION_START_RE =
  /(?:^|\n)\s*(В\s+целях\s+предотвращения|В\s+случае\s+невозможности)/i;

function normalizeCvssLabel(raw: string | undefined): FstecBulletinCvssLabel {
  const s = (raw ?? "").toLowerCase();
  if (s.includes("крит")) return "критический";
  if (s.includes("высок")) return "высокий";
  if (s.includes("средн")) return "средний";
  if (s.includes("низк")) return "низкий";
  return "неизвестный";
}

function firstBduInSection(section: string): string | null {
  const m = section.match(/BDU:\s*(\d{4}-\d{4,6})/i);
  return m ? m[1]! : null;
}

function extractHeadline(section: string): string {
  const oneLine = section.replace(/\s+/g, " ").trim();
  const linked = oneLine.match(
    /^Уязвимость\s+(.+?)(?:,\s*\(BDU:|,\s*связанная|\.\s*\(BDU:)/i
  );
  if (linked?.[1]) return linked[1].trim();
  const short = oneLine.match(/^Уязвимость\s+(.{10,200}?)(?:\.|,)/i);
  return (short?.[1] ?? oneLine.slice(0, 240)).trim();
}

function splitRemediation(section: string): {
  body: string;
  remediation: string | null;
  compensatingMeasures: string | null;
} {
  const m = section.match(REMEDIATION_START_RE);
  if (!m || m.index == null) {
    return { body: section.trim(), remediation: null, compensatingMeasures: null };
  }
  const body = section.slice(0, m.index).trim();
  const tail = section.slice(m.index).trim();
  const compMatch = tail.match(
    /(?:^|\n)\s*(В\s+случае\s+невозможности[\s\S]*)$/i
  );
  if (compMatch?.[1]) {
    const remEnd = tail.indexOf(compMatch[1]);
    const remediation = tail.slice(0, remEnd).trim() || null;
    return {
      body,
      remediation,
      compensatingMeasures: compMatch[1].trim(),
    };
  }
  return { body, remediation: tail, compensatingMeasures: null };
}

function extractTitleBlock(text: string): {
  title: string | null;
  subject: string | null;
  intro: string | null;
} {
  const norm = text.replace(/\r\n/g, "\n");
  const analysisIdx = norm.search(/Анализ\s+сведений/i);
  const header = analysisIdx > 0 ? norm.slice(0, analysisIdx) : norm.slice(0, 2500);
  const lines = header
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 3);
  const title =
    lines.find((l) => /бюллетен|бсп|защищенност|кии|фстэк/i.test(l)) ??
    lines[0] ??
    null;
  const subject =
    lines.find((l) => /^о\s+/i.test(l) || /меры\s+по/i.test(l)) ?? null;
  const intro =
    analysisIdx > 0
      ? norm
          .slice(analysisIdx, norm.search(ITEM_START_RE) > 0 ? norm.search(ITEM_START_RE) : undefined)
          .trim()
          .slice(0, 4000) || null
      : null;
  return { title, subject, intro };
}

/** Парсит текст официального бюллетеня ФСТЭК (нумерованные «Уязвимость … (BDU:…)). */
export function parseFstecBulletinText(
  text: string,
  opts?: { referenceHint?: string | null }
): FstecBulletinParsed {
  const norm = text.replace(/\r\n/g, "\n").replace(/\u00a0/g, " ");
  const { title, subject, intro } = extractTitleBlock(norm);

  const starts: { ordinal: number; index: number }[] = [];
  let m: RegExpExecArray | null;
  const re = new RegExp(ITEM_START_RE.source, ITEM_START_RE.flags);
  while ((m = re.exec(norm)) !== null) {
    starts.push({ ordinal: Number(m[1]), index: m.index + (m[0].startsWith("\n") ? 1 : 0) });
  }

  const items: FstecBulletinParsedItem[] = [];
  for (let i = 0; i < starts.length; i++) {
    const start = starts[i]!;
    const end = starts[i + 1]?.index ?? norm.length;
    let section = norm.slice(start.index, end).trim();
    section = section.replace(/^\d{1,3}\.\s*/, "");

    const bduId = firstBduInSection(section);
    if (!bduId) continue;

    const cvssM = section.match(CVSS_LABEL_RE);
    const { body, remediation, compensatingMeasures } = splitRemediation(section);

    items.push({
      ordinal: start.ordinal,
      bduId,
      cvssLabel: normalizeCvssLabel(cvssM?.[1]),
      headline: extractHeadline(section),
      body: body.replace(/^Уязвимость\s+/i, "").trim(),
      remediation,
      compensatingMeasures,
    });
  }

  const itemBdu = new Set(items.map((it) => it.bduId));
  const orphanBduIds = extractBduIds(norm).filter((id) => !itemBdu.has(id));

  return {
    title,
    subject,
    referenceHint: opts?.referenceHint ?? null,
    intro,
    items,
    orphanBduIds,
  };
}

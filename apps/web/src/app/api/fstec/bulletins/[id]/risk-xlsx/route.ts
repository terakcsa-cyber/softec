import { NextResponse } from "next/server";
import ExcelJS from "exceljs";
import { forwardAuthHeaders } from "@/lib/upstream-proxy";
import { getUpstreamApiBase } from "@/lib/upstream-api";

function asNum(v: unknown): number | null {
  if (typeof v !== "number" || !Number.isFinite(v)) return null;
  return v;
}

function asStr(v: unknown): string | null {
  if (v == null) return null;
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return null;
}

function asObj(v: unknown): Record<string, unknown> | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  return v as Record<string, unknown>;
}

function asStrArray(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.map((x) => String(x)).map((s) => s.trim()).filter(Boolean);
}

function cellBoxStyle(fill: string) {
  return {
    fill: { type: "pattern" as const, pattern: "solid" as const, fgColor: { argb: fill } },
    border: {
      top: { style: "thin" as const, color: { argb: "FF94A3B8" } },
      left: { style: "thin" as const, color: { argb: "FF94A3B8" } },
      bottom: { style: "thin" as const, color: { argb: "FF94A3B8" } },
      right: { style: "thin" as const, color: { argb: "FF94A3B8" } }
    },
    alignment: { vertical: "middle" as const, horizontal: "center" as const, wrapText: true as const }
  };
}

function setMergedBox(
  ws: ExcelJS.Worksheet,
  fromCell: string,
  toCell: string,
  text: string,
  fillArgb: string
) {
  ws.mergeCells(`${fromCell}:${toCell}`);
  const c = ws.getCell(fromCell);
  c.value = text;
  Object.assign(c, cellBoxStyle(fillArgb));
  c.font = { bold: true, size: 11, color: { argb: "FF0F172A" } };
}

function setArrow(ws: ExcelJS.Worksheet, cell: string, text: string) {
  const c = ws.getCell(cell);
  c.value = text;
  c.alignment = { vertical: "middle", horizontal: "center" };
  c.font = { bold: true, size: 14, color: { argb: "FF64748B" } };
}

type Ctx = { params: Promise<{ id: string }> };

export async function GET(req: Request, ctx: Ctx) {
  const { id } = await ctx.params;
  const target = `${getUpstreamApiBase()}/fstec/bulletins/${encodeURIComponent(id)}`;
  const res = await fetch(target, {
    headers: { accept: "application/json", ...forwardAuthHeaders(req) },
    cache: "no-store"
  });
  if (!res.ok) {
    const body = await res.text();
    return new NextResponse(body, {
      status: res.status,
      headers: { "content-type": res.headers.get("content-type") ?? "application/json" }
    });
  }

  const payload = (await res.json()) as {
    bulletin?: {
      id?: string;
      title?: string | null;
      referenceNo?: string | null;
      sourceFilename?: string | null;
      status?: string;
      itemCount?: number;
      createdAt?: string;
    };
    parsed?: {
      title?: string | null;
      subject?: string | null;
      intro?: string | null;
      items?: Array<{
        ordinal?: number;
        bduId?: string;
        cvssLabel?: string;
        headline?: string;
        body?: string;
        remediation?: string | null;
        compensatingMeasures?: string | null;
      }>;
    };
    registry?: Array<{
      bduId?: string;
      found?: boolean;
      name?: string | null;
      cvssScore?: number | null;
      severity?: string | null;
      hasExploit?: boolean;
      hasFix?: boolean;
      linkedCves?: Array<{ cveId?: string; cvssBase?: number | null; riskScore?: number | null }>;
    }>;
    analysis?: {
      status?: string;
      outputJson?: unknown;
      outputText?: string | null;
      model?: string | null;
      promptVersion?: string | null;
    } | null;
  };

  const bulletin = payload.bulletin ?? {};
  const parsed = payload.parsed ?? {};
  const items = Array.isArray(parsed.items) ? parsed.items : [];
  const registry = Array.isArray(payload.registry) ? payload.registry : [];
  const regByBdu = new Map(registry.map((r) => [String(r.bduId ?? ""), r]));

  const out = asObj(payload.analysis?.outputJson ?? null);
  const hasAi = payload.analysis?.status === "ready" && out != null;

  const wb = new ExcelJS.Workbook();
  wb.creator = "Vuln Intel Platform";
  wb.created = new Date();

  const ref = asStr(bulletin.referenceNo) ?? "bulletin";
  const fileSlug = ref.replace(/[^\w.-]+/g, "_").slice(0, 48) || id.slice(0, 8);

  const ws0 = wb.addWorksheet("Сводка");
  ws0.columns = [
    { header: "Поле", key: "k", width: 28 },
    { header: "Значение", key: "v", width: 95 }
  ];
  const executiveSummary =
    asStr(out?.executiveSummary) ?? asStr(payload.analysis?.outputText) ?? null;
  const overallRisk = asStr(out?.overallRiskRating) ?? null;
  const managementBrief = asStr(out?.managementBrief) ?? null;
  const technicalBrief = asStr(out?.technicalBrief) ?? null;

  ws0.addRows([
    { k: "Бюллетень", v: asStr(bulletin.title) ?? "—" },
    { k: "Номер / ссылка", v: ref },
    { k: "Файл", v: asStr(bulletin.sourceFilename) ?? "—" },
    { k: "Позиций (BDU)", v: String(items.length) },
    { k: "Статус", v: asStr(bulletin.status) ?? "—" },
    { k: "Создан", v: asStr(bulletin.createdAt) ?? "—" },
    { k: "ИИ статус", v: asStr(payload.analysis?.status) ?? "нет" },
    { k: "Общий риск (ИИ)", v: overallRisk ?? "—" }
  ]);
  ws0.addRow({});
  ws0.addRow({ k: "Сводка для руководства", v: executiveSummary ?? "—" });
  if (managementBrief) {
    ws0.addRow({});
    ws0.addRow({ k: "Management brief", v: managementBrief });
  }
  if (technicalBrief) {
    ws0.addRow({});
    ws0.addRow({ k: "Technical brief", v: technicalBrief });
  }
  if (asStr(parsed.intro)) {
    ws0.addRow({});
    ws0.addRow({ k: "Вводная (бюллетень)", v: asStr(parsed.intro) });
  }
  ws0.getRow(1).font = { bold: true };
  ws0.views = [{ state: "frozen", ySplit: 1 }];
  ws0.getColumn("v").alignment = { wrapText: true, vertical: "top" };

  const wsItems = wb.addWorksheet("Позиции BDU");
  wsItems.columns = [
    { header: "#", key: "ord", width: 5 },
    { header: "BDU", key: "bdu", width: 14 },
    { header: "CVSS (бюллетень)", key: "cvssB", width: 16 },
    { header: "CVSS (реестр)", key: "cvssR", width: 12 },
    { header: "В БДУ", key: "found", width: 8 },
    { header: "Эксплойт", key: "exploit", width: 10 },
    { header: "Заголовок", key: "head", width: 42 },
    { header: "Описание", key: "body", width: 55 },
    { header: "Устранение", key: "fix", width: 45 },
    { header: "Компенсация", key: "comp", width: 40 }
  ];
  for (const it of items) {
    const bduId = asStr(it.bduId) ?? "";
    const reg = regByBdu.get(bduId);
    wsItems.addRow({
      ord: it.ordinal ?? "",
      bdu: bduId ? `BDU:${bduId}` : "",
      cvssB: asStr(it.cvssLabel) ?? "",
      cvssR: reg?.cvssScore != null ? reg.cvssScore : "",
      found: reg?.found ? "да" : "нет",
      exploit: reg?.hasExploit ? "да" : "нет",
      head: asStr(it.headline) ?? "",
      body: asStr(it.body) ?? "",
      fix: asStr(it.remediation) ?? "",
      comp: asStr(it.compensatingMeasures) ?? ""
    });
  }
  wsItems.getRow(1).font = { bold: true };
  wsItems.views = [{ state: "frozen", ySplit: 1 }];
  for (const col of ["body", "fix", "comp", "head"]) {
    wsItems.getColumn(col).alignment = { wrapText: true, vertical: "top" };
  }

  const aiItems = Array.isArray(out?.itemSummaries) ? out!.itemSummaries : [];
  if (aiItems.length > 0) {
    const wsAi = wb.addWorksheet("ИИ по позициям");
    wsAi.columns = [
      { header: "#", key: "ord", width: 5 },
      { header: "BDU", key: "bdu", width: 14 },
      { header: "Приоритет", key: "pri", width: 10 },
      { header: "Срочность", key: "urg", width: 14 },
      { header: "Сводка ИИ", key: "sum", width: 70 },
      { header: "Шаги атаки", key: "flow", width: 55 }
    ];
    for (const raw of aiItems) {
      const row = asObj(raw);
      const flow = asStrArray(row?.attackFlow).join("\n");
      wsAi.addRow({
        ord: row?.ordinal ?? "",
        bdu: asStr(row?.bduId) ? `BDU:${asStr(row?.bduId)}` : "",
        pri: row?.priority ?? "",
        urg: asStr(row?.exploitUrgency) ?? "",
        sum: asStr(row?.summary) ?? asStr(row?.headline) ?? "",
        flow
      });
    }
    wsAi.getRow(1).font = { bold: true };
    wsAi.getColumn("sum").alignment = { wrapText: true, vertical: "top" };
    wsAi.getColumn("flow").alignment = { wrapText: true, vertical: "top" };
  }

  const wsPlan = wb.addWorksheet("План действий");
  wsPlan.columns = [
    { header: "Фаза", key: "phase", width: 28 },
    { header: "Срок", key: "horizon", width: 12 },
    { header: "BDU", key: "bdu", width: 14 },
    { header: "Тип", key: "type", width: 14 },
    { header: "Действие", key: "title", width: 42 },
    { header: "Детали", key: "detail", width: 55 }
  ];
  const ap = out?.actionPlan as
    | {
        introduction?: string;
        phases?: Array<{
          title?: string;
          horizon?: string;
          steps?: Array<{
            order?: number;
            bduId?: string | null;
            title?: string;
            detail?: string;
            actionType?: string;
          }>;
        }>;
      }
    | undefined;
  let planRow = 0;
  if (ap?.introduction) {
    wsPlan.addRow({ phase: "Введение", horizon: "", bdu: "", type: "", title: ap.introduction, detail: "" });
    planRow++;
  }
  if (Array.isArray(ap?.phases)) {
    for (const ph of ap.phases) {
      for (const step of ph.steps ?? []) {
        planRow++;
        wsPlan.addRow({
          phase: ph.title ?? "",
          horizon: ph.horizon ?? "",
          bdu: step.bduId ? `BDU:${step.bduId}` : "",
          type: step.actionType ?? "",
          title: step.title ?? "",
          detail: step.detail ?? ""
        });
      }
    }
  }
  if (planRow === 0) {
    const plan = asStrArray(out?.combinedRemediationPlan);
    if (plan.length) plan.forEach((t) => wsPlan.addRow({ phase: "", horizon: "", bdu: "", type: "", title: t, detail: "" }));
    else wsPlan.addRow({ phase: "", horizon: "", bdu: "", type: "", title: hasAi ? "—" : "Запустите ИИ-анализ", detail: "" });
  }
  wsPlan.getRow(1).font = { bold: true };
  wsPlan.getColumn("detail").alignment = { wrapText: true, vertical: "top" };
  wsPlan.getColumn("title").alignment = { wrapText: true, vertical: "top" };

  const priorityOrder = asStrArray(out?.priorityOrder);
  if (priorityOrder.length) {
    const wsPri = wb.addWorksheet("Приоритет BDU");
    wsPri.columns = [
      { header: "Ранг", key: "n", width: 6 },
      { header: "BDU", key: "bdu", width: 18 }
    ];
    priorityOrder.forEach((bdu, i) => wsPri.addRow({ n: i + 1, bdu }));
    wsPri.getRow(1).font = { bold: true };
  }

  const cross = asStrArray(out?.crossCuttingThemes);
  if (cross.length) {
    const wsCross = wb.addWorksheet("Темы");
    wsCross.columns = [{ header: "Тема", key: "t", width: 100 }];
    cross.forEach((t) => wsCross.addRow({ t }));
    wsCross.getRow(1).font = { bold: true };
  }

  const riskMatrix = asObj(out?.riskMatrix);
  if (riskMatrix) {
    const wsRm = wb.addWorksheet("Risk matrix");
    wsRm.columns = [
      { header: "Метрика", key: "k", width: 32 },
      { header: "Значение", key: "v", width: 12 }
    ];
    for (const [k, v] of Object.entries(riskMatrix)) {
      wsRm.addRow({ k, v: asNum(v) ?? asStr(v) ?? "" });
    }
    wsRm.getRow(1).font = { bold: true };
  }

  const graph = asObj(out?.combinedGraph);
  const nodes = Array.isArray(graph?.nodes) ? graph!.nodes : [];
  const edges = Array.isArray(graph?.edges) ? graph!.edges : [];

  const wsMap = wb.addWorksheet("Attack map");
  wsMap.columns = [
    { header: "", key: "a", width: 6 },
    { header: "", key: "b", width: 18 },
    { header: "", key: "c", width: 18 },
    { header: "", key: "d", width: 18 },
    { header: "", key: "e", width: 18 },
    { header: "", key: "f", width: 18 },
    { header: "", key: "g", width: 6 }
  ];
  wsMap.getCell("A1").value = `Сводная схема атаки — ${asStr(bulletin.title) ?? ref}`;
  wsMap.mergeCells("A1:G1");
  wsMap.getCell("A1").font = { bold: true, size: 12 };

  if (!hasAi || nodes.length === 0) {
    const themes = cross.length ? cross : ["Запустите ИИ-анализ для карты атаки"];
    let r = 3;
    setMergedBox(wsMap, `B${r}`, `F${r}`, "Злоумышленник", "FFFFE4E6");
    r += 2;
    for (let i = 0; i < Math.min(themes.length, 6); i++) {
      setMergedBox(wsMap, `B${r}`, `F${r}`, themes[i]!, "FFF5F3FF");
      r += 2;
      setArrow(wsMap, `D${r - 1}`, "↓");
    }
    setMergedBox(wsMap, `B${r}`, `F${r}`, "Воздействие на КИИ", "FFFFF7ED");
  } else {
    const byType = (t: string) =>
      nodes
        .map((n) => asObj(n))
        .filter((n) => asStr(n?.type) === t)
        .map((n) => asStr(n?.label) ?? asStr(n?.id) ?? "")
        .filter(Boolean);

    let r = 3;
    const attackers = byType("attacker");
    setMergedBox(
      wsMap,
      `B${r}`,
      `F${r}`,
      attackers.length ? attackers.join("\n") : "Злоумышленник",
      "FFFFE4E6"
    );
    r += 2;
    setArrow(wsMap, `D${r - 1}`, "↓");

    for (const t of ["vector", "service", "asset"] as const) {
      const labels = byType(t);
      if (!labels.length) continue;
      setMergedBox(wsMap, `B${r}`, `F${r}`, labels.join("\n"), "FFF5F3FF");
      r += 2;
      setArrow(wsMap, `D${r - 1}`, "↓");
    }

    const impacts = byType("impact");
    setMergedBox(
      wsMap,
      `B${r}`,
      `F${r}`,
      impacts.length ? impacts.join("\n") : "Воздействие",
      "FFFFF7ED"
    );
  }

  const wsGn = wb.addWorksheet("Graph nodes");
  wsGn.columns = [
    { header: "id", key: "id", width: 18 },
    { header: "type", key: "type", width: 14 },
    { header: "label", key: "label", width: 60 }
  ];
  for (const n of nodes) {
    const no = asObj(n);
    wsGn.addRow({
      id: asStr(no?.id) ?? "",
      type: asStr(no?.type) ?? "",
      label: asStr(no?.label) ?? ""
    });
  }
  if (nodes.length === 0) wsGn.addRow({ id: "", type: "", label: hasAi ? "—" : "ИИ нет" });
  wsGn.getRow(1).font = { bold: true };

  const wsGe = wb.addWorksheet("Graph edges");
  wsGe.columns = [
    { header: "from", key: "from", width: 18 },
    { header: "to", key: "to", width: 18 },
    { header: "label", key: "label", width: 70 }
  ];
  for (const e of edges) {
    const eo = asObj(e);
    wsGe.addRow({
      from: asStr(eo?.from) ?? "",
      to: asStr(eo?.to) ?? "",
      label: asStr(eo?.label) ?? ""
    });
  }
  if (edges.length === 0) wsGe.addRow({ from: "", to: "", label: hasAi ? "—" : "ИИ нет" });
  wsGe.getRow(1).font = { bold: true };

  const buf = await wb.xlsx.writeBuffer();
  const filename = `FSTEC-bulletin-${fileSlug}.xlsx`;

  return new NextResponse(Buffer.from(buf), {
    status: 200,
    headers: {
      "content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "content-disposition": `attachment; filename=\"${filename}\"`,
      "cache-control": "no-store"
    }
  });
}

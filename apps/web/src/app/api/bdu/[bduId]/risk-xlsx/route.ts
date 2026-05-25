import { NextResponse } from "next/server";
import ExcelJS from "exceljs";
import { forwardAuthHeaders } from "../../../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../../../lib/upstream-api";

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

export async function GET(req: Request, ctx: { params: Promise<{ bduId: string }> }) {
  const { bduId } = await ctx.params;
  const target = `${getUpstreamApiBase()}/bdu/${encodeURIComponent(bduId)}`;
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
    found?: boolean;
    bdu?: Record<string, unknown>;
    links?: { fstec?: string | null; cves?: Array<{ cveId?: string; nvd?: string }> };
    ai?: { output_json?: unknown; output_text?: unknown; model?: unknown; prompt_version?: unknown; created_at?: unknown };
  };
  if (!payload?.found || !payload.bdu) {
    return NextResponse.json({ ok: false, message: "BDU not found" }, { status: 404 });
  }

  const bdu = payload.bdu;
  const links = payload.links ?? null;
  const ai = payload.ai ?? null;
  const out = asObj(ai?.output_json ?? null);

  const wb = new ExcelJS.Workbook();
  wb.creator = "Vuln Intel Platform";
  wb.created = new Date();

  const id = String(bdu.bduId ?? bduId);
  const cvss = asNum(bdu.cvssScore);
  const hasExploit = Boolean(bdu.hasExploit);

  const ws0 = wb.addWorksheet("Комплексный анализ");
  ws0.columns = [
    { header: "Поле", key: "k", width: 28 },
    { header: "Значение", key: "v", width: 90 }
  ];

  const title = asStr(out?.title) ?? null;
  const summary = asStr(out?.summary) ?? asStr(ai?.output_text) ?? null;
  const description = asStr(out?.description) ?? asStr(out?.explanation) ?? null;
  const vulnerabilityClass = asStr(out?.vulnerabilityClass) ?? null;
  const exploitation = asObj(out?.exploitation);
  const publicExploit = asStr(exploitation?.publicExploit) ?? "unknown";
  const applicability = asObj(out?.applicability);
  const appStatus = asStr(applicability?.status) ?? "unknown";

  const aiMeta = [
    `model=${asStr(ai?.model) ?? "—"}`,
    `prompt=${asStr(ai?.prompt_version) ?? "—"}`,
    `created_at=${asStr(ai?.created_at) ?? "—"}`
  ].join(" ");

  ws0.addRows([
    { k: "Заголовок", v: title ?? "—" },
    { k: "BDU", v: `BDU:${id}` },
    { k: "Название (ФСТЭК)", v: asStr(bdu.name) ?? "—" },
    { k: "Класс", v: vulnerabilityClass ?? "—" },
    { k: "Уровень ФСТЭК", v: asStr(bdu.severity) ?? "—" },
    { k: "CVSS (реестр)", v: cvss == null ? "—" : cvss },
    { k: "Эксплойт (реестр)", v: hasExploit ? "да" : "нет" },
    { k: "Эксплойт (ИИ)", v: publicExploit },
    { k: "Применимость", v: appStatus },
    { k: "ИИ метаданные", v: out ? aiMeta : "ИИ‑данных пока нет (запросите обогащение)" }
  ]);
  ws0.addRow({});
  ws0.addRow({ k: "Кратко", v: summary ?? "—" });
  ws0.addRow({});
  ws0.addRow({ k: "Описание", v: description ?? asStr(bdu.description) ?? "—" });
  ws0.getRow(1).font = { bold: true };
  ws0.views = [{ state: "frozen", ySplit: 1 }];
  ws0.getColumn("v").alignment = { wrapText: true, vertical: "top" };

  const ws = wb.addWorksheet("Risk");
  ws.columns = [
    { header: "Поле", key: "k", width: 26 },
    { header: "Значение", key: "v", width: 80 }
  ];
  ws.addRows([
    { k: "BDU", v: `BDU:${id}` },
    { k: "Публикация", v: asStr(bdu.publicationDate) ?? "—" },
    { k: "Выявлено", v: asStr(bdu.identifyDate) ?? "—" },
    { k: "CVSS", v: cvss == null ? "—" : cvss },
    { k: "CVSS vector", v: asStr(bdu.cvssVector) ?? "—" },
    { k: "Эксплойт", v: hasExploit ? "да" : "нет" },
    { k: "Исправление", v: Boolean(bdu.hasFix) ? "да" : "нет" }
  ]);
  ws.addRow({});
  ws.addRow({ k: "ФСТЭК", v: links?.fstec ?? asStr(bdu.fstecUrl) ?? "—" });
  const cveLinks = Array.isArray(links?.cves) ? links!.cves! : [];
  for (const c of cveLinks.slice(0, 15)) {
    ws.addRow({ k: `CVE`, v: `${c.cveId ?? ""} ${c.nvd ?? ""}`.trim() });
  }
  ws.getRow(1).font = { bold: true };
  ws.views = [{ state: "frozen", ySplit: 1 }];
  ws.getColumn("v").alignment = { wrapText: true, vertical: "top" };

  const nextSteps = asStrArray(out?.nextSteps);
  const wsNs = wb.addWorksheet("Next steps");
  wsNs.columns = [
    { header: "#", key: "n", width: 5 },
    { header: "Действие", key: "t", width: 110 }
  ];
  if (nextSteps.length === 0) {
    wsNs.addRow({ n: "", t: out ? "—" : "ИИ‑данных пока нет (nextSteps появятся после обогащения)" });
  } else {
    nextSteps.forEach((t, i) => wsNs.addRow({ n: i + 1, t }));
  }
  wsNs.getRow(1).font = { bold: true };
  wsNs.views = [{ state: "frozen", ySplit: 1 }];
  wsNs.getColumn("t").alignment = { wrapText: true, vertical: "top" };

  const questions = asStrArray(out?.questions);
  const wsQ = wb.addWorksheet("Questions");
  wsQ.columns = [
    { header: "#", key: "n", width: 5 },
    { header: "Вопрос", key: "q", width: 110 }
  ];
  if (questions.length === 0) {
    wsQ.addRow({ n: "", q: out ? "—" : "ИИ‑данных пока нет (questions появятся после обогащения)" });
  } else {
    questions.forEach((t, i) => wsQ.addRow({ n: i + 1, q: t }));
  }
  wsQ.getRow(1).font = { bold: true };
  wsQ.views = [{ state: "frozen", ySplit: 1 }];
  wsQ.getColumn("q").alignment = { wrapText: true, vertical: "top" };

  const attackFlow = asStrArray(out?.attackFlow);
  const wsAf = wb.addWorksheet("Attack flow");
  wsAf.columns = [
    { header: "Шаг", key: "n", width: 7 },
    { header: "Описание", key: "t", width: 110 }
  ];
  if (attackFlow.length === 0) {
    wsAf.addRow({ n: "", t: out ? "—" : "ИИ‑данных пока нет" });
  } else {
    attackFlow.forEach((t, i) => wsAf.addRow({ n: i + 1, t }));
  }
  wsAf.getRow(1).font = { bold: true };
  wsAf.views = [{ state: "frozen", ySplit: 1 }];
  wsAf.getColumn("t").alignment = { wrapText: true, vertical: "top" };

  const graph = asObj(out?.graph);
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
  wsMap.views = [{ state: "frozen", ySplit: 1 }];
  wsMap.getRow(1).height = 22;
  wsMap.getCell("A1").value = "Схема атаки (Excel)";
  wsMap.mergeCells("A1:G1");
  wsMap.getCell("A1").font = { bold: true, size: 12 };
  wsMap.getCell("A1").alignment = { vertical: "middle", horizontal: "left" };

  const flow = attackFlow.length ? attackFlow : [];
  if (!out || flow.length === 0) {
    wsMap.getCell("A3").value = out ? "—" : "ИИ‑данных пока нет (attackFlow/graph появятся после обогащения)";
    wsMap.mergeCells("A3:G6");
    wsMap.getCell("A3").alignment = { wrapText: true, vertical: "top", horizontal: "left" };
  } else {
    let r = 3;
    wsMap.getRow(r).height = 34;
    setMergedBox(wsMap, `B${r}`, `F${r}`, "Злоумышленник", "FFFFE4E6");
    r += 1;
    setArrow(wsMap, `D${r}`, "↓");
    r += 1;
    for (let i = 0; i < Math.min(flow.length, 8); i++) {
      wsMap.getRow(r).height = 54;
      setMergedBox(wsMap, `B${r}`, `F${r}`, `Шаг ${i + 1}\n${flow[i]}`, "FFF5F3FF");
      r += 1;
      setArrow(wsMap, `D${r}`, "↓");
      r += 1;
    }
    wsMap.getRow(r).height = 40;
    setMergedBox(wsMap, `B${r}`, `F${r}`, "Воздействие / результат", "FFFFF7ED");
  }

  if (out && nodes.length > 0) {
    const baseRow = 22;
    wsMap.getCell(`A${baseRow}`).value = "Схема по LLM graph (горизонтально)";
    wsMap.mergeCells(`A${baseRow}:G${baseRow}`);
    wsMap.getCell(`A${baseRow}`).font = { bold: true, size: 11 };
    wsMap.getRow(baseRow).height = 20;

    const byType = (t: string) =>
      nodes
        .map((n) => asObj(n))
        .filter(Boolean)
        .filter((n) => String(n!.type ?? "") === t)
        .slice(0, 6) as Array<Record<string, unknown>>;

    const attackers = byType("attacker");
    const vectors = byType("vector");
    const services = [...byType("service"), ...byType("asset")].slice(0, 6);
    const impacts = byType("impact");

    const headerRow = baseRow + 1;
    wsMap.getRow(headerRow).height = 18;
    wsMap.getCell(`B${headerRow}`).value = "Attacker";
    wsMap.getCell(`D${headerRow}`).value = "Vector";
    wsMap.getCell(`F${headerRow}`).value = "Impact";
    for (const c of ["B", "D", "F"]) {
      const cell = wsMap.getCell(`${c}${headerRow}`);
      cell.font = { bold: true, size: 10, color: { argb: "FF334155" } };
      cell.alignment = { horizontal: "center", vertical: "middle" };
    }

    const maxRows = Math.max(attackers.length, vectors.length, services.length, impacts.length, 1);
    const start = baseRow + 2;
    for (let i = 0; i < maxRows; i++) {
      const rr = start + i * 2;
      wsMap.getRow(rr).height = 34;

      const a = attackers[i] ? String(attackers[i]!.label ?? attackers[i]!.id ?? "attacker") : "";
      const v = vectors[i] ? String(vectors[i]!.label ?? vectors[i]!.id ?? "vector") : "";
      const s = services[i] ? String(services[i]!.label ?? services[i]!.id ?? "service") : "";
      const im = impacts[i] ? String(impacts[i]!.label ?? impacts[i]!.id ?? "impact") : "";

      if (a) setMergedBox(wsMap, `B${rr}`, `B${rr}`, a, "FFFFE4E6");
      setArrow(wsMap, `C${rr}`, "→");
      if (v || s) setMergedBox(wsMap, `D${rr}`, `D${rr}`, [v, s].filter(Boolean).join("\n"), "FFF5F3FF");
      setArrow(wsMap, `E${rr}`, "→");
      if (im) setMergedBox(wsMap, `F${rr}`, `F${rr}`, im, "FFFFF7ED");

      const rr2 = rr + 1;
      wsMap.getRow(rr2).height = 18;
      const eText = asObj(edges[i])?.label ? String(asObj(edges[i])!.label) : "";
      if (eText) {
        wsMap.getCell(`D${rr2}`).value = eText.length > 90 ? `${eText.slice(0, 90)}…` : eText;
        wsMap.getCell(`D${rr2}`).alignment = { wrapText: true, vertical: "top", horizontal: "center" };
        wsMap.getCell(`D${rr2}`).font = { size: 9, color: { argb: "FF64748B" } };
      }
    }
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
  if (nodes.length === 0) wsGn.addRow({ id: "", type: "", label: out ? "—" : "ИИ нет" });
  wsGn.getRow(1).font = { bold: true };
  wsGn.views = [{ state: "frozen", ySplit: 1 }];

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
  if (edges.length === 0) wsGe.addRow({ from: "", to: "", label: out ? "—" : "ИИ нет" });
  wsGe.getRow(1).font = { bold: true };
  wsGe.views = [{ state: "frozen", ySplit: 1 }];
  wsGe.getColumn("label").alignment = { wrapText: true, vertical: "top" };

  const wsSrc = wb.addWorksheet("Sources");
  wsSrc.columns = [
    { header: "kind", key: "kind", width: 14 },
    { header: "label", key: "label", width: 30 },
    { header: "url", key: "url", width: 80 }
  ];
  const srcRows: Array<{ kind: string; label: string; url: string }> = [];
  const fstec = links?.fstec ?? asStr(bdu.fstecUrl);
  if (fstec) srcRows.push({ kind: "fstec", label: "БДУ ФСТЭК", url: fstec });
  for (const c of cveLinks) {
    if (c.nvd) srcRows.push({ kind: "nvd", label: String(c.cveId ?? ""), url: c.nvd });
  }
  const llmSources = Array.isArray(out?.sources) ? out!.sources : [];
  for (const s of llmSources) {
    const so = asObj(s);
    const url = asStr(so?.url);
    if (!url) continue;
    srcRows.push({ kind: asStr(so?.kind) ?? "other", label: asStr(so?.label) ?? "", url });
  }
  if (srcRows.length === 0) {
    wsSrc.addRow({ kind: "", label: "", url: "—" });
  } else {
    for (const r of srcRows) {
      const row = wsSrc.addRow(r);
      row.getCell(3).value = { text: r.url, hyperlink: r.url };
      row.getCell(3).font = { color: { argb: "FF2563EB" }, underline: true };
    }
  }
  wsSrc.getRow(1).font = { bold: true };
  wsSrc.views = [{ state: "frozen", ySplit: 1 }];
  wsSrc.getColumn("url").alignment = { wrapText: true, vertical: "top" };

  const remediation = asStrArray(out?.remediation);
  const wsRem = wb.addWorksheet("Remediation");
  wsRem.columns = [
    { header: "#", key: "n", width: 5 },
    { header: "Действие", key: "t", width: 110 }
  ];
  const fixText = asStr(bdu.solution);
  if (remediation.length) remediation.forEach((t, i) => wsRem.addRow({ n: i + 1, t }));
  else if (fixText) wsRem.addRow({ n: 1, t: fixText });
  else wsRem.addRow({ n: "", t: "—" });
  wsRem.getRow(1).font = { bold: true };
  wsRem.views = [{ state: "frozen", ySplit: 1 }];
  wsRem.getColumn("t").alignment = { wrapText: true, vertical: "top" };

  const buf = await wb.xlsx.writeBuffer();
  const filename = `BDU-${id}-risk.xlsx`;

  return new NextResponse(Buffer.from(buf), {
    status: 200,
    headers: {
      "content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "content-disposition": `attachment; filename=\"${filename}\"`,
      "cache-control": "no-store"
    }
  });
}

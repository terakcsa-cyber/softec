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

export async function GET(req: Request, ctx: { params: Promise<{ cveId: string }> }) {
  const { cveId } = await ctx.params;
  const target = `${getUpstreamApiBase()}/cves/${encodeURIComponent(cveId)}`;
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
    cve?: Record<string, unknown>;
    links?: { nvd?: string | null; kev?: string | null; epss?: string | null } | null;
    vendorAdvisories?: unknown[];
    ai?: { output_json?: unknown; output_text?: unknown; model?: unknown; prompt_version?: unknown; created_at?: unknown } | null;
  };
  if (!payload?.found || !payload?.cve) {
    return NextResponse.json({ ok: false, message: "CVE not found" }, { status: 404 });
  }

  const cve = payload.cve as Record<string, unknown>;
  const links = (payload.links ?? null) as null | { nvd?: string | null; kev?: string | null; epss?: string | null };
  const advisories = Array.isArray(payload.vendorAdvisories)
    ? (payload.vendorAdvisories as Array<Record<string, unknown>>)
    : [];
  const ai = (payload.ai ?? null) as null | { output_json?: unknown; output_text?: unknown; model?: unknown; prompt_version?: unknown; created_at?: unknown };
  const out = asObj(ai?.output_json ?? null);

  const wb = new ExcelJS.Workbook();
  wb.creator = "Vuln Intel Platform";
  wb.created = new Date();

  const id = String(cve.cve_id ?? cveId);
  const cvss = asNum(cve.cvss_base);
  const epss = asNum(cve.epss);
  const riskScore = asNum(cve.risk_score);
  const kev = Boolean(cve.exploit_known);

  // === Sheet: Комплексный анализ (bank-grade) ===
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
  const exploitNotes = asStr(exploitation?.exploitNotes) ?? null;

  const applicability = asObj(out?.applicability);
  const appStatus = asStr(applicability?.status) ?? "unknown";
  const appNotes = asStr(applicability?.notes) ?? null;

  const aiMeta = [
    `model=${asStr(ai?.model) ?? "—"}`,
    `prompt=${asStr(ai?.prompt_version) ?? "—"}`,
    `created_at=${asStr(ai?.created_at) ?? "—"}`
  ].join(" ");

  ws0.addRows([
    { k: "Заголовок", v: title ?? "—" },
    { k: "CVE", v: id },
    { k: "Класс", v: vulnerabilityClass ?? "—" },
    { k: "CVSS", v: cvss == null ? "—" : cvss },
    { k: "EPSS", v: epss == null ? "—" : epss },
    { k: "KEV", v: kev ? "да" : "нет" },
    { k: "Risk score", v: riskScore == null ? "—" : riskScore },
    { k: "Эксплойт (public)", v: publicExploit },
    { k: "Эксплойт (примечания)", v: exploitNotes ?? "—" },
    { k: "Применимость", v: appStatus },
    { k: "Применимость (примечания)", v: appNotes ?? "—" },
    { k: "ИИ метаданные", v: out ? aiMeta : "ИИ‑данных пока нет (запросите обогащение)" }
  ]);
  ws0.addRow({});
  ws0.addRow({ k: "Кратко", v: summary ?? "—" });
  ws0.addRow({});
  ws0.addRow({ k: "Описание", v: description ?? "—" });
  ws0.getRow(1).font = { bold: true };
  ws0.views = [{ state: "frozen", ySplit: 1 }];
  ws0.getColumn("v").alignment = { wrapText: true, vertical: "top" };

  const ws = wb.addWorksheet("Risk");
  ws.columns = [
    { header: "Поле", key: "k", width: 26 },
    { header: "Значение", key: "v", width: 80 }
  ];

  ws.addRows([
    { k: "CVE", v: id },
    { k: "Источник", v: String(cve.source ?? "—") },
    { k: "Опубликовано", v: String(cve.published_at ?? "—") },
    { k: "Изменено", v: String(cve.modified_at ?? "—") },
    { k: "CVSS base", v: cvss == null ? "—" : cvss },
    { k: "EPSS", v: epss == null ? "—" : epss },
    { k: "KEV (known exploited)", v: kev ? "да" : "нет" },
    { k: "Risk score (platform)", v: riskScore == null ? "—" : riskScore }
  ]);

  ws.addRow({});
  ws.addRow({ k: "Ссылки (NVD)", v: links?.nvd ?? "—" });
  ws.addRow({ k: "Ссылки (EPSS)", v: links?.epss ?? "—" });
  ws.addRow({ k: "Ссылки (CISA KEV)", v: links?.kev ?? "—" });

  // === Sheet: Next steps ===
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

  // === Sheet: Questions ===
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

  // === Sheet: Attack flow ===
  const attackFlow = asStrArray(out?.attackFlow);
  const wsAf = wb.addWorksheet("Attack flow");
  wsAf.columns = [
    { header: "Шаг", key: "n", width: 7 },
    { header: "Описание", key: "t", width: 110 }
  ];
  if (attackFlow.length === 0) {
    wsAf.addRow({ n: "", t: out ? "—" : "ИИ‑данных пока нет (attackFlow появится после обогащения)" });
  } else {
    attackFlow.forEach((t, i) => wsAf.addRow({ n: i + 1, t }));
  }
  wsAf.getRow(1).font = { bold: true };
  wsAf.views = [{ state: "frozen", ySplit: 1 }];
  wsAf.getColumn("t").alignment = { wrapText: true, vertical: "top" };

  // === Sheet: Graph ===
  const graph = asObj(out?.graph);
  const nodes = Array.isArray(graph?.nodes) ? graph!.nodes : [];
  const edges = Array.isArray(graph?.edges) ? graph!.edges : [];

  // === Sheet: Attack map (diagram with arrows) ===
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
  wsMap.getCell("A1").font = { bold: true, size: 12 };
  wsMap.mergeCells("A1:G1");
  wsMap.getCell("A1").alignment = { vertical: "middle", horizontal: "left" };

  const flow = attackFlow.length ? attackFlow : [];
  if (!out || flow.length === 0) {
    wsMap.getCell("A3").value = out ? "—" : "ИИ‑данных пока нет (attackFlow/graph появятся после обогащения)";
    wsMap.mergeCells("A3:G6");
    wsMap.getCell("A3").alignment = { wrapText: true, vertical: "top", horizontal: "left" };
  } else {
    // Render a vertical chain of boxes with arrows:
    // Attacker -> Step 1 -> Step 2 -> ... -> Impact
    const startRow = 3;
    let r = startRow;
    wsMap.getRow(r).height = 34;
    setMergedBox(wsMap, `B${r}`, `F${r}`, "Злоумышленник", "FFFFE4E6"); // rose-50
    r += 1;
    setArrow(wsMap, `D${r}`, "↓");
    r += 1;
    for (let i = 0; i < Math.min(flow.length, 8); i++) {
      wsMap.getRow(r).height = 54;
      const txt = `Шаг ${i + 1}\n${flow[i]}`;
      setMergedBox(wsMap, `B${r}`, `F${r}`, txt, "FFF5F3FF"); // purple-ish
      r += 1;
      setArrow(wsMap, `D${r}`, "↓");
      r += 1;
    }
    wsMap.getRow(r).height = 40;
    setMergedBox(wsMap, `B${r}`, `F${r}`, "Воздействие / результат", "FFFFF7ED"); // amber-50
  }

  // Graph-based horizontal map (attacker → vector → service/asset → impact)
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

    // headers
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

      // attacker + arrow + vector + arrow + impact
      if (a) setMergedBox(wsMap, `B${rr}`, `B${rr}`, a, "FFFFE4E6");
      setArrow(wsMap, `C${rr}`, "→");
      if (v || s) {
        const vv = [v, s].filter(Boolean).join("\n");
        setMergedBox(wsMap, `D${rr}`, `D${rr}`, vv, "FFF5F3FF");
      }
      setArrow(wsMap, `E${rr}`, "→");
      if (im) setMergedBox(wsMap, `F${rr}`, `F${rr}`, im, "FFFFF7ED");

      // edge labels (best-effort): look for matching from/to ids in edges and put in row below
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
  if (nodes.length === 0) {
    wsGn.addRow({ id: "", type: "", label: out ? "—" : "ИИ‑данных пока нет (graph появится после обогащения)" });
  } else {
    for (const n of nodes) {
      const no = asObj(n);
      wsGn.addRow({
        id: asStr(no?.id) ?? "",
        type: asStr(no?.type) ?? "",
        label: asStr(no?.label) ?? ""
      });
    }
  }
  wsGn.getRow(1).font = { bold: true };
  wsGn.views = [{ state: "frozen", ySplit: 1 }];

  const wsGe = wb.addWorksheet("Graph edges");
  wsGe.columns = [
    { header: "from", key: "from", width: 18 },
    { header: "to", key: "to", width: 18 },
    { header: "label", key: "label", width: 70 }
  ];
  if (edges.length === 0) {
    wsGe.addRow({ from: "", to: "", label: out ? "—" : "ИИ‑данных пока нет (graph появится после обогащения)" });
  } else {
    for (const e of edges) {
      const eo = asObj(e);
      wsGe.addRow({
        from: asStr(eo?.from) ?? "",
        to: asStr(eo?.to) ?? "",
        label: asStr(eo?.label) ?? ""
      });
    }
  }
  wsGe.getRow(1).font = { bold: true };
  wsGe.views = [{ state: "frozen", ySplit: 1 }];
  wsGe.getColumn("label").alignment = { wrapText: true, vertical: "top" };

  // === Sheet: Sources (LLM + platform links) ===
  const wsSrc = wb.addWorksheet("Sources");
  wsSrc.columns = [
    { header: "kind", key: "kind", width: 14 },
    { header: "label", key: "label", width: 30 },
    { header: "url", key: "url", width: 80 }
  ];
  const srcRows: Array<{ kind: string; label: string; url: string }> = [];
  if (links?.nvd) srcRows.push({ kind: "nvd", label: "NVD", url: links.nvd });
  if (links?.epss) srcRows.push({ kind: "epss", label: "EPSS scorecard", url: links.epss });
  if (links?.kev) srcRows.push({ kind: "kev", label: "CISA KEV catalog search", url: links.kev });
  const llmSources = Array.isArray(out?.sources) ? out!.sources : [];
  for (const s of llmSources) {
    const so = asObj(s);
    const url = asStr(so?.url);
    if (!url) continue;
    srcRows.push({
      kind: asStr(so?.kind) ?? "other",
      label: asStr(so?.label) ?? "",
      url
    });
  }
  if (srcRows.length === 0) {
    wsSrc.addRow({ kind: "", label: "", url: out ? "—" : "ИИ‑данных пока нет (sources появятся после обогащения)" });
  } else {
    for (const r of srcRows) {
      const row = wsSrc.addRow({ kind: r.kind, label: r.label, url: r.url });
      // Make URL clickable
      const cell = row.getCell(3);
      cell.value = { text: r.url, hyperlink: r.url };
      cell.font = { color: { argb: "FF2563EB" }, underline: true };
    }
  }
  wsSrc.getRow(1).font = { bold: true };
  wsSrc.views = [{ state: "frozen", ySplit: 1 }];
  wsSrc.getColumn("url").alignment = { wrapText: true, vertical: "top" };

  const ws2 = wb.addWorksheet("Vendor advisories");
  ws2.columns = [
    { header: "Vendor", key: "vendor", width: 18 },
    { header: "Title", key: "title", width: 60 },
    { header: "Link", key: "link", width: 60 },
    { header: "Published", key: "published", width: 22 },
    { header: "Fetched", key: "fetched", width: 22 }
  ];
  for (const a of advisories) {
    ws2.addRow({
      vendor: String(a.vendorSlug ?? ""),
      title: String(a.title ?? ""),
      link: String(a.link ?? ""),
      published: a.publishedAt ? String(a.publishedAt) : "",
      fetched: a.fetchedAt ? String(a.fetchedAt) : ""
    });
  }

  ws.getRow(1).font = { bold: true };
  ws2.getRow(1).font = { bold: true };
  ws.views = [{ state: "frozen", ySplit: 1 }];
  ws2.views = [{ state: "frozen", ySplit: 1 }];
  ws.getColumn("v").alignment = { wrapText: true, vertical: "top" };
  ws2.getColumn("title").alignment = { wrapText: true, vertical: "top" };
  ws2.getColumn("link").alignment = { wrapText: true, vertical: "top" };

  const buf = await wb.xlsx.writeBuffer();
  const filename = `${id}-risk.xlsx`;

  return new NextResponse(Buffer.from(buf), {
    status: 200,
    headers: {
      "content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "content-disposition": `attachment; filename="${filename}"`,
      "cache-control": "no-store"
    }
  });
}


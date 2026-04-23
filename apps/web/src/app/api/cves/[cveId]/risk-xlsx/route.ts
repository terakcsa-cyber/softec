import { NextResponse } from "next/server";
import ExcelJS from "exceljs";
import { forwardAuthHeaders } from "../../../../../lib/upstream-proxy";
import { getUpstreamApiBase } from "../../../../../lib/upstream-api";

function asNum(v: unknown): number | null {
  if (typeof v !== "number" || !Number.isFinite(v)) return null;
  return v;
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

  const payload = (await res.json()) as any;
  if (!payload?.found || !payload?.cve) {
    return NextResponse.json({ ok: false, message: "CVE not found" }, { status: 404 });
  }

  const cve = payload.cve as Record<string, unknown>;
  const links = (payload.links ?? null) as null | { nvd?: string | null; kev?: string | null; epss?: string | null };
  const advisories = Array.isArray(payload.vendorAdvisories) ? payload.vendorAdvisories : [];

  const wb = new ExcelJS.Workbook();
  wb.creator = "Vuln Intel Platform";
  wb.created = new Date();

  const ws = wb.addWorksheet("Risk");
  ws.columns = [
    { header: "Поле", key: "k", width: 26 },
    { header: "Значение", key: "v", width: 80 }
  ];

  const id = String(cve.cve_id ?? cveId);
  const cvss = asNum(cve.cvss_base);
  const epss = asNum(cve.epss);
  const riskScore = asNum(cve.risk_score);
  const kev = Boolean(cve.exploit_known);

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

  const buf = await wb.xlsx.writeBuffer();
  const filename = `${id}-risk.xlsx`;

  return new NextResponse(Buffer.from(buf), {
    status: 200,
    headers: {
      "content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "content-disposition": `attachment; filename=\"${filename}\"`,
      "cache-control": "no-store"
    }
  });
}


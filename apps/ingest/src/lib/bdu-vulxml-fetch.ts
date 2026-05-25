import { XMLParser } from "fast-xml-parser";
import { fetchBduVulxmlWithFallback, parseBduVulNode, type BduVulxmlRecord } from "@vuln-intel/shared";

export { fetchBduVulxmlWithFallback } from "@vuln-intel/shared";

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  trimValues: true,
  processEntities: false
});

export function parseBduVulxmlDocument(xml: Buffer | string): BduVulxmlRecord[] {
  const parsed = xmlParser.parse(typeof xml === "string" ? xml : xml.toString("utf8")) as Record<string, unknown>;
  const root = (parsed.vulnerabilities ?? parsed) as Record<string, unknown>;
  const rawVul = root.vul ?? parsed.vul;
  const rows = Array.isArray(rawVul) ? rawVul : rawVul ? [rawVul] : [];
  const out: BduVulxmlRecord[] = [];
  for (const row of rows) {
    const rec = parseBduVulNode(row);
    if (rec) out.push(rec);
  }
  return out;
}

export async function loadBduVulxmlRecords(timeoutMs: number) {
  const { xml, sourceUrl, usedFallback } = await fetchBduVulxmlWithFallback(timeoutMs);
  const records = parseBduVulxmlDocument(xml);
  return { records, sourceUrl, usedFallback };
}

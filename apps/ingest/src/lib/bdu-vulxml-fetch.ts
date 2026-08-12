import { XMLParser } from "fast-xml-parser";
import { fetchBduVulxmlWithFallback, parseBduVulNode, type BduVulxmlRecord } from "@vuln-intel/shared";

export { fetchBduVulxmlWithFallback } from "@vuln-intel/shared";

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  trimValues: true,
  processEntities: false
});

const VUL_OPEN = Buffer.from("<vul");
const VUL_CLOSE = Buffer.from("</vul>");
/** V8 max string length ≈ 512MiB; keep margin for UTF-8 expansion. */
const MAX_SINGLE_STRING_BYTES = 480 * 1024 * 1024;
const MAX_VUL_FRAGMENT_BYTES = 32 * 1024 * 1024;

function looksLikeVulOpen(buf: Buffer, start: number): boolean {
  // Match `<vul>` / `<vul ` / `<vul/` but not `<vulnerabilities`.
  const probe = buf.subarray(start, Math.min(start + 20, buf.length)).toString("latin1");
  return /^<vul([\s>/]|$)/.test(probe);
}

/**
 * Parse BDU vulxml without materializing the whole document as one JS string.
 * Official dumps can exceed V8's ~512MB string limit (`Cannot create a string longer than 0x1fffffe8`).
 */
export function parseBduVulxmlDocument(xml: Buffer | string): BduVulxmlRecord[] {
  const buf = Buffer.isBuffer(xml) ? xml : Buffer.from(xml, "utf8");

  if (buf.length <= MAX_SINGLE_STRING_BYTES) {
    try {
      return parseBduVulxmlAsWholeDocument(buf.toString("utf8"));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (!/string longer than|Invalid string length/i.test(msg)) throw e;
      // Fall through to chunked parse.
    }
  }

  return parseBduVulxmlChunked(buf);
}

function parseBduVulxmlAsWholeDocument(xml: string): BduVulxmlRecord[] {
  const parsed = xmlParser.parse(xml) as Record<string, unknown>;
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

function parseBduVulxmlChunked(buf: Buffer): BduVulxmlRecord[] {
  const out: BduVulxmlRecord[] = [];
  let pos = 0;
  let skipped = 0;

  while (pos < buf.length) {
    const start = buf.indexOf(VUL_OPEN, pos);
    if (start < 0) break;
    if (!looksLikeVulOpen(buf, start)) {
      pos = start + 4;
      continue;
    }
    const closeAt = buf.indexOf(VUL_CLOSE, start + 4);
    if (closeAt < 0) break;
    const end = closeAt + VUL_CLOSE.length;
    const sliceLen = end - start;
    if (sliceLen <= 0 || sliceLen > MAX_VUL_FRAGMENT_BYTES) {
      skipped += 1;
      pos = end;
      continue;
    }
    try {
      const fragment = buf.subarray(start, end).toString("utf8");
      const doc = xmlParser.parse(fragment) as Record<string, unknown>;
      const rec = parseBduVulNode(doc.vul);
      if (rec) out.push(rec);
      else skipped += 1;
    } catch {
      skipped += 1;
    }
    pos = end;
  }

  if (out.length === 0) {
    throw new Error(
      `BDU vulxml chunk parse found 0 <vul> nodes (bytes=${buf.length}, skipped=${skipped}). ` +
        `Primary FSTEC fetch may have returned a non-XML payload, or the dump format changed.`
    );
  }

  // eslint-disable-next-line no-console
  console.log(`[bdu-parse] chunked ok records=${out.length} skipped=${skipped} bytes=${buf.length}`);
  return out;
}

export async function loadBduVulxmlRecords(timeoutMs: number) {
  const { xml, sourceUrl, usedFallback } = await fetchBduVulxmlWithFallback(timeoutMs);
  // eslint-disable-next-line no-console
  console.log(
    `[bdu-parse] loaded source=${sourceUrl} fallback=${usedFallback} xmlBytes=${xml.length}`
  );
  const records = parseBduVulxmlDocument(xml);
  return { records, sourceUrl, usedFallback };
}

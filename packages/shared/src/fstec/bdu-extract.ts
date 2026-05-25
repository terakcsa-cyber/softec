const BDU_ID_RE = /(?:BDU|bdu):\s*(\d{4}-\d{4,6})/gi;

export function extractBduIds(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  let m: RegExpExecArray | null;
  const re = new RegExp(BDU_ID_RE.source, BDU_ID_RE.flags);
  while ((m = re.exec(text)) !== null) {
    const id = m[1];
    if (!id || seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }
  return out;
}

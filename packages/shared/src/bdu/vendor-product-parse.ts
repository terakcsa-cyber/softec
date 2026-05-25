/** Пары vendor/product из полей БДУ (как в UI карточки BDU). */
export function parseBduVendorProductPairs(
  softwareNames?: string | null,
  vendors?: string | null
): Array<{ vendor: string; product: string }> {
  const out: Array<{ vendor: string; product: string }> = [];
  const names = (softwareNames ?? "")
    .split(/\s{2,}|\n|;/)
    .map((s) => s.trim())
    .filter(Boolean);
  const vendorList = (vendors ?? "")
    .split(/\s{2,}|\n|;/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (names.length === 0 && vendorList.length === 0) return out;
  const n = Math.max(names.length, vendorList.length, 1);
  for (let i = 0; i < n && out.length < 40; i++) {
    const vendor = vendorList[i] ?? vendorList[0] ?? "";
    const product = names[i] ?? names[0] ?? "";
    if (!vendor && !product) continue;
    out.push({
      vendor: vendor || "—",
      product: product || "—"
    });
  }
  return out;
}

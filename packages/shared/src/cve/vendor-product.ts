export type VendorProductSource = "cpe" | "sourceIdentifier" | "reference";
export type VendorProductPair = { vendor: string; product: string | null; source: VendorProductSource };

function normalizeKey(s: string | null | undefined): string | null {
  if (!s) return null;
  let k = String(s).trim().toLowerCase();
  k = k.replace(/%20/g, " ");
  k = k.replace(/\s+/g, "_");
  k = k.replace(/_+/g, "_").replace(/^_|_$/g, "");
  return k.length ? k : null;
}

function extractCpe23UrisFromRaw(raw: any): string[] {
  const out: string[] = [];
  const stack: unknown[] = [raw];
  while (stack.length > 0) {
    const cur = stack.pop();
    if (!cur) continue;
    if (Array.isArray(cur)) {
      for (const v of cur) stack.push(v);
      continue;
    }
    if (typeof cur !== "object") continue;
    const o = cur as Record<string, unknown>;
    for (const [k, v] of Object.entries(o)) {
      if (k === "criteria" && typeof v === "string" && v.startsWith("cpe:2.3:")) {
        out.push(v);
        continue;
      }
      if (v && (typeof v === "object" || Array.isArray(v))) stack.push(v);
    }
  }
  return out;
}

function parseCpe23VendorProduct(uri: string): { vendor: string | null; product: string | null } {
  const parts = uri.split(":");
  if (parts.length < 5) return { vendor: null, product: null };
  const vendor = parts[3] && parts[3] !== "*" ? parts[3] : null;
  const product = parts[4] && parts[4] !== "*" ? parts[4] : null;
  return { vendor, product };
}

function vendorFromHostname(hostname: string): string | null {
  const host = hostname.toLowerCase().replace(/\.+$/, "");
  if (!host || host === "localhost") return null;
  const parts = host.split(".").filter(Boolean);
  if (parts.length === 0) return null;
  if (parts.length === 1) return normalizeKey(parts[0]);

  const tlds = new Set([
    "com",
    "org",
    "net",
    "io",
    "gov",
    "edu",
    "co",
    "ru",
    "cn",
    "de",
    "uk",
    "jp",
    "fr",
    "it",
    "es",
    "nl",
    "se",
    "no",
    "fi",
    "pl",
    "br",
    "in",
    "au",
    "ca",
    "us",
    "ch"
  ]);
  const secondLevel = new Set(["co", "com", "org", "net", "gov", "edu"]);

  const last = parts[parts.length - 1] ?? "";
  const prev = parts[parts.length - 2] ?? "";
  if (tlds.has(last) && secondLevel.has(prev) && parts.length >= 3) {
    return normalizeKey(parts[parts.length - 3] ?? null);
  }
  if (tlds.has(prev) && parts.length >= 3) {
    return normalizeKey(parts[parts.length - 3] ?? null);
  }
  const cand = normalizeKey(prev);
  if (!cand || tlds.has(cand)) return null;
  return cand;
}

function vendorFromSourceIdentifier(raw: any): string | null {
  const s = typeof raw?.sourceIdentifier === "string" ? raw.sourceIdentifier : null;
  if (!s) return null;
  const at = s.lastIndexOf("@");
  if (at >= 0 && at < s.length - 1) {
    const domain = s.slice(at + 1).toLowerCase();
    return vendorFromHostname(domain);
  }
  if (s.length <= 64) return s.toLowerCase();
  return null;
}

function vendorFromReferences(raw: any): string | null {
  const refs = Array.isArray(raw?.references) ? raw.references : [];
  for (const r of refs) {
    const url = typeof r?.url === "string" ? r.url : null;
    if (!url) continue;
    try {
      const u = new URL(url);
      const vendor = vendorFromHostname(u.hostname);
      if (vendor) return vendor;
    } catch {
      // ignore
    }
  }
  return null;
}

function vendorProductFromReferences(raw: any): { vendor: string | null; product: string | null; source: VendorProductSource } {
  const refs = Array.isArray(raw?.references) ? raw.references : [];
  for (const r of refs) {
    const url = typeof r?.url === "string" ? r.url : null;
    if (!url) continue;
    try {
      const u = new URL(url);
      const host = u.hostname.toLowerCase();
      const path = u.pathname.replace(/\/+$/, "");
      const seg = path.split("/").filter(Boolean);
      if (!host) continue;

      const stop = new Set([
        "security",
        "advisories",
        "advisory",
        "blog",
        "docs",
        "support",
        "kb",
        "cve",
        "cves",
        "browse",
        "browser",
        "search",
        "ticket",
        "trac",
        "changeset",
        "changelog",
        "release",
        "releases",
        "download",
        "downloads",
        "index",
        "index.html",
        "en",
        "fr",
        "de",
        "es",
        "it",
        "pt",
        "ru",
        "zh",
        "ja",
        "ko"
      ]);
      const cleanProduct = (s: string | null | undefined) => {
        const k = normalizeKey(s);
        if (!k) return null;
        if (k.length < 3) return null;
        if (k.length > 48) return null;
        if (stop.has(k)) return null;
        if (k.endsWith(".html") || k.endsWith(".htm") || k.endsWith(".php") || k.endsWith(".aspx")) return null;
        return k;
      };

      if ((host === "github.com" || host === "gitlab.com" || host === "bitbucket.org") && seg.length >= 2) {
        const vendor = normalizeKey(seg[0]);
        const product = seg[1] === "repos" ? null : cleanProduct(seg[1]);
        if (vendor) return { vendor, product, source: "reference" };
      }

      if ((host === "wordpress.org" || host.endsWith(".wordpress.org")) && seg[0] === "plugins") {
        const vendor = normalizeKey("wordpress");
        if (seg.length >= 2) {
          const slug = cleanProduct(seg[1]);
          const product = slug && slug !== "browse" && slug !== "search" ? slug : null;
          if (vendor) return { vendor, product, source: "reference" };
        }
        if (vendor) return { vendor, product: null, source: "reference" };
      }

      const domainVendor = vendorFromHostname(host);
      if (domainVendor) {
        const product = seg.length >= 1 ? cleanProduct(seg[0]) : null;
        return { vendor: domainVendor, product, source: "reference" };
      }
    } catch {
      // ignore
    }
  }
  return { vendor: null, product: null, source: "reference" };
}

export function extractVendorProductPairsFromCveRaw(raw: any): VendorProductPair[] {
  const pairs: VendorProductPair[] = [];

  const cpes = extractCpe23UrisFromRaw(raw);
  if (cpes.length > 0) {
    for (const cpe of cpes) {
      const { vendor, product } = parseCpe23VendorProduct(cpe);
      const v = normalizeKey(vendor);
      if (!v) continue;
      const p = normalizeKey(product);
      pairs.push({ vendor: v, product: p, source: "cpe" });
    }
  } else {
    const fromRefs = vendorProductFromReferences(raw);
    if (fromRefs.vendor) {
      pairs.push({ vendor: fromRefs.vendor, product: fromRefs.product, source: fromRefs.source });
    } else {
      const v = normalizeKey(vendorFromSourceIdentifier(raw) ?? vendorFromReferences(raw));
      if (v) pairs.push({ vendor: v, product: null, source: "sourceIdentifier" });
    }
  }

  const dedup = new Map<string, VendorProductPair>();
  for (const p of pairs) {
    const k = `${p.vendor}\0${p.product ?? ""}`;
    if (!dedup.has(k)) dedup.set(k, p);
  }
  return Array.from(dedup.values());
}


import { Agent, fetch as undiciFetch } from "undici";

export const MPVM_DEFAULT_PDQL =
  "select(@Host, Host.@Id, Host.Hostname, Host.IpAddress, Host.OsName, Host.OsVersion) | limit(0)";

export const MPVM_DEFAULT_INVENTORY_PDQL =
  "select(@Host, Host.@Id, Host.Hostname, Host.IpAddress, Host.OsName, Host.OsVersion, Host.Software.Name, Host.Software.Version, Host.Software.Vendor, Host.Software.InstallPath, Host.Vulnerabilities.CVE, Host.Vulnerabilities.Name, Host.Vulnerabilities.Severity, Host.Vulnerabilities.CvssScore, Host.Vulnerabilities.Status, Host.Vulnerabilities.HasFix, Host.Vulnerabilities.Solution) | limit(0)";

export type MpvmClientConfig = {
  baseUrl: string;
  /** Логин учётной записи (для password-grant или подпись в UI). */
  username?: string;
  /** Bearer / API-токен (основной способ). */
  apiToken?: string;
  password?: string;
  clientSecret?: string;
  authPort?: number;
  tlsInsecure?: boolean;
  pdql?: string;
  timeoutMs?: number;
};

export type MpvmParsedAsset = {
  externalId: string;
  hostname: string | null;
  ipAddress: string | null;
  osName: string | null;
  osVersion: string | null;
  displayName: string;
  raw: Record<string, unknown>;
};

export type MpvmParsedSoftware = {
  assetExternalId: string;
  softwareKey: string;
  kind: "software" | "package";
  name: string;
  version: string | null;
  vendor: string | null;
  installPath: string | null;
  raw: Record<string, unknown>;
};

export type MpvmParsedVulnerability = {
  assetExternalId: string;
  vulnKey: string;
  cveId: string | null;
  title: string | null;
  severity: string | null;
  cvssScore: number | null;
  status: string | null;
  fixAvailable: boolean | null;
  solution: string | null;
  affectedSoftwareKey: string | null;
  affectedSoftwareName: string | null;
  affectedSoftwareVersion: string | null;
  raw: Record<string, unknown>;
};

export type MpvmSyncResult = {
  fetched: number;
  upserted: number;
  pdql: string;
};

function dispatcher(tlsInsecure?: boolean): Agent | undefined {
  if (tlsInsecure) return new Agent({ connect: { rejectUnauthorized: false } });
  return undefined;
}

function normalizeBaseUrl(raw: string): string {
  const t = raw.trim().replace(/\/+$/, "");
  if (!t) throw new Error("baseUrl is required");
  if (!/^https?:\/\//i.test(t)) return `https://${t}`;
  return t;
}

function apiRoot(baseUrl: string): string {
  const u = new URL(normalizeBaseUrl(baseUrl));
  if (u.port === "3334") u.port = "";
  return u.origin;
}

function tokenUrl(baseUrl: string, authPort: number): string {
  const u = new URL(normalizeBaseUrl(baseUrl));
  u.port = String(authPort);
  u.pathname = "/connect/token";
  return u.toString();
}

async function mpvmFetch(
  url: string,
  init: RequestInit & { timeoutMs?: number; tlsInsecure?: boolean }
): Promise<Response> {
  const timeoutMs = init.timeoutMs ?? 60_000;
  const { timeoutMs: _t, tlsInsecure, ...rest } = init;
  const res = await undiciFetch(url, {
    ...rest,
    dispatcher: dispatcher(tlsInsecure),
    signal: AbortSignal.timeout(timeoutMs)
  } as Parameters<typeof undiciFetch>[1]);
  return res as unknown as Response;
}

export async function fetchMpvmAccessToken(cfg: MpvmClientConfig): Promise<string> {
  const token = cfg.apiToken?.trim();
  if (token) return token;

  const username = cfg.username?.trim();
  const password = cfg.password?.trim();
  const clientSecret = cfg.clientSecret?.trim();
  if (!username || !password || !clientSecret) {
    throw new Error("Укажите API-токен или пару логин/пароль + ClientSecret");
  }

  const authPort = cfg.authPort ?? 3334;
  const body = new URLSearchParams({
    grant_type: "password",
    username,
    password,
    client_id: "mpx",
    client_secret: clientSecret,
    response_type: "id_token token",
    scope: "offline_access mpx.api"
  });

  const res = await mpvmFetch(tokenUrl(cfg.baseUrl, authPort), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: body.toString(),
    timeoutMs: cfg.timeoutMs,
    tlsInsecure: cfg.tlsInsecure
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`MP VM token HTTP ${res.status}: ${text.slice(0, 400)}`);
  }
  let json: unknown;
  try {
    json = JSON.parse(text) as unknown;
  } catch {
    throw new Error("MP VM token: invalid JSON");
  }
  const access =
    json != null && typeof json === "object" && !Array.isArray(json)
      ? String((json as Record<string, unknown>).access_token ?? "").trim()
      : "";
  if (!access) throw new Error("MP VM token: access_token missing");
  return access;
}

function pickField(row: Record<string, unknown>, keys: string[]): string | null {
  for (const k of keys) {
    const v = row[k];
    if (v == null) continue;
    const s = String(v).trim();
    if (s) return s;
  }
  return null;
}

function pickNumber(row: Record<string, unknown>, keys: string[]): number | null {
  for (const k of keys) {
    const v = row[k];
    if (typeof v === "number" && Number.isFinite(v)) return v;
    if (typeof v === "string") {
      const n = Number(v.replace(",", ".").trim());
      if (Number.isFinite(n)) return n;
    }
  }
  return null;
}

function pickBoolean(row: Record<string, unknown>, keys: string[]): boolean | null {
  for (const k of keys) {
    const v = row[k];
    if (typeof v === "boolean") return v;
    if (typeof v === "number") return v !== 0;
    if (typeof v === "string") {
      const s = v.trim().toLowerCase();
      if (["true", "yes", "y", "1", "да", "есть"].includes(s)) return true;
      if (["false", "no", "n", "0", "нет", "—", "-"].includes(s)) return false;
    }
  }
  return null;
}

function keyPart(s: string | null | undefined): string {
  return String(s ?? "").trim().toLowerCase().replace(/\s+/g, " ").slice(0, 160);
}

function stableInventoryKey(parts: Array<string | null | undefined>): string {
  const joined = parts.map(keyPart).filter(Boolean).join("|");
  return joined || "unknown";
}

function extractCveId(row: Record<string, unknown>): string | null {
  const direct = pickField(row, [
    "Host.Vulnerabilities.CVE",
    "Host.Vulnerability.CVE",
    "Vulnerabilities.CVE",
    "Vulnerability.CVE",
    "Vulnerability.CveId",
    "Vulnerability.CveIds",
    "CVE",
    "CveId",
    "cve",
    "cveId"
  ]);
  const fromDirect = direct?.match(/CVE-\d{4}-\d{4,}/i)?.[0]?.toUpperCase();
  if (fromDirect) return fromDirect;
  const fromRaw = JSON.stringify(row).match(/CVE-\d{4}-\d{4,}/i)?.[0]?.toUpperCase();
  return fromRaw ?? null;
}

function rowToRecord(row: unknown, fields?: Array<{ name?: string }>): Record<string, unknown> {
  if (row != null && typeof row === "object" && !Array.isArray(row)) {
    return row as Record<string, unknown>;
  }
  if (!Array.isArray(row) || !fields?.length) return {};
  const out: Record<string, unknown> = {};
  for (let i = 0; i < fields.length; i++) {
    const name = fields[i]?.name;
    if (name) out[name] = row[i];
  }
  return out;
}

export function parseMpvmAssetRow(row: Record<string, unknown>): MpvmParsedAsset | null {
  const externalId = pickField(row, ["Host.@Id", "Host.@id", "@Id", "id", "assetId"]);
  if (!externalId) return null;
  const hostname = pickField(row, ["Host.Hostname", "Host.hostname", "Hostname", "hostname"]);
  const ipAddress = pickField(row, ["Host.IpAddress", "Host.ip", "IpAddress", "ip"]);
  const osName = pickField(row, ["Host.OsName", "Host.osName", "OsName"]);
  const osVersion = pickField(row, ["Host.OsVersion", "Host.osVersion", "OsVersion"]);
  const displayName = hostname || ipAddress || externalId;
  return {
    externalId,
    hostname,
    ipAddress,
    osName,
    osVersion,
    displayName,
    raw: row
  };
}

export function parseMpvmSoftwareRow(row: Record<string, unknown>): MpvmParsedSoftware | null {
  const asset = parseMpvmAssetRow(row);
  if (!asset) return null;
  const name = pickField(row, [
    "Host.Software.Name",
    "Host.InstalledSoftware.Name",
    "Software.Name",
    "InstalledSoftware.Name",
    "Application.Name",
    "Host.Package.Name",
    "Package.Name",
    "softwareName",
    "software.name",
    "packageName"
  ]);
  if (!name) return null;
  const version = pickField(row, [
    "Host.Software.Version",
    "Host.InstalledSoftware.Version",
    "Software.Version",
    "InstalledSoftware.Version",
    "Application.Version",
    "Host.Package.Version",
    "Package.Version",
    "softwareVersion",
    "software.version",
    "packageVersion"
  ]);
  const vendor = pickField(row, [
    "Host.Software.Vendor",
    "Host.InstalledSoftware.Vendor",
    "Software.Vendor",
    "InstalledSoftware.Vendor",
    "Application.Vendor",
    "Host.Package.Vendor",
    "Package.Vendor",
    "softwareVendor",
    "vendor"
  ]);
  const installPath = pickField(row, [
    "Host.Software.InstallPath",
    "Host.InstalledSoftware.InstallPath",
    "Software.InstallPath",
    "InstalledSoftware.InstallPath",
    "Host.Package.InstallPath",
    "Package.InstallPath",
    "installPath"
  ]);
  const softwareKey = stableInventoryKey([vendor, name, version, installPath]);
  const kind =
    pickField(row, ["Host.Package.Name", "Package.Name", "packageName"]) != null ||
    Object.keys(row).some((k) => /package/i.test(k))
      ? "package"
      : "software";
  return {
    assetExternalId: asset.externalId,
    softwareKey,
    kind,
    name,
    version,
    vendor,
    installPath,
    raw: row
  };
}

export function parseMpvmVulnerabilityRow(row: Record<string, unknown>): MpvmParsedVulnerability | null {
  const asset = parseMpvmAssetRow(row);
  if (!asset) return null;
  const cveId = extractCveId(row);
  const title = pickField(row, [
    "Host.Vulnerabilities.Name",
    "Host.Vulnerabilities.Title",
    "Host.Vulnerability.Name",
    "Vulnerabilities.Name",
    "Vulnerabilities.Title",
    "Vulnerability.Name",
    "Vulnerability.Title",
    "vulnerabilityName",
    "vulnerabilityTitle"
  ]);
  const vulnId = pickField(row, [
    "Host.Vulnerabilities.@Id",
    "Host.Vulnerabilities.Id",
    "Host.Vulnerability.@Id",
    "Vulnerability.@Id",
    "Vulnerability.Id",
    "vulnerabilityId"
  ]);
  if (!cveId && !title && !vulnId) return null;

  const software = parseMpvmSoftwareRow(row);
  const severity = pickField(row, [
    "Host.Vulnerabilities.Severity",
    "Host.Vulnerabilities.SeverityLevel",
    "Vulnerability.Severity",
    "Vulnerability.SeverityLevel",
    "severity"
  ]);
  const cvssScore = pickNumber(row, [
    "Host.Vulnerabilities.CvssScore",
    "Host.Vulnerabilities.CVSS",
    "Vulnerability.CvssScore",
    "Vulnerability.CVSS",
    "cvss",
    "cvssScore"
  ]);
  const status = pickField(row, [
    "Host.Vulnerabilities.Status",
    "Vulnerability.Status",
    "vulnerabilityStatus",
    "status"
  ]);
  const fixAvailable = pickBoolean(row, [
    "Host.Vulnerabilities.HasFix",
    "Host.Vulnerabilities.FixAvailable",
    "Vulnerability.HasFix",
    "Vulnerability.FixAvailable",
    "hasFix",
    "fixAvailable"
  ]);
  const solution = pickField(row, [
    "Host.Vulnerabilities.Solution",
    "Host.Vulnerabilities.Remediation",
    "Vulnerability.Solution",
    "Vulnerability.Remediation",
    "solution",
    "remediation"
  ]);
  const vulnKey = stableInventoryKey([cveId, vulnId, title, software?.softwareKey]);
  return {
    assetExternalId: asset.externalId,
    vulnKey,
    cveId,
    title,
    severity,
    cvssScore,
    status,
    fixAvailable,
    solution,
    affectedSoftwareKey: software?.softwareKey ?? null,
    affectedSoftwareName: software?.name ?? null,
    affectedSoftwareVersion: software?.version ?? null,
    raw: row
  };
}

function extractRecords(payload: unknown, fields?: Array<{ name?: string }>): Record<string, unknown>[] {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return [];
  const o = payload as Record<string, unknown>;
  const candidates = [o.records, o.data, o.rows, o.items];
  for (const c of candidates) {
    if (!Array.isArray(c)) continue;
    return c.map((r) => rowToRecord(r, fields)).filter((r) => Object.keys(r).length > 0);
  }
  return [];
}

async function requestPdqlToken(
  accessToken: string,
  cfg: MpvmClientConfig,
  pdql: string
): Promise<{ token: string; fields?: Array<{ name?: string }> }> {
  const root = apiRoot(cfg.baseUrl);
  const url = `${root}/api/assets_temporal_readmodel/v1/assets_grid`;
  const res = await mpvmFetch(url, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      pdql,
      includeNestedGroups: true,
      additionalFilterParameters: { groupIds: [], assetIds: [] }
    }),
    timeoutMs: cfg.timeoutMs,
    tlsInsecure: cfg.tlsInsecure
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`MP VM assets_grid HTTP ${res.status}: ${text.slice(0, 500)}`);
  const json = JSON.parse(text) as Record<string, unknown>;
  const token = typeof json.token === "string" ? json.token.trim() : "";
  if (!token) throw new Error("MP VM: PDQL token missing in response");
  const fields = Array.isArray(json.fields)
    ? (json.fields as Array<{ name?: string }>)
    : undefined;
  return { token, fields };
}

async function fetchPdqlPage(
  accessToken: string,
  cfg: MpvmClientConfig,
  pdqlToken: string,
  offset: number,
  limit: number,
  fields?: Array<{ name?: string }>
): Promise<{ records: Record<string, unknown>[]; done: boolean }> {
  const root = apiRoot(cfg.baseUrl);
  const urls = [
    `${root}/api/assets_temporal_readmodel/v1/assets_grid/data`,
    `${root}/api/assets_temporal_readmodel/v1/assets_grid/${encodeURIComponent(pdqlToken)}/data`
  ];

  let lastErr: string | null = null;
  for (const url of urls) {
    try {
      const res = await mpvmFetch(url, {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          authorization: `Bearer ${accessToken}`
        },
        body: JSON.stringify({ token: pdqlToken, offset, limit }),
        timeoutMs: cfg.timeoutMs,
        tlsInsecure: cfg.tlsInsecure
      });
      const text = await res.text();
      if (!res.ok) {
        lastErr = `HTTP ${res.status}: ${text.slice(0, 300)}`;
        continue;
      }
      const json = JSON.parse(text) as unknown;
      const records = extractRecords(json, fields);
      const total =
        json != null && typeof json === "object" && !Array.isArray(json)
          ? Number((json as Record<string, unknown>).totalCount ?? (json as Record<string, unknown>).total)
          : NaN;
      const done = records.length < limit || (Number.isFinite(total) && offset + records.length >= total);
      return { records, done };
    } catch (e) {
      lastErr = e instanceof Error ? e.message : String(e);
    }
  }
  throw new Error(lastErr ?? "MP VM: failed to fetch PDQL data");
}

export async function verifyMpvmConnection(cfg: MpvmClientConfig): Promise<{
  ok: boolean;
  ms: number;
  error: string | null;
  assetSample: number;
  pdql: string;
}> {
  const started = Date.now();
  const pdql = (cfg.pdql?.trim() || MPVM_DEFAULT_PDQL).replace(/\|\s*limit\(\d+\)\s*$/i, "") + " | limit(5)";
  try {
    const access = await fetchMpvmAccessToken(cfg);
    const { token, fields } = await requestPdqlToken(access, cfg, pdql);
    const page = await fetchPdqlPage(access, cfg, token, 0, 5, fields);
    return {
      ok: true,
      ms: Date.now() - started,
      error: null,
      assetSample: page.records.length,
      pdql
    };
  } catch (e) {
    return {
      ok: false,
      ms: Date.now() - started,
      error: e instanceof Error ? e.message : String(e),
      assetSample: 0,
      pdql
    };
  }
}

export async function fetchAllMpvmAssets(cfg: MpvmClientConfig): Promise<{
  assets: MpvmParsedAsset[];
  pdql: string;
}> {
  const pdql = cfg.pdql?.trim() || MPVM_DEFAULT_PDQL;
  const access = await fetchMpvmAccessToken(cfg);
  const { token: pdqlToken, fields } = await requestPdqlToken(access, cfg, pdql);

  const limit = 1000;
  const maxRows = Math.max(1000, Math.min(200_000, Number(process.env.MPVM_SYNC_MAX_ROWS ?? 50_000)));
  const out: MpvmParsedAsset[] = [];
  const seen = new Set<string>();

  for (let offset = 0; offset < maxRows; offset += limit) {
    const page = await fetchPdqlPage(access, cfg, pdqlToken, offset, limit, fields);
    for (const row of page.records) {
      const parsed = parseMpvmAssetRow(row);
      if (!parsed || seen.has(parsed.externalId)) continue;
      seen.add(parsed.externalId);
      out.push(parsed);
    }
    if (page.done || page.records.length === 0) break;
  }

  return { assets: out, pdql };
}

export async function fetchAllMpvmInventory(cfg: MpvmClientConfig): Promise<{
  assets: MpvmParsedAsset[];
  software: MpvmParsedSoftware[];
  vulnerabilities: MpvmParsedVulnerability[];
  pdql: string;
  warning: string | null;
}> {
  const pdql = cfg.pdql?.trim() || MPVM_DEFAULT_INVENTORY_PDQL;
  const hasCustomPdql =
    Boolean(cfg.pdql?.trim()) && pdql !== MPVM_DEFAULT_INVENTORY_PDQL && pdql !== MPVM_DEFAULT_PDQL;
  const access = await fetchMpvmAccessToken(cfg);
  let pdqlToken: string;
  let fields: Array<{ name?: string }> | undefined;
  let warning: string | null = null;

  try {
    const tokenRes = await requestPdqlToken(access, cfg, pdql);
    pdqlToken = tokenRes.token;
    fields = tokenRes.fields;
  } catch (e) {
    if (hasCustomPdql) throw e;
    warning = `Extended MPVM inventory PDQL failed, fell back to asset-only PDQL: ${e instanceof Error ? e.message : String(e)}`;
    const tokenRes = await requestPdqlToken(access, cfg, MPVM_DEFAULT_PDQL);
    pdqlToken = tokenRes.token;
    fields = tokenRes.fields;
  }

  const effectivePdql = warning ? MPVM_DEFAULT_PDQL : pdql;
  const limit = 1000;
  const maxRows = Math.max(1000, Math.min(200_000, Number(process.env.MPVM_SYNC_MAX_ROWS ?? 50_000)));
  const assets: MpvmParsedAsset[] = [];
  const software: MpvmParsedSoftware[] = [];
  const vulnerabilities: MpvmParsedVulnerability[] = [];
  const seenAssets = new Set<string>();
  const seenSoftware = new Set<string>();
  const seenVulns = new Set<string>();

  for (let offset = 0; offset < maxRows; offset += limit) {
    const page = await fetchPdqlPage(access, cfg, pdqlToken, offset, limit, fields);
    for (const row of page.records) {
      const asset = parseMpvmAssetRow(row);
      if (asset && !seenAssets.has(asset.externalId)) {
        seenAssets.add(asset.externalId);
        assets.push(asset);
      }
      const sw = parseMpvmSoftwareRow(row);
      if (sw) {
        const k = `${sw.assetExternalId}|${sw.softwareKey}`;
        if (!seenSoftware.has(k)) {
          seenSoftware.add(k);
          software.push(sw);
        }
      }
      const vuln = parseMpvmVulnerabilityRow(row);
      if (vuln) {
        const k = `${vuln.assetExternalId}|${vuln.vulnKey}`;
        if (!seenVulns.has(k)) {
          seenVulns.add(k);
          vulnerabilities.push(vuln);
        }
      }
    }
    if (page.done || page.records.length === 0) break;
  }

  return { assets, software, vulnerabilities, pdql: effectivePdql, warning };
}

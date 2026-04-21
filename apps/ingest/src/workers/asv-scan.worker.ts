import { Injectable, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import amqplib, { Channel, ChannelModel, ConsumeMessage } from "amqplib";
import { DbService } from "../services/db.service.js";
import { sha256Hex, stableJsonStringify } from "@vuln-intel/shared";
import dns from "node:dns/promises";
import net from "node:net";
import { createHash, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import os from "node:os";
import fs from "node:fs/promises";
import path from "node:path";
import readline from "node:readline";

type AsvScanRequestedEnvelope = {
  type?: string;
  payload?: { scanRunId?: string; mode?: "safe" | "standard"; profileId?: string | null };
  [k: string]: unknown;
};

type AssetRow = {
  scan_run_id: string;
  asset_id: string;
  asset_type: "domain" | "ip" | "cidr" | "url";
  key_norm: string;
  display_name: string;
  scan_mode: "safe" | "standard";
  scope_policy: Record<string, unknown> | null;
};

type ScanProfileRow = {
  id: string;
  name: string;
  mode: "safe" | "standard";
  config: any;
};

type NucleiResolvedConfig = {
  enabled: boolean;
  templates: string[];
  tags: string[];
  excludeTags: string[];
  severity: string[];
  rateLimitPerMin: number;
  maxMs: number | null;
};

type ResolvedScanConfig = {
  mode: "safe" | "standard";
  profileName: string;
  ports: number[];
  httpPaths: string[];
  tcpTimeoutMs: number;
  httpTimeoutMs: number;
  maxPortConcurrency: number;
  maxHttpConcurrency: number;
  nuclei: NucleiResolvedConfig;
};

type NucleiReadiness = {
  enabled: boolean;
  reason?: string;
  planned: boolean;
};

type NucleiRunResult = {
  ok: boolean;
  exec: { kind: "bin"; bin: string; args: string[] } | { kind: "docker"; image: string; args: string[] };
  matched: number;
  linesCaptured: number;
  stdoutCaptured: string;
  stderrCaptured: string;
  jsonlCaptured: string;
  error?: string;
};

type AsvFindingRow = {
  fingerprint: string;
  title: string;
  severity: string;
  confidence: string;
  tool: string;
  external_id: string | null;
  affected: unknown;
  evidence: unknown;
};

function extractCveIdsFromText(text: string): string[] {
  const m = text.match(/CVE-\d{4}-\d{4,7}/gi) ?? [];
  const out = new Set<string>();
  for (const x of m) out.add(x.toUpperCase());
  return [...out].slice(0, 12);
}

function pickNucleiCveIds(obj: any): string[] {
  const info = obj?.info && typeof obj.info === "object" ? obj.info : {};
  const classification = info?.classification && typeof info.classification === "object" ? info.classification : {};

  const parts: string[] = [];
  parts.push(JSON.stringify(info));
  parts.push(JSON.stringify(classification));
  parts.push(typeof info.description === "string" ? info.description : "");
  parts.push(typeof info.name === "string" ? info.name : "");
  parts.push(typeof obj?.["curl-command"] === "string" ? obj["curl-command"] : "");
  parts.push(typeof obj?.["request"] === "string" ? obj["request"] : "");
  parts.push(typeof obj?.["matcher-name"] === "string" ? obj["matcher-name"] : "");

  const refs = Array.isArray(info.reference) ? info.reference.map(String) : [];
  parts.push(refs.join("\n"));

  const extracted = Array.isArray(obj?.["extracted-results"]) ? obj["extracted-results"] : [];
  parts.push(JSON.stringify(extracted));

  // Common nuclei classification keys (best-effort).
  for (const k of ["cve-id", "cve_id", "cveId", "CVE-ID", "CVE_ID"]) {
    const v = (classification as any)?.[k];
    if (typeof v === "string") parts.push(v);
    if (Array.isArray(v)) parts.push(v.map(String).join(","));
  }

  return extractCveIdsFromText(parts.join("\n"));
}

function severityRank(sev: string): number {
  const s = String(sev ?? "info").toLowerCase();
  if (s === "critical") return 5;
  if (s === "high") return 4;
  if (s === "medium") return 3;
  if (s === "low") return 2;
  return 1;
}

function pickWorstSeverity(a: string, b: string): string {
  return severityRank(a) >= severityRank(b) ? a : b;
}

function cvssBaseToSeverity(score: number | null | undefined): string | null {
  if (score == null || !Number.isFinite(score)) return null;
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0) return "low";
  return null;
}

const NUCLEI_TEMPLATES_READY = ".vip-nuclei-templates-ready";

/** Default PD-style tags (unknown tags are ignored by Nuclei with a warning). */
const NUCLEI_TAGS_SAFE = [
  "cve",
  "misconfiguration",
  "misconfig",
  "exposed-panels",
  "panel",
  "technologies",
  "tech",
  "exposure",
  "token-spray",
  "takeovers",
  "default-login",
  "osint"
];

const NUCLEI_TAGS_STANDARD = [
  ...NUCLEI_TAGS_SAFE,
  "vuln",
  "kubernetes",
  "k8s",
  "cloud",
  "devops",
  "config",
  "authentication",
  "microsoft",
  "azure",
  "aws",
  "gcp",
  "firebase",
  "jwt",
  "oauth",
  "graphql",
  "swagger",
  "api"
];

const NUCLEI_SEVERITY_ALL = ["critical", "high", "medium", "low", "info"];

function defaultNucleiConfig(mode: "safe" | "standard"): NucleiResolvedConfig {
  return {
    enabled: true,
    templates: [],
    tags: mode === "standard" ? NUCLEI_TAGS_STANDARD : NUCLEI_TAGS_SAFE,
    excludeTags: ["intrusive", "dos", "fuzz"],
    severity: NUCLEI_SEVERITY_ALL,
    rateLimitPerMin: mode === "standard" ? 600 : 280,
    // Per-profile override; when null, falls back to env/global default.
    maxMs: null
  };
}

function mergeNucleiConfig(mode: "safe" | "standard", raw: unknown): NucleiResolvedConfig {
  const def = defaultNucleiConfig(mode);
  if (!raw || typeof raw !== "object") return def;
  const r = raw as Record<string, unknown>;
  const tags = Array.isArray(r.tags) ? (r.tags as unknown[]).map(String).filter(Boolean) : def.tags;
  const excludeTags = Array.isArray(r.excludeTags)
    ? (r.excludeTags as unknown[]).map(String).filter(Boolean)
    : def.excludeTags;
  const severity = Array.isArray(r.severity)
    ? (r.severity as unknown[]).map(String).filter(Boolean)
    : def.severity;
  const templates = Array.isArray(r.templates) ? (r.templates as unknown[]).map(String).filter(Boolean) : def.templates;
  const rl = Number(r.rateLimitPerMin);
  const maxMsRaw = r.maxMs == null ? null : Number(r.maxMs);
  return {
    enabled: typeof r.enabled === "boolean" ? r.enabled : def.enabled,
    templates,
    tags: tags.length ? tags : def.tags,
    excludeTags: excludeTags.length ? excludeTags : def.excludeTags,
    severity: severity.length ? severity : def.severity,
    rateLimitPerMin: Number.isFinite(rl) && rl > 0 ? rl : def.rateLimitPerMin,
    maxMs: Number.isFinite(maxMsRaw) && (maxMsRaw as number) > 0 ? Math.floor(maxMsRaw as number) : null
  };
}

function nucleiTemplatesHostDir(): string {
  const fromEnv = process.env.ASV_NUCLEI_TEMPLATES_DIR?.trim();
  if (fromEnv) return fromEnv;
  return path.join(os.homedir(), ".vuln-intel", "nuclei-templates");
}

function inferTechHintsFromHttp(hr: { tech: unknown; server: string | null; title: string | null }): string[] {
  const out = new Set<string>();
  const add = (s: string) => {
    const v = s.trim().toLowerCase();
    if (!v) return;
    out.add(v);
  };

  if (hr.server) add(hr.server);
  if (hr.title) {
    const t = hr.title.toLowerCase();
    for (const k of ["grafana", "jenkins", "gitlab", "kibana", "prometheus", "splunk", "sonarqube", "keycloak"]) {
      if (t.includes(k)) add(k);
    }
  }

  const tech = hr.tech;
  if (Array.isArray(tech)) {
    for (const x of tech) add(String(x));
  } else if (tech && typeof tech === "object") {
    for (const k of Object.keys(tech as any)) add(String(k));
  } else if (typeof tech === "string") {
    add(tech);
  }

  for (const s of [...out]) {
    if (s.includes("nginx")) out.add("nginx");
    if (s.includes("apache")) out.add("apache");
    if (s.includes("gunicorn")) out.add("gunicorn");
    if (s.includes("cloudflare")) out.add("cloudflare");
    if (s.includes("iis")) out.add("iis");
    if (s.includes("openresty")) out.add("openresty");
  }

  return [...out].slice(0, 40);
}

function isHttpLiveStatus(status: number | null): boolean {
  if (status == null) return false;
  if (status >= 200 && status < 400) return true;
  if (status === 401 || status === 403) return true;
  return false;
}

function isLikelyWafHint(h: string): boolean {
  const s = h.toLowerCase();
  // Keep this list short and high-signal.
  return (
    s.includes("cloudflare") ||
    s.includes("akamai") ||
    s.includes("incapsula") ||
    s.includes("imperva") ||
    s.includes("sucuri") ||
    s.includes("fastly") ||
    s.includes("aws waf") ||
    s.includes("waf")
  );
}

function pct(n: number, d: number): number {
  if (!d) return 0;
  return Math.round((n / d) * 1000) / 10;
}

async function nucleiTemplatesNeedBootstrap(hostDir: string, force: boolean): Promise<boolean> {
  if (force) return true;
  try {
    await fs.access(path.join(hostDir, NUCLEI_TEMPLATES_READY));
    const entries = await fs.readdir(hostDir);
    const meaningful = entries.filter((e) => e !== NUCLEI_TEMPLATES_READY && !e.startsWith("."));
    return meaningful.length < 4;
  } catch {
    return true;
  }
}

async function runProcessWithTimeout(
  cmd: string,
  args: string[],
  timeoutMs: number,
  capture: (kind: "stdout" | "stderr", chunk: string) => void
): Promise<number> {
  return await new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    let done = false;
    const finish = (code: number) => {
      if (done) return;
      done = true;
      resolve(code);
    };
    const t = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        // ignore
      }
      finish(124);
    }, timeoutMs);
    child.stdout?.on("data", (d) => capture("stdout", d.toString("utf8")));
    child.stderr?.on("data", (d) => capture("stderr", d.toString("utf8")));
    child.on("error", () => {
      clearTimeout(t);
      finish(1);
    });
    child.on("exit", (code) => {
      clearTimeout(t);
      finish(code ?? 1);
    });
  });
}

async function ensureNucleiCommunityTemplates(opts: {
  useDocker: boolean;
  image: string;
  bin: string;
  hostDir: string;
  containerDir: string;
}): Promise<{ exitCode: number; log: string }> {
  const { useDocker, image, bin, hostDir, containerDir } = opts;
  const maxMs = Math.max(30_000, Math.min(1_800_000, Number(process.env.ASV_NUCLEI_UPDATE_MAX_MS ?? 900_000)));
  const chunks: string[] = [];
  const cap = (kind: "stdout" | "stderr", s: string) => {
    if (chunks.join("").length > 400_000) return;
    chunks.push(kind === "stderr" ? s : s);
  };

  const exitCode = useDocker
    ? await runProcessWithTimeout(
        "docker",
        // macOS: no --network host (same as scan runner).
        [
          "run",
          "--rm",
          "-v",
          `${hostDir}:${containerDir}`,
          ...(process.platform === "darwin" ? [] : ["--network", "host"]),
          image,
          "-ut",
          "-ud",
          containerDir
        ],
        maxMs,
        cap
      )
    : await runProcessWithTimeout(bin, ["-ut", "-ud", hostDir], maxMs, cap);

  return { exitCode, log: chunks.join("") };
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  const n = Math.max(1, Math.min(256, Math.floor(limit)));
  const workers = new Array(Math.min(n, items.length)).fill(null).map(async () => {
    while (true) {
      const idx = i++;
      if (idx >= items.length) return;
      out[idx] = await fn(items[idx]!);
    }
  });
  await Promise.all(workers);
  return out;
}

@Injectable()
export class AsvScanWorker implements OnModuleInit, OnModuleDestroy {
  private conn?: ChannelModel;
  private ch?: Channel;

  constructor(private readonly db: DbService) {}

  async onModuleInit() {
    const url = process.env.RABBITMQ_URL ?? "amqp://vuln:vuln@localhost:5672/";
    this.conn = await amqplib.connect(url);
    this.ch = await this.conn.createChannel();
    await this.ensureTopology();

    // Limit parallelism: one message at a time (safe baseline).
    await this.ch.prefetch(1);
    await this.ch.consume("asv.scan", (msg) => void this.handleMessage(msg), { noAck: false });
    // eslint-disable-next-line no-console
    console.log("[asv] worker ready queue=asv.scan prefetch=1");
  }

  private async ensureTopology() {
    if (!this.ch) throw new Error("channel not initialized");
    const ch = this.ch;
    await ch.assertExchange("vuln.events", "topic", { durable: true });
    await ch.assertExchange("vuln.dlx", "topic", { durable: true });
    await ch.assertQueue("asv.scan", {
      durable: true,
      arguments: {
        "x-dead-letter-exchange": "vuln.dlx",
        "x-dead-letter-routing-key": "dlq.asv.scan"
      }
    });
    await ch.bindQueue("asv.scan", "vuln.events", "asv.scan.requested.*");
    await ch.assertQueue("dlq.asv.scan", { durable: true });
    await ch.bindQueue("dlq.asv.scan", "vuln.dlx", "dlq.asv.scan");
  }

  private ack(msg: ConsumeMessage) {
    if (!this.ch) throw new Error("channel not initialized");
    this.ch.ack(msg);
  }

  private nack(msg: ConsumeMessage, requeue = false) {
    if (!this.ch) throw new Error("channel not initialized");
    this.ch.nack(msg, false, requeue);
  }

  private async handleMessage(msg: ConsumeMessage | null) {
    if (!msg) return;
    const raw = msg.content.toString("utf8");
    let env: AsvScanRequestedEnvelope;
    try {
      env = JSON.parse(raw) as AsvScanRequestedEnvelope;
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn(`[asv] bad json, dropping: ${e instanceof Error ? e.message : String(e)}`);
      this.ack(msg);
      return;
    }

    const scanRunId = env?.payload?.scanRunId;
    if (!scanRunId || typeof scanRunId !== "string") {
      // eslint-disable-next-line no-console
      console.warn("[asv] missing payload.scanRunId, dropping");
      this.ack(msg);
      return;
    }

    try {
      const requestedMode = env?.payload?.mode === "standard" ? "standard" : "safe";
      const requestedProfileId =
        typeof env?.payload?.profileId === "string" && env.payload.profileId.length > 0 ? env.payload.profileId : null;

      // Mark running (idempotent).
      await this.db.query(
        `UPDATE asv_scan_run
            SET status = CASE WHEN status IN ('completed','failed','cancelled') THEN status ELSE 'running' END,
                started_at = COALESCE(started_at, now()),
                updated_at = now()
          WHERE id = $1`,
        [scanRunId]
      );

      const base = await this.db.query<{
        scan_run_id: string;
        asset_id: string;
        asset_type: "domain" | "ip" | "cidr" | "url";
        key_norm: string;
        display_name: string;
        scan_mode: "safe" | "standard";
        scope_policy: any;
      }>(
        `SELECT r.id as scan_run_id, a.id as asset_id, a.asset_type, a.key_norm, a.display_name, r.scan_mode, a.scope_policy
           FROM asv_scan_run r
           JOIN asv_asset a ON a.id = r.asset_id
          WHERE r.id = $1`,
        [scanRunId]
      );
      const row = base.rows[0];
      if (!row) {
        // eslint-disable-next-line no-console
        console.warn(`[asv] scan run not found: ${scanRunId}`);
        this.ack(msg);
        return;
      }

      // Always create an early artifact at message start (defensive; helps diagnose hangs).
      try {
        const content = [
          `[asv] scanRunId=${scanRunId}`,
          `[asv] asset_id=${row.asset_id}`,
          `[asv] asset_type=${row.asset_type} key_norm=${row.key_norm}`,
          `[asv] requestedMode=${requestedMode} profileId=${requestedProfileId ?? "null"}`,
          `[asv] note=early-artifact`
        ].join("\n");
        const bytes = Buffer.byteLength(content, "utf8");
        const sha256 = createHash("sha256").update(content).digest("hex");
        await this.db.query(
          `INSERT INTO asv_scan_artifact (scan_run_id, kind, bytes, sha256, storage, content_text)
           VALUES ($1,'scanner.log',$2,$3,'inline',$4)`,
          [scanRunId, bytes, sha256, content]
        );
      } catch (e) {
        // eslint-disable-next-line no-console
        console.warn(`[asv] early scanner.log insert failed: ${e instanceof Error ? e.message : String(e)}`);
      }

      const scan = await this.scanAsset({
        scan_run_id: row.scan_run_id,
        asset_id: row.asset_id,
        asset_type: row.asset_type,
        key_norm: row.key_norm,
        display_name: row.display_name,
        scan_mode: row.scan_mode ?? "safe",
        scope_policy: row.scope_policy && typeof row.scope_policy === "object" ? (row.scope_policy as any) : null
      }, requestedMode, requestedProfileId);

      // Aggregate findings -> issues (best-effort; do not fail the scan).
      try {
        await this.upsertIssuesForRun(row.asset_id, scanRunId);
      } catch (e) {
        // eslint-disable-next-line no-console
        console.warn(`[asv] issues upsert failed: ${e instanceof Error ? e.message : String(e)}`);
      }

      const nucleiOk = Boolean((scan.stats as any)?.nuclei?.run?.ok);
      const nucleiErr = ((scan.stats as any)?.nuclei?.run?.error ?? null) as string | null;
      const nucleiFatal = typeof nucleiErr === "string" && nucleiErr.includes("[FTL]");

      await this.db.query(
        `UPDATE asv_scan_run
            SET status = CASE WHEN $3::boolean THEN 'failed' ELSE 'completed' END,
                error = CASE WHEN $3::boolean THEN LEFT(COALESCE($4::text, 'nuclei fatal error'), 2000) ELSE error END,
                ended_at = COALESCE(ended_at, now()),
                stats = $2::jsonb,
                updated_at = now()
          WHERE id = $1 AND status NOT IN ('failed','cancelled')`,
        [scanRunId, JSON.stringify(scan.stats), nucleiOk === false && nucleiFatal, nucleiErr]
      );

      this.ack(msg);
    } catch (e) {
      const err = e instanceof Error ? e.message : String(e);
      // eslint-disable-next-line no-console
      console.error(`[asv] scan failed: ${err}`);
      try {
        await this.db.query(
          `UPDATE asv_scan_run
              SET status = 'failed',
                  error = $2,
                  ended_at = COALESCE(ended_at, now()),
                  updated_at = now()
            WHERE id = $1`,
          [scanRunId, err]
        );
      } catch {
        // ignore
      }
      this.nack(msg, false);
    }
  }

  async onModuleDestroy() {
    try {
      await this.ch?.close();
    } finally {
      await this.conn?.close();
    }
  }

  private async scanAsset(
    asset: AssetRow,
    requestedMode: "safe" | "standard",
    requestedProfileId: string | null
  ): Promise<{
    stats: Record<string, unknown>;
  }> {
    const startedAt = Date.now();
    const resolved = await this.resolveConfig(asset, requestedMode, requestedProfileId);
    const targets = await this.expandTargets(asset);

    const nuclei = this.resolveNucleiReadiness(asset, resolved);

    // Always write an initial artifact early (so UI isn't empty even if later steps hang).
    await this.writeScanArtifact(asset.scan_run_id, "scanner.log", [
      `[asv] started_at=${new Date().toISOString()}`,
      `[asv] asset_type=${asset.asset_type} key_norm=${asset.key_norm}`,
      `[asv] requestedMode=${requestedMode} resolvedMode=${resolved.mode}`,
      `[asv] targets=${targets.length} ports=${resolved.ports.length}`,
      `[asv] nuclei.enabled=${nuclei.enabled} planned=${nuclei.planned}${nuclei.reason ? ` reason=${nuclei.reason}` : ""}`
    ].join("\n"));

    const allowStandard = resolved.mode === "standard";
    const portsToCheck = resolved.ports;
    let portOpen = 0;
    let httpObs = 0;
    let findings = 0;
    let httpAggressive = 0;

    const portTasks: Array<{ t: { target: string; ip?: string }; port: number }> = [];
    for (const t of targets) for (const port of portsToCheck) portTasks.push({ t, port });

    const openWeb: Array<{ target: string; port: number }> = [];
    const openPorts = new Set<number>();

    await mapLimit(portTasks, resolved.maxPortConcurrency, async ({ t, port }) => {
      const pr = await this.checkTcpPort(t.ip ?? t.target, port, resolved.tcpTimeoutMs);
      await this.db.query(
        `INSERT INTO asv_port_observation (asset_id, scan_run_id, target, ip, port, transport, state, latency_ms, evidence, observed_at)
         VALUES ($1,$2,$3,$4,$5,'tcp',$6,$7,$8,now())`,
        [
          asset.asset_id,
          asset.scan_run_id,
          t.target,
          t.ip ?? null,
          port,
          pr.state,
          pr.latencyMs,
          JSON.stringify({ error: pr.error ?? null })
        ]
      );
      if (pr.state === "open") portOpen++;
      if (pr.state === "open") openPorts.add(port);
      if (pr.state === "open" && (port === 80 || port === 8080 || port === 443 || port === 8443)) {
        openWeb.push({ target: t.target, port });
      }
      return null;
    });

    const httpTasks: Array<{ url: string; baseUrl: string }> = [];
    for (const w of openWeb) {
      const scheme = w.port === 443 || w.port === 8443 ? "https" : "http";
      const baseUrl = `${scheme}://${w.target}${w.port === 80 || w.port === 443 ? "" : `:${w.port}`}`;
      // For non-URL assets, keep HTTP probing minimal by default; monster profile uses full paths for tech hints + smart heavy phase.
      const paths =
        asset.asset_type === "url" ? resolved.httpPaths : resolved.profileName === "monster" ? resolved.httpPaths : ["/"];
      for (const pth of paths) {
        const url = pth === "/" ? `${baseUrl}/` : `${baseUrl}${pth}`;
        httpTasks.push({ url, baseUrl });
      }
    }

    const baseUrlStatus = new Map<string, number | null>();
    const baseUrlTech = new Map<string, Set<string>>();
    const baseUrlCounts = new Map<
      string,
      { total: number; nulls: number; s403: number; s429: number; s2xx3xx401: number }
    >();

    await mapLimit(httpTasks, resolved.maxHttpConcurrency, async ({ url, baseUrl }) => {
      const hr = await this.fetchHttp(url, resolved.httpTimeoutMs);
      await this.db.query(
        `INSERT INTO asv_http_observation (asset_id, scan_run_id, url, final_url, status, title, server, headers, tech, latency_ms, evidence, observed_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now())`,
        [
          asset.asset_id,
          asset.scan_run_id,
          url,
          hr.finalUrl,
          hr.status,
          hr.title,
          hr.server,
          JSON.stringify(hr.headers),
          JSON.stringify(hr.tech),
          hr.latencyMs,
          JSON.stringify({ error: hr.error ?? null })
        ]
      );
      httpObs++;
      if (resolved.httpPaths.length > 1 && !url.endsWith("/")) httpAggressive++;

      const prev = baseUrlStatus.get(baseUrl);
      const cur = hr.status ?? null;
      if (prev == null) baseUrlStatus.set(baseUrl, cur);
      else if (prev >= 500 && cur != null && cur < prev) baseUrlStatus.set(baseUrl, cur);

      const bc = baseUrlCounts.get(baseUrl) ?? { total: 0, nulls: 0, s403: 0, s429: 0, s2xx3xx401: 0 };
      bc.total++;
      if (cur == null) bc.nulls++;
      else if (cur === 403) bc.s403++;
      else if (cur === 429) bc.s429++;
      else if ((cur >= 200 && cur < 400) || cur === 401) bc.s2xx3xx401++;
      baseUrlCounts.set(baseUrl, bc);

      const hints = inferTechHintsFromHttp({ tech: hr.tech, server: hr.server, title: hr.title });
      if (hints.length) {
        const s = baseUrlTech.get(baseUrl) ?? new Set<string>();
        for (const h of hints) s.add(h);
        baseUrlTech.set(baseUrl, s);
      }

      const fp = await sha256Hex(
        stableJsonStringify({ kind: "http", url, status: hr.status ?? null, title: hr.title ?? null })
      );
      const fingerprint = `http:${fp.slice(0, 24)}`;
      const title = `HTTP surface: ${url} (${hr.status ?? "no-status"})${hr.title ? ` · ${hr.title}` : ""}`;
      await this.db.query(
        `INSERT INTO asv_finding (asset_id, scan_run_id, fingerprint, title, severity, confidence, tool, affected, evidence, status, first_seen, last_seen)
         VALUES ($1,$2,$3,$4,'info','medium','http-probe',$5,$6,'open',now(),now())
         ON CONFLICT (asset_id, fingerprint)
         DO UPDATE SET last_seen = now(), updated_at = now(), scan_run_id = EXCLUDED.scan_run_id`,
        [
          asset.asset_id,
          asset.scan_run_id,
          fingerprint,
          title,
          JSON.stringify({ url }),
          JSON.stringify([{ kind: "http", url, status: hr.status, finalUrl: hr.finalUrl, server: hr.server }])
        ]
      );
      findings++;
      return null;
    });

    // Nuclei
    let nucleiStats: Record<string, unknown> = nuclei;
    if (nuclei.enabled) {
      const scanRunStatus = await this.db
        .query<{ status: string }>(`SELECT status FROM asv_scan_run WHERE id = $1`, [asset.scan_run_id])
        .then((r) => r.rows[0]?.status ?? "running")
        .catch(() => "running");
      if (scanRunStatus === "cancelled") {
        await this.writeScanArtifact(asset.scan_run_id, "scanner.log", "[asv] aborted (cancelled before nuclei)");
        return {
          stats: {
            targets: targets.length,
            portsChecked: targets.length * resolved.ports.length,
            portsOpen: portOpen,
            httpObservations: httpObs,
            httpAggressive,
            findings,
            mode: resolved.mode,
            profile: { name: resolved.profileName, id: requestedProfileId ?? null },
            nuclei: { ...nuclei, aborted: true, reason: "cancelled" },
            elapsedMs: Date.now() - startedAt
          }
        };
      }

      let nucleiTemplateLog = "";
      if (process.env.ASV_NUCLEI_SKIP_TEMPLATE_BOOTSTRAP === "1") {
        nucleiTemplateLog = `[nuclei] ASV_NUCLEI_SKIP_TEMPLATE_BOOTSTRAP=1 (no -ut bootstrap)\n`;
      } else {
        try {
          nucleiTemplateLog = await this.bootstrapNucleiTemplates();
        } catch (e) {
          nucleiTemplateLog = `[nuclei] template bootstrap error: ${e instanceof Error ? e.message : String(e)}\n`;
        }
      }

      const runWithTimeout = async (label: string, r: ResolvedScanConfig, targets0: string[]) => {
        const maxNucleiMs = Number(r.nuclei.maxMs ?? process.env.ASV_NUCLEI_MAX_MS ?? 600_000);
        const nr = await Promise.race([
          this.runNuclei(asset, r, targets0),
          new Promise<NucleiRunResult>((resolve) =>
            setTimeout(() => {
              resolve({
                ok: false,
                exec: { kind: "docker", image: process.env.ASV_NUCLEI_IMAGE?.trim() || "projectdiscovery/nuclei:latest", args: [] },
                matched: 0,
                linesCaptured: 0,
                stdoutCaptured: "",
                stderrCaptured: `timeout after ${maxNucleiMs}ms`,
                jsonlCaptured: "",
                error: `timeout after ${maxNucleiMs}ms`
              });
            }, Math.max(5_000, Math.min(1_200_000, maxNucleiMs)))
          )
        ]).catch((e) => {
          const msg = e instanceof Error ? e.message : String(e);
          return {
            ok: false,
            exec: { kind: "bin", bin: this.nucleiBin() ?? "nuclei", args: [] },
            matched: 0,
            linesCaptured: 0,
            stdoutCaptured: "",
            stderrCaptured: msg,
            jsonlCaptured: "",
            error: msg
          } satisfies NucleiRunResult;
        });
        return { label, maxNucleiMs, nr };
      };

      // For IP/domain/CIDR assets, run nuclei in a port-oriented way (avoid web path scanning).
      if (asset.asset_type !== "url") {
        const portsList = Array.from(openPorts.values()).sort((a, b) => a - b).slice(0, 256);
        const hostList = targets.map((t) => t.target).filter(Boolean).slice(0, 500);
        const targetList = portsList.length
          ? hostList.flatMap((h) => portsList.map((p) => `${h}:${p}`)).slice(0, 2000)
          : hostList;
        const diagBase = [
          `[nuclei] mode=network asset_type=${asset.asset_type}`,
          `[nuclei] targets=${targetList.length}`,
          `[nuclei] ports=${portsList.length ? portsList.join(",") : "n/a"}`
        ].join("\n");

        const smartMonster = resolved.profileName === "monster";
        const phases: Array<{ label: string; ok: boolean; matched: number; maxMs: number; error?: string | null }> = [];
        const smartLogLines: string[] = [];

        let single: NucleiRunResult;

        if (!smartMonster) {
          const maxNucleiMs = Number(resolved.nuclei.maxMs ?? process.env.ASV_NUCLEI_MAX_MS ?? 600_000);
          single = await Promise.race([
            this.runNuclei(asset, { ...resolved, nuclei: { ...resolved.nuclei, tags: resolved.nuclei.tags } }, targetList),
            new Promise<NucleiRunResult>((resolve) =>
              setTimeout(() => {
                resolve({
                  ok: false,
                  exec: { kind: "docker", image: process.env.ASV_NUCLEI_IMAGE?.trim() || "projectdiscovery/nuclei:latest", args: [] },
                  matched: 0,
                  linesCaptured: 0,
                  stdoutCaptured: "",
                  stderrCaptured: `timeout after ${maxNucleiMs}ms`,
                  jsonlCaptured: "",
                  error: `timeout after ${maxNucleiMs}ms`
                });
              }, Math.max(5_000, Math.min(1_200_000, maxNucleiMs)))
            )
          ]).catch((e) => {
            const msg = e instanceof Error ? e.message : String(e);
            return {
              ok: false,
              exec: { kind: "bin", bin: this.nucleiBin() ?? "nuclei", args: [] },
              matched: 0,
              linesCaptured: 0,
              stdoutCaptured: "",
              stderrCaptured: msg,
              jsonlCaptured: "",
              error: msg
            } satisfies NucleiRunResult;
          });
        } else {
          const baseUrls = Array.from(
            new Set(
              httpTasks
                .map((t) => t.baseUrl.trim())
                .filter(Boolean)
                .map((u) => (u.endsWith("/") ? u.slice(0, -1) : u))
            )
          ).slice(0, 500);

          const liveOrigins = baseUrls.filter((u) => isHttpLiveStatus(baseUrlStatus.get(u) ?? null));

          const blockedOrigins = new Set<string>();
          for (const u of baseUrls) {
            const st = baseUrlStatus.get(u) ?? null;
            if (st !== 403 && st !== 429) continue;
            const hints = baseUrlTech.get(u);
            if (!hints) continue;
            if ([...hints].some(isLikelyWafHint)) blockedOrigins.add(u);
          }

          const unreachableOrigins = new Set<string>();
          if (resolved.profileName === "monster") {
            for (const u of baseUrls) {
              const c = baseUrlCounts.get(u);
              if (!c) continue;
              if (c.total < 6) continue;
              if (c.nulls / c.total >= 0.7) unreachableOrigins.add(u);
            }
          }

          const nucleiLive = liveOrigins.filter((u) => !blockedOrigins.has(u) && !unreachableOrigins.has(u));
          const nucleiAll = baseUrls.filter((u) => !blockedOrigins.has(u) && !unreachableOrigins.has(u));
          const nucleiTargets = nucleiLive.length ? nucleiLive : nucleiAll;

          const allTechHints = new Set<string>();
          for (const s of baseUrlTech.values()) for (const h of s) allTechHints.add(h);
          const techHintList = [...allTechHints].slice(0, 40);
          const wafHints = techHintList.filter(isLikelyWafHint);
          const wafBlocked = blockedOrigins.size > 0 && wafHints.length > 0;

          smartLogLines.push("[nuclei] smartMonster=1 (network)");
          smartLogLines.push(
            `[nuclei] targets.all=${baseUrls.length} targets.live=${liveOrigins.length} targets.blocked=${blockedOrigins.size} targets.unreachable=${unreachableOrigins.size} targets.used=${nucleiTargets.length}`
          );
          smartLogLines.push(`[nuclei] techHints=${techHintList.length ? techHintList.join(",") : "none"}`);
          if (wafBlocked) {
            smartLogLines.push(`[nuclei] wafDetected=${wafHints.join(",")}`);
          }
          if (unreachableOrigins.size) {
            const samples = [...unreachableOrigins].slice(0, 8).map((u) => {
              const c = baseUrlCounts.get(u);
              return `${u}{null=${c?.nulls ?? 0}/${c?.total ?? 0}=${pct(c?.nulls ?? 0, c?.total ?? 0)}%}`;
            });
            smartLogLines.push(`[nuclei] unreachableDetected=${samples.join(" ")}`);
          }

          let combined: NucleiRunResult | null = null;

          // Network nuclei uses host:port — unlike URL mode, do not zero the whole run when HTTP origins
          // are WAF-blocked or unreachable; still scan open TCP ports.
          if (targetList.length === 0) {
            smartLogLines.push("[nuclei] skipped (no host:port targets)");
            combined = {
              ok: true,
              exec: { kind: "docker", image: process.env.ASV_NUCLEI_IMAGE?.trim() || "projectdiscovery/nuclei:latest", args: [] },
              matched: 0,
              linesCaptured: 0,
              stdoutCaptured: "",
              stderrCaptured: "skipped (no host:port targets)",
              jsonlCaptured: ""
            };
          } else {
            if ((wafBlocked || unreachableOrigins.size > 0) && nucleiTargets.length === 0) {
              smartLogLines.push(
                "[nuclei] note=http_origins_unusable (WAF/unreachable/no usable origins); still running network nuclei on host:port"
              );
            }
            const liteTags = [
              "misconfiguration",
              "misconfig",
              "exposed-panels",
              "panel",
              "technologies",
              "tech",
              "exposure",
              "default-login",
              "osint",
              "takeovers"
            ];

            const liteResolved: ResolvedScanConfig = {
              ...resolved,
              nuclei: {
                ...resolved.nuclei,
                tags: liteTags,
                severity: ["critical", "high", "medium", "low", "info"],
                maxMs: Math.min(resolved.nuclei.maxMs ?? 600_000, 240_000)
              }
            };

            const lite = await runWithTimeout("lite", liteResolved, targetList);
            phases.push({ label: lite.label, ok: lite.nr.ok, matched: lite.nr.matched, maxMs: lite.maxNucleiMs, error: lite.nr.error ?? null });

            const heavyShouldRun = !wafBlocked && techHintList.length > 0 && targetList.length > 0;
            if (heavyShouldRun) {
              const status2 = await this.db
                .query<{ status: string }>(`SELECT status FROM asv_scan_run WHERE id = $1`, [asset.scan_run_id])
                .then((r) => r.rows[0]?.status ?? "running")
                .catch(() => "running");
              if (status2 === "cancelled") {
                smartLogLines.push("[nuclei] heavy skipped (cancelled)");
                combined = lite.nr;
              } else {
                const heavyResolved: ResolvedScanConfig = {
                  ...resolved,
                  nuclei: {
                    ...resolved.nuclei,
                    tags: ["cve", "vuln"],
                    severity: ["critical", "high"],
                    maxMs: Math.max(resolved.nuclei.maxMs ?? 600_000, 900_000)
                  }
                };
                const heavy = await runWithTimeout("heavy", heavyResolved, targetList);
                phases.push({ label: heavy.label, ok: heavy.nr.ok, matched: heavy.nr.matched, maxMs: heavy.maxNucleiMs, error: heavy.nr.error ?? null });

                combined = {
                  ok: lite.nr.ok && heavy.nr.ok,
                  exec: heavy.nr.exec,
                  matched: lite.nr.matched + heavy.nr.matched,
                  linesCaptured: lite.nr.linesCaptured + heavy.nr.linesCaptured,
                  stdoutCaptured: [lite.nr.stdoutCaptured, heavy.nr.stdoutCaptured].filter(Boolean).join("\n"),
                  stderrCaptured: [`[nuclei] phase=lite`, lite.nr.stderrCaptured, `[nuclei] phase=heavy`, heavy.nr.stderrCaptured]
                    .filter(Boolean)
                    .join("\n"),
                  jsonlCaptured: [lite.nr.jsonlCaptured, heavy.nr.jsonlCaptured].filter(Boolean).join("\n"),
                  error: heavy.nr.error ?? lite.nr.error
                };
              }
            } else {
              smartLogLines.push("[nuclei] heavy skipped (no tech hints)");
              combined = lite.nr;
            }
          }

          single = combined!;
          smartLogLines.push(
            `[nuclei] phases=${phases.map((p) => `${p.label}{ok=${p.ok},matched=${p.matched},maxMs=${p.maxMs}${p.error ? ",err" : ""}}`).join(" ")}`
          );
        }

        const stderrPrefix =
          smartMonster && smartLogLines.length
            ? `${nucleiTemplateLog}${diagBase}\n${smartLogLines.join("\n")}\n`
            : `${nucleiTemplateLog}${diagBase}\n`;

        nucleiStats = {
          ...nuclei,
          run: {
            ok: single.ok,
            matched: single.matched,
            error: single.error ?? null,
            exec: single.exec,
            linesCaptured: single.linesCaptured,
            templatesHostDir: nucleiTemplatesHostDir(),
            smartMonster,
            mode: "network",
            ports: portsList,
            ...(smartMonster && phases.length ? { phases } : {})
          }
        };

        await this.writeScanArtifact(asset.scan_run_id, "nuclei.stdout", single.stdoutCaptured || "");
        await this.writeScanArtifact(asset.scan_run_id, "nuclei.stderr", `${stderrPrefix}${single.stderrCaptured || ""}`);
        await this.writeScanArtifact(asset.scan_run_id, "nuclei.jsonl", single.jsonlCaptured || "");
      } else {
      const seedTargets: string[] = [];
      // Prefer base URLs (origins) rather than per-path URLs.
      for (const t of httpTasks) seedTargets.push(t.baseUrl);
      // For URL assets, always include the origin even if port-scan didn't yield open web ports.
      if (asset.asset_type === "url") {
        try {
          const u = new URL(asset.key_norm);
          seedTargets.push(u.origin);
        } catch {
          // ignore
        }
      }

      const baseUrls = Array.from(
        new Set(
          seedTargets
            .map((u) => u.trim())
            .filter(Boolean)
            .map((u) => (u.endsWith("/") ? u.slice(0, -1) : u))
        )
      ).slice(0, 500);

      const liveOrigins = baseUrls.filter((u) => isHttpLiveStatus(baseUrlStatus.get(u) ?? null));

      // If an origin looks "live" only because it returns 403, but also screams WAF, treat it as blocked.
      // This helps monster scans stop spending time on targets that actively shut us down.
      const blockedOrigins = new Set<string>();
      const unreachableOrigins = new Set<string>();
      for (const u of baseUrls) {
        const st = baseUrlStatus.get(u) ?? null;
        if (st !== 403 && st !== 429) continue;
        const hints = baseUrlTech.get(u);
        if (!hints) continue;
        if ([...hints].some(isLikelyWafHint)) blockedOrigins.add(u);
      }

      // If an origin is consistently timing out / yielding null status, treat it as unreachable and don't waste nuclei time.
      // Only applies aggressively to monster profile.
      if (resolved.profileName === "monster") {
        for (const u of baseUrls) {
          const c = baseUrlCounts.get(u);
          if (!c) continue;
          // Require some evidence before we decide.
          if (c.total < 6) continue;
          if (c.nulls / c.total >= 0.7) unreachableOrigins.add(u);
        }
      }

      const nucleiLive = liveOrigins.filter((u) => !blockedOrigins.has(u) && !unreachableOrigins.has(u));
      const nucleiAll = baseUrls.filter((u) => !blockedOrigins.has(u) && !unreachableOrigins.has(u));
      const nucleiTargets = nucleiLive.length ? nucleiLive : nucleiAll;

      const allTechHints = new Set<string>();
      for (const s of baseUrlTech.values()) for (const h of s) allTechHints.add(h);
      const techHintList = [...allTechHints].slice(0, 40);

      const smartMonster = resolved.profileName === "monster";
      const smartLogLines: string[] = [];
      const wafHints = techHintList.filter(isLikelyWafHint);
      const wafBlocked = blockedOrigins.size > 0 && wafHints.length > 0;
      smartLogLines.push(
        `[nuclei] targets.all=${baseUrls.length} targets.live=${liveOrigins.length} targets.blocked=${blockedOrigins.size} targets.unreachable=${unreachableOrigins.size} targets.used=${nucleiTargets.length}`
      );
      smartLogLines.push(`[nuclei] techHints=${techHintList.length ? techHintList.join(",") : "none"}`);
      if (wafBlocked) {
        smartLogLines.push(`[nuclei] wafDetected=${wafHints.join(",")}`);
      }
      if (unreachableOrigins.size) {
        const samples = [...unreachableOrigins].slice(0, 8).map((u) => {
          const c = baseUrlCounts.get(u);
          return `${u}{null=${c?.nulls ?? 0}/${c?.total ?? 0}=${pct(c?.nulls ?? 0, c?.total ?? 0)}%}`;
        });
        smartLogLines.push(`[nuclei] unreachableDetected=${samples.join(" ")}`);
      }

      let combined: NucleiRunResult | null = null;
      const phases: Array<{ label: string; ok: boolean; matched: number; maxMs: number; error?: string | null }> = [];

      if ((wafBlocked || unreachableOrigins.size > 0) && nucleiTargets.length === 0) {
        smartLogLines.push("[nuclei] skipped (all candidate origins appear WAF-blocked)");
        combined = {
          ok: true,
          exec: { kind: "docker", image: process.env.ASV_NUCLEI_IMAGE?.trim() || "projectdiscovery/nuclei:latest", args: [] },
          matched: 0,
          linesCaptured: 0,
          stdoutCaptured: "",
          stderrCaptured: "skipped (blocked/unreachable)",
          jsonlCaptured: ""
        };
      } else if (smartMonster) {
        const liteTags = [
          "misconfiguration",
          "misconfig",
          "exposed-panels",
          "panel",
          "technologies",
          "tech",
          "exposure",
          "default-login",
          "osint",
          "takeovers"
        ];

        const liteResolved: ResolvedScanConfig = {
          ...resolved,
          nuclei: {
            ...resolved.nuclei,
            tags: liteTags,
            severity: ["critical", "high", "medium", "low", "info"],
            maxMs: Math.min(resolved.nuclei.maxMs ?? 600_000, 240_000)
          }
        };

        const lite = await runWithTimeout("lite", liteResolved, nucleiTargets);
        phases.push({ label: lite.label, ok: lite.nr.ok, matched: lite.nr.matched, maxMs: lite.maxNucleiMs, error: lite.nr.error ?? null });

        const heavyShouldRun = !wafBlocked && techHintList.length > 0 && nucleiTargets.length > 0;
        if (heavyShouldRun) {
          const status2 = await this.db
            .query<{ status: string }>(`SELECT status FROM asv_scan_run WHERE id = $1`, [asset.scan_run_id])
            .then((r) => r.rows[0]?.status ?? "running")
            .catch(() => "running");
          if (status2 === "cancelled") {
            smartLogLines.push("[nuclei] heavy skipped (cancelled)");
            combined = lite.nr;
          } else {
          const heavyResolved: ResolvedScanConfig = {
            ...resolved,
            nuclei: {
              ...resolved.nuclei,
              tags: ["cve", "vuln"],
              severity: ["critical", "high"],
              maxMs: Math.max(resolved.nuclei.maxMs ?? 600_000, 900_000)
            }
          };
          const heavy = await runWithTimeout("heavy", heavyResolved, nucleiTargets);
          phases.push({ label: heavy.label, ok: heavy.nr.ok, matched: heavy.nr.matched, maxMs: heavy.maxNucleiMs, error: heavy.nr.error ?? null });

          combined = {
            ok: lite.nr.ok && heavy.nr.ok,
            exec: heavy.nr.exec,
            matched: lite.nr.matched + heavy.nr.matched,
            linesCaptured: lite.nr.linesCaptured + heavy.nr.linesCaptured,
            stdoutCaptured: [lite.nr.stdoutCaptured, heavy.nr.stdoutCaptured].filter(Boolean).join("\n"),
            stderrCaptured: [`[nuclei] phase=lite`, lite.nr.stderrCaptured, `[nuclei] phase=heavy`, heavy.nr.stderrCaptured].filter(Boolean).join("\n"),
            jsonlCaptured: [lite.nr.jsonlCaptured, heavy.nr.jsonlCaptured].filter(Boolean).join("\n"),
            error: heavy.nr.error ?? lite.nr.error
          };
          }
        } else {
          smartLogLines.push("[nuclei] heavy skipped (no tech hints)");
          combined = lite.nr;
        }
      } else {
        const single = await runWithTimeout("single", resolved, nucleiTargets);
        phases.push({ label: single.label, ok: single.nr.ok, matched: single.nr.matched, maxMs: single.maxNucleiMs, error: single.nr.error ?? null });
        combined = single.nr;
      }

      const nr = combined!;
      smartLogLines.push(
        `[nuclei] phases=${phases.map((p) => `${p.label}{ok=${p.ok},matched=${p.matched},maxMs=${p.maxMs}${p.error ? ",err" : ""}}`).join(" ")}`
      );
      nucleiStats = {
        ...nuclei,
        run: {
          ok: nr.ok,
          matched: nr.matched,
          error: nr.error ?? null,
          exec: nr.exec,
          linesCaptured: nr.linesCaptured,
          templatesHostDir: nucleiTemplatesHostDir(),
          smartMonster
        }
      };
      await this.writeScanArtifact(asset.scan_run_id, "nuclei.stdout", nr.stdoutCaptured || "");
      await this.writeScanArtifact(asset.scan_run_id, "nuclei.stderr", `${nucleiTemplateLog}${smartLogLines.join("\n")}\n${nr.stderrCaptured || ""}`);
      await this.writeScanArtifact(asset.scan_run_id, "nuclei.jsonl", nr.jsonlCaptured || "");
      }
    }

    await this.writeScanArtifact(asset.scan_run_id, "scanner.log", [
      `[asv] scan_mode=${resolved.mode}`,
      `[asv] targets=${targets.length} ports=${portsToCheck.length}`,
      `[asv] nuclei.enabled=${nuclei.enabled} planned=${nuclei.planned}${nuclei.reason ? ` reason=${nuclei.reason}` : ""}`,
      `[asv] nuclei.targets=${nuclei.enabled ? "computed" : "n/a"}`
    ].join("\n"));

    const elapsedMs = Date.now() - startedAt;
    return {
      stats: {
        targets: targets.length,
        portsChecked: targets.length * portsToCheck.length,
        portsOpen: portOpen,
        httpObservations: httpObs,
        httpAggressive: httpAggressive,
        findings: findings,
        mode: resolved.mode,
        profile: { name: resolved.profileName, id: requestedProfileId ?? null },
        concurrency: { ports: resolved.maxPortConcurrency, http: resolved.maxHttpConcurrency },
        nuclei: nucleiStats,
        elapsedMs
      }
    };
  }

  private severityRank(sev: string): number {
    const s = (sev ?? "info").toString().toLowerCase();
    if (s === "critical") return 5;
    if (s === "high") return 4;
    if (s === "medium") return 3;
    if (s === "low") return 2;
    return 1; // info/unknown
  }

  private pickWorstSeverity(a: string, b: string): string {
    return this.severityRank(a) >= this.severityRank(b) ? a : b;
  }

  private extractEndpointKey(f: AsvFindingRow): string | null {
    const aff = f.affected;
    if (!aff || typeof aff !== "object") return null;
    const o = aff as Record<string, unknown>;
    const url = typeof o.url === "string" ? o.url : null;
    const matchedAt = typeof o.matchedAt === "string" ? o.matchedAt : null;
    const raw = url || matchedAt;
    if (!raw) return null;
    try {
      const u = new URL(raw);
      // Normalize: scheme://host:port/path (no query/fragment)
      return `${u.protocol}//${u.host}${u.pathname || "/"}`;
    } catch {
      return raw.slice(0, 300);
    }
  }

  private buildFixGuidance(f: AsvFindingRow): Record<string, unknown> {
    const tool = (f.tool ?? "unknown").toString();
    const ext = (f.external_id ?? "").toString();
    const title = (f.title ?? "").toString();
    const endpoint = this.extractEndpointKey(f);

    // Baseline guidance for HTTP surface observations (not a vuln, but useful hardening).
    if (tool === "http-probe") {
      return {
        kind: "surface",
        summary: "Endpoint discovered during scan.",
        fix: "Review exposure (auth, WAF, rate limiting) and ensure only intended endpoints are public.",
        verify: "Re-run scan; ensure only expected endpoints remain reachable.",
        endpoint
      };
    }

    // Nuclei templates: keep generic but actionable (avoid hallucinating).
    if (tool === "nuclei" && ext) {
      return {
        kind: "nuclei",
        summary: "Template match requires validation and remediation.",
        fix: "Validate finding on the exact endpoint, then apply vendor remediation or configuration hardening; update affected component if applicable.",
        verify: "Re-run scan after fix and confirm the template no longer matches.",
        templateId: ext,
        endpoint
      };
    }

    // Simple heuristics for common web hardening findings (title-based).
    const t = title.toLowerCase();
    if (t.includes("missing") && (t.includes("header") || t.includes("headers"))) {
      return {
        kind: "hardening",
        summary: "Security headers missing.",
        fix: "Add recommended security headers (CSP, HSTS, X-Content-Type-Options, Referrer-Policy) at the edge or app layer.",
        verify: "Check response headers and confirm they are present on all relevant routes.",
        endpoint
      };
    }

    return {
      kind: "generic",
      summary: "Review evidence and remediate the underlying root cause.",
      fix: "Apply vendor patches / configuration changes; consider compensating controls if patching is not immediate.",
      verify: "Re-run scan and/or perform a manual check to confirm remediation.",
      endpoint
    };
  }

  private async upsertIssuesForRun(assetId: string, scanRunId: string) {
    const r = await this.db.query<AsvFindingRow>(
      `SELECT fingerprint, title, severity, confidence, tool, external_id, affected, evidence
         FROM asv_finding
        WHERE scan_run_id = $1 AND asset_id = $2`,
      [scanRunId, assetId]
    );

    for (const f of r.rows) {
      const issueKey = f.fingerprint;
      const endpointKey = this.extractEndpointKey(f);
      const fixGuidance = this.buildFixGuidance(f);

      // Upsert: keep earliest first_seen, update last_seen + severity (worst), increment occurrences.
      await this.db.query(
        `INSERT INTO asv_issue (asset_id, issue_key, title, tool, external_id, endpoint_key, severity, confidence, status, first_seen, last_seen, last_scan_run_id, occurrences, fix_guidance)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'open',now(),now(),$9,1,$10::jsonb)
         ON CONFLICT (asset_id, issue_key)
         DO UPDATE SET
           title = EXCLUDED.title,
           tool = EXCLUDED.tool,
           external_id = EXCLUDED.external_id,
           endpoint_key = COALESCE(EXCLUDED.endpoint_key, asv_issue.endpoint_key),
           severity = CASE
                      WHEN asv_issue.severity = 'critical' OR EXCLUDED.severity = 'critical' THEN 'critical'
                      WHEN asv_issue.severity = 'high' OR EXCLUDED.severity = 'high' THEN 'high'
                      WHEN asv_issue.severity = 'medium' OR EXCLUDED.severity = 'medium' THEN 'medium'
                      WHEN asv_issue.severity = 'low' OR EXCLUDED.severity = 'low' THEN 'low'
                      ELSE 'info'
                    END,
           confidence = EXCLUDED.confidence,
           status = CASE WHEN asv_issue.status = 'resolved' THEN 'open' ELSE asv_issue.status END,
           last_seen = now(),
           last_scan_run_id = EXCLUDED.last_scan_run_id,
           occurrences = asv_issue.occurrences + 1,
           fix_guidance = CASE WHEN asv_issue.fix_guidance = '{}'::jsonb THEN EXCLUDED.fix_guidance ELSE asv_issue.fix_guidance END,
           updated_at = now()`,
        [
          assetId,
          issueKey,
          f.title,
          f.tool,
          f.external_id ?? null,
          endpointKey,
          (f.severity ?? "info").toString().toLowerCase(),
          (f.confidence ?? "medium").toString().toLowerCase(),
          scanRunId,
          JSON.stringify(fixGuidance)
        ]
      );
    }
  }

  private resolveNucleiReadiness(asset: AssetRow, resolved: ResolvedScanConfig): NucleiReadiness {
    const policy = asset.scope_policy ?? {};
    const allow = Boolean((policy as any).allowStandard === true);
    // Enabled by default; set ASV_NUCLEI_ENABLED=0 to force-disable.
    const enabledByEnv = process.env.ASV_NUCLEI_ENABLED !== "0";
    const enabledInProfile = Boolean(resolved.nuclei?.enabled);
    const requested = enabledByEnv && enabledInProfile;
    if (!requested) {
      return { enabled: false, planned: true, reason: "disabled (profile/env)" };
    }
    if (resolved.mode === "standard" && !allow) {
      return { enabled: false, planned: true, reason: "standard requires allowlist" };
    }
    // Runner presence check is done at execution time (bin/docker). Here we mark enabled.
    return { enabled: true, planned: false };
  }

  private async writeScanArtifact(scanRunId: string, kind: "scanner.log" | "nuclei.jsonl" | "nuclei.stdout" | "nuclei.stderr", content: string) {
    const max = 2_000_000; // 2MB cap for inline storage
    const truncated = content.length > max ? `${content.slice(0, max)}\n\n[truncated]\n` : content;
    const bytes = Buffer.byteLength(truncated, "utf8");
    const sha256 = createHash("sha256").update(truncated).digest("hex");
    await this.db.query(
      `INSERT INTO asv_scan_artifact (scan_run_id, kind, bytes, sha256, storage, content_text)
       VALUES ($1,$2,$3,$4,'inline',$5)`,
      [scanRunId, kind, bytes, sha256, truncated]
    );
  }

  private nucleiBin(): string | null {
    const b = process.env.ASV_NUCLEI_BIN?.trim();
    if (b) return b;
    return "nuclei";
  }

  /**
   * Community templates on a persistent host path (required for Docker: each `docker run` is a fresh FS).
   * Runs outside the per-scan timeout so the first download is not killed by ASV_NUCLEI_MAX_MS.
   */
  private async bootstrapNucleiTemplates(): Promise<string> {
    const useDocker = process.env.ASV_NUCLEI_RUNNER?.trim().toLowerCase() === "docker";
    const image = process.env.ASV_NUCLEI_IMAGE?.trim() || "projectdiscovery/nuclei:latest";
    const bin = this.nucleiBin() ?? "nuclei";
    const templatesHostDir = nucleiTemplatesHostDir();
    const containerTemplates =
      process.env.ASV_NUCLEI_TEMPLATES_CONTAINER_PATH?.trim() || "/root/nuclei-templates";
    await fs.mkdir(templatesHostDir, { recursive: true });

    let templateBootstrap = `[nuclei] templatesHostDir=${templatesHostDir}\n`;
    const needsTpl = await nucleiTemplatesNeedBootstrap(
      templatesHostDir,
      process.env.ASV_NUCLEI_FORCE_UPDATE === "1"
    );
    if (needsTpl) {
      const up = await ensureNucleiCommunityTemplates({
        useDocker,
        image,
        bin,
        hostDir: templatesHostDir,
        containerDir: containerTemplates
      });
      templateBootstrap += `[nuclei] nuclei-templates update exit=${up.exitCode}\n${up.log.slice(0, 200_000)}\n`;
      if (up.exitCode === 0) {
        await fs
          .writeFile(path.join(templatesHostDir, NUCLEI_TEMPLATES_READY), new Date().toISOString(), "utf8")
          .catch(() => {});
      }
    } else {
      templateBootstrap += `[nuclei] template cache OK (marker present)\n`;
    }
    return templateBootstrap;
  }

  private async runNuclei(
    asset: AssetRow,
    resolved: ResolvedScanConfig,
    targets: string[],
    opts?: { _didRetryProxy?: boolean }
  ): Promise<NucleiRunResult> {
    const cfg = resolved.nuclei;
    const bin = this.nucleiBin();
    if (!bin) {
      return {
        ok: false,
        exec: { kind: "bin", bin: "nuclei", args: [] },
        matched: 0,
        linesCaptured: 0,
        stdoutCaptured: "",
        stderrCaptured: "",
        jsonlCaptured: "",
        error: "nuclei bin not configured"
      };
    }
    if (!targets.length) {
      return {
        ok: false,
        exec: { kind: "bin", bin, args: [] },
        matched: 0,
        linesCaptured: 0,
        stdoutCaptured: "",
        stderrCaptured: "",
        jsonlCaptured: "",
        error: "no targets for nuclei"
      };
    }

    const useDocker = process.env.ASV_NUCLEI_RUNNER?.trim().toLowerCase() === "docker";
    const image = process.env.ASV_NUCLEI_IMAGE?.trim() || "projectdiscovery/nuclei:latest";
    const templatesHostDir = nucleiTemplatesHostDir();
    const containerTemplates =
      process.env.ASV_NUCLEI_TEMPLATES_CONTAINER_PATH?.trim() || "/root/nuclei-templates";
    await fs.mkdir(templatesHostDir, { recursive: true });

    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "vip-asv-nuclei-"));
    const listPath = path.join(dir, "targets.txt");
    await fs.writeFile(listPath, targets.join("\n") + "\n", "utf8");

    const tags = cfg.tags.map(String).filter(Boolean).slice(0, 64);
    const sev = cfg.severity.map(String).filter(Boolean).slice(0, 16);
    const rateLimitPerMin = cfg.rateLimitPerMin;
    const rps = Math.max(1, Math.min(200, Math.ceil(rateLimitPerMin / 60)));
    const timeoutSec = Math.max(1, Math.min(20, Math.ceil(resolved.httpTimeoutMs / 1000)));

    const extraArgs0 = process.env.ASV_NUCLEI_EXTRA_ARGS?.trim()
      ? process.env.ASV_NUCLEI_EXTRA_ARGS.trim().split(/\s+/).filter(Boolean).slice(0, 64)
      : [];
    // Defensive: prevent misconfigured proxy flags from killing nuclei.
    const extraArgs: string[] = [];
    for (let i = 0; i < extraArgs0.length; i++) {
      const a = extraArgs0[i]!;
      const low = a.toLowerCase();
      if (low === "-proxy" || low.startsWith("-proxy=") || low === "-proxy-url" || low.startsWith("-proxy-url=")) {
        // drop flag and its value (if any)
        if ((low === "-proxy" || low === "-proxy-url") && extraArgs0[i + 1] && !extraArgs0[i + 1]!.startsWith("-")) i++;
        continue;
      }
      extraArgs.push(a);
      if (extraArgs.length >= 32) break;
    }

    const baseArgs: string[] = [
      "-duc",
      "-nc",
      "-ni",
      ...(useDocker ? ["-templates", containerTemplates] : ["-templates", templatesHostDir]),
      ...extraArgs,
      "-jsonl",
      "-l",
      listPath,
      "-rl",
      String(rps),
      "-c",
      String(Math.max(1, Math.min(50, resolved.maxHttpConcurrency))),
      "-retries",
      "1",
      "-timeout",
      String(timeoutSec)
    ];

    const args = baseArgs.slice();
    const tplList = cfg.templates.map(String).filter(Boolean).slice(0, 64);
    if (tplList.length) args.push("-t", tplList.join(","));
    if (tags.length) args.push("-tags", tags.join(","));
    const excludeTags = cfg.excludeTags.map(String).filter(Boolean).slice(0, 64);
    if (excludeTags.length) args.push("-etags", excludeTags.join(","));
    if (sev.length) args.push("-severity", sev.join(","));

    // If targets look like host:port (network scan), restrict templates to network protocols.
    if (targets.some((t) => /:\d{1,5}$/.test(t) && !t.includes("://"))) {
      args.push("-pt", "tcp,ssl");
    }

    const stdoutChunks: string[] = [];
    const stderrChunks: string[] = [];
    const jsonlLines: string[] = [];
    let matched = 0;
    let lines = 0;

    const hardMs = Number(resolved.nuclei.maxMs ?? process.env.ASV_NUCLEI_MAX_MS ?? 600_000);
    const containerName = useDocker ? `vip-asv-nuclei-${asset.scan_run_id.slice(0, 8)}-${randomUUID().slice(0, 8)}` : null;

    const allowProxy = process.env.ASV_NUCLEI_ALLOW_PROXY === "1";
    const proxyKeys = [
      "HTTP_PROXY",
      "HTTPS_PROXY",
      "ALL_PROXY",
      "NO_PROXY",
      "http_proxy",
      "https_proxy",
      "all_proxy",
      "no_proxy",
      "SOCKS_PROXY",
      "SOCKS5_PROXY",
      "socks_proxy",
      "socks5_proxy"
    ];

    let child: ReturnType<typeof spawn>;
    try {
      if (useDocker) {
        // On macOS Docker doesn't support --network host the same way Linux does; default bridge is fine for outbound scans.
        const dockerArgs: string[] = [
          "run",
          "--rm",
          "--name",
          containerName!,
          "--label",
          `vip.asv.scan_run_id=${asset.scan_run_id}`,
          "-i",
          "-v",
          `${templatesHostDir}:${containerTemplates}`,
          "-v",
          `${dir}:/work`
        ];
        // DO NOT pass proxy env vars by default.
        // Passing empty proxy vars makes nuclei treat them as configured and can crash with "invalid proxy format".
        if (process.platform !== "darwin") dockerArgs.push("--network", "host");
        dockerArgs.push(image, ...args.map((a) => (a === listPath ? "/work/targets.txt" : a)));
        child = spawn("docker", dockerArgs, { stdio: ["ignore", "pipe", "pipe"] });
      } else {
        const env = { ...process.env } as Record<string, string | undefined>;
        if (!allowProxy) for (const k of proxyKeys) delete env[k];
        child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"], env });
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        ok: false,
        exec: useDocker ? { kind: "docker", image, args } : { kind: "bin", bin, args },
        matched: 0,
        linesCaptured: 0,
        stdoutCaptured: "",
        stderrCaptured: msg,
        jsonlCaptured: "",
        error: msg
      };
    }

    // Ensure we don't leave long-running docker containers behind on timeout.
    const timeout = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        // ignore
      }
      if (useDocker && containerName) {
        try {
          spawn("docker", ["rm", "-f", containerName], { stdio: ["ignore", "ignore", "ignore"] });
        } catch {
          // ignore
        }
      }
    }, Math.max(5_000, Math.min(3_600_000, hardMs)));

    child.stderr?.on("data", (d) => {
      const s = d.toString("utf8");
      if (stderrChunks.join("").length < 1_000_000) stderrChunks.push(s);
    });
    child.stdout?.on("data", (d) => {
      const s = d.toString("utf8");
      if (stdoutChunks.join("").length < 1_000_000) stdoutChunks.push(s);
    });

    const rl = readline.createInterface({ input: child.stdout ?? process.stdin });
    rl.on("line", (line) => {
      lines++;
      if (jsonlLines.length < 20_000) jsonlLines.push(line);
    });

    const exitCode: number = await new Promise((resolve) => {
      child.on("error", (err) => {
        const msg = err instanceof Error ? err.message : String(err);
        stderrChunks.push(msg);
        resolve(1);
      });
      child.on("exit", (code) => resolve(code ?? 1));
    });
    clearTimeout(timeout);
    rl.close();

    // Parse captured JSONL into findings (limited).
    const toUpsertTemplates: Array<{ templateId: string; name?: string; severity?: string; tags?: string[]; description?: string; reference?: string[] }> =
      [];

    for (const line of jsonlLines) {
      let obj: any;
      try {
        obj = JSON.parse(line);
      } catch {
        continue;
      }
      const templateId = typeof obj["template-id"] === "string" ? obj["template-id"] : typeof obj["templateID"] === "string" ? obj["templateID"] : "";
      const matchedAt = typeof obj["matched-at"] === "string" ? obj["matched-at"] : typeof obj["matchedAt"] === "string" ? obj["matchedAt"] : "";
      if (!templateId || !matchedAt) continue;
      matched++;

      const info = obj.info && typeof obj.info === "object" ? obj.info : {};
      const sev0 = typeof info.severity === "string" ? info.severity : "info";
      const name = typeof info.name === "string" ? info.name : templateId;
      const tags0 = Array.isArray(info.tags) ? info.tags.map(String).slice(0, 32) : [];
      const ref0 = Array.isArray(info.reference) ? info.reference.map(String).slice(0, 16) : [];
      const desc0 = typeof info.description === "string" ? info.description : undefined;

      toUpsertTemplates.push({ templateId, name, severity: sev0, tags: tags0, description: desc0, reference: ref0 });

      const matcher = typeof obj["matcher-name"] === "string" ? obj["matcher-name"] : undefined;
      const extracted = Array.isArray(obj["extracted-results"]) ? obj["extracted-results"].slice(0, 10) : undefined;
      const host = typeof obj.host === "string" ? obj.host : undefined;
      const ip = typeof obj.ip === "string" ? obj.ip : undefined;

      // Fingerprint must be stable across re-runs, but differentiate multiple distinct matches.
      // Use template + matched target + matcher + a small extracted slice.
      const fp = await sha256Hex(
        stableJsonStringify({
          kind: "nuclei",
          templateId,
          matchedAt,
          host,
          ip,
          matcher: matcher ?? null,
          extracted: extracted ?? null
        })
      );
      const fingerprint = `nuclei:${fp.slice(0, 24)}`;

      const cveIds = pickNucleiCveIds(obj);
      let cveRows: Array<{
        cve_id: string;
        published_at: string | null;
        modified_at: string | null;
        cvss_base: number | null;
        raw: any;
        epss_score: number | null;
        epss_percentile: number | null;
        epss_scored_at: string | null;
        kev_date_added: string | null;
        kev_required_action: string | null;
      }> = [];
      if (cveIds.length) {
        try {
          const r = await this.db.query<{
            cve_id: string;
            published_at: string | null;
            modified_at: string | null;
            cvss_base: number | null;
            raw: any;
            epss_score: number | null;
            epss_percentile: number | null;
            epss_scored_at: string | null;
            kev_date_added: string | null;
            kev_required_action: string | null;
          }>(
            `SELECT c.cve_id,
                    c.published_at::text,
                    c.modified_at::text,
                    c.cvss_base,
                    c.raw,
                    e.score AS epss_score,
                    e.percentile AS epss_percentile,
                    e.scored_at::text AS epss_scored_at,
                    k.date_added::text AS kev_date_added,
                    k.required_action AS kev_required_action
               FROM cve c
          LEFT JOIN epss_score e ON e.cve_id = c.cve_id
          LEFT JOIN kev k ON k.cve_id = c.cve_id
              WHERE c.cve_id = ANY($1::text[])`,
            [cveIds]
          );
          cveRows = r.rows;
        } catch {
          cveRows = [];
        }
      }

      const cveIntel = cveRows.map((r) => {
        const rawObj = r.raw && typeof r.raw === "object" ? r.raw : null;
        let description: string | null = null;
        try {
          // NVD-ish JSON: CVE_Items[0].cve.description.description_data[0].value
          const items = rawObj && Array.isArray((rawObj as any).CVE_Items) ? (rawObj as any).CVE_Items : null;
          const c0 = items && items[0] && typeof items[0] === "object" ? items[0] : null;
          const descData = c0?.cve?.description?.description_data;
          if (Array.isArray(descData) && descData[0] && typeof descData[0].value === "string") description = String(descData[0].value);
        } catch {
          description = null;
        }
        const fromCvss = cvssBaseToSeverity(r.cvss_base);
        return {
          cve_id: r.cve_id,
          published_at: r.published_at,
          modified_at: r.modified_at,
          cvss_base: r.cvss_base,
          severity_hint: fromCvss,
          description,
          epss: r.epss_score != null ? { score: r.epss_score, percentile: r.epss_percentile, scored_at: r.epss_scored_at } : null,
          kev: r.kev_date_added
            ? { date_added: r.kev_date_added, required_action: r.kev_required_action ?? null }
            : null
        };
      });

      let severity = sev0;
      for (const c of cveIntel) {
        const hint = c.severity_hint;
        if (hint) severity = pickWorstSeverity(severity, hint);
        if (c.kev) severity = pickWorstSeverity(severity, "critical");
      }

      const title =
        cveIds.length > 0
          ? `Nuclei: ${name} [${cveIds.slice(0, 3).join(", ")}${cveIds.length > 3 ? ` +${cveIds.length - 3}` : ""}]`
          : `Nuclei: ${name}`;

      const hasKev = cveIntel.some((c) => Boolean(c.kev));
      const confidence = hasKev || cveIntel.length ? "high" : "medium";

      const evidence = [
        {
          kind: "nuclei",
          templateId,
          matchedAt,
          host,
          ip,
          timestamp: typeof obj.timestamp === "string" ? obj.timestamp : undefined,
          matcher,
          extracted
        },
        {
          kind: "enrichment",
          source: "local_cve_db",
          cveIds,
          missingInLocalDb: cveIds.filter((id) => !cveIntel.some((m) => m.cve_id === id)),
          matches: cveIntel
        }
      ];

      await this.db.query(
        `INSERT INTO asv_finding (asset_id, scan_run_id, fingerprint, title, severity, confidence, tool, external_id, affected, evidence, status, first_seen, last_seen)
         VALUES ($1,$2,$3,$4,$5,$6,'nuclei',$7,$8,$9,'open',now(),now())
         ON CONFLICT (asset_id, fingerprint)
         DO UPDATE SET
           title = EXCLUDED.title,
           severity = EXCLUDED.severity,
           confidence = EXCLUDED.confidence,
           external_id = EXCLUDED.external_id,
           affected = EXCLUDED.affected,
           evidence = EXCLUDED.evidence,
           last_seen = now(),
           updated_at = now(),
           scan_run_id = EXCLUDED.scan_run_id`,
        [
          asset.asset_id,
          asset.scan_run_id,
          fingerprint,
          title,
          severity,
          confidence,
          templateId,
          JSON.stringify({ matchedAt, url: matchedAt }),
          JSON.stringify(evidence)
        ]
      );
    }

    // Upsert template metadata (best effort, dedup by template_id).
    const seen = new Set<string>();
    for (const t of toUpsertTemplates) {
      if (!t.templateId || seen.has(t.templateId)) continue;
      seen.add(t.templateId);
      await this.db.query(
        `INSERT INTO asv_nuclei_template (template_id, name, severity, tags, description, reference, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,now())
         ON CONFLICT (template_id)
         DO UPDATE SET name = COALESCE(EXCLUDED.name, asv_nuclei_template.name),
                       severity = COALESCE(EXCLUDED.severity, asv_nuclei_template.severity),
                       tags = COALESCE(EXCLUDED.tags, asv_nuclei_template.tags),
                       description = COALESCE(EXCLUDED.description, asv_nuclei_template.description),
                       reference = COALESCE(EXCLUDED.reference, asv_nuclei_template.reference),
                       updated_at = now()`,
        [t.templateId, t.name ?? null, t.severity ?? null, t.tags ?? null, t.description ?? null, t.reference ?? null]
      );
    }

    const stdoutCaptured = stdoutChunks.join("");
    const stderrCaptured = stderrChunks.join("");
    const jsonlCaptured = jsonlLines.join("\n");

    await fs.rm(dir, { recursive: true, force: true });

    const fatal = /\[FTL\]/.test(stderrCaptured) || /Program exiting/.test(stderrCaptured);
    const proxyFatal =
      /invalid proxy format/i.test(stderrCaptured) ||
      /all proxies are dead/i.test(stderrCaptured);
    const ok = exitCode === 0 && !fatal;

    // One retry: if we hit proxy-related fatal (often due to inherited env/args), retry with proxy stripped.
    if (!ok && proxyFatal && !opts?._didRetryProxy) {
      const msg = stderrCaptured.slice(0, 2000);
      const retry = await this.runNuclei(asset, resolved, targets, {
        ...opts,
        _didRetryProxy: true
      });
      if (retry.ok) {
        retry.stderrCaptured = `[retry] previous proxy error:\n${msg}\n\n${retry.stderrCaptured || ""}`.slice(0, 1_000_000);
        return retry;
      }
    }
    return {
      ok,
      exec: useDocker ? { kind: "docker", image, args } : { kind: "bin", bin, args },
      matched,
      linesCaptured: lines,
      stdoutCaptured,
      stderrCaptured,
      jsonlCaptured,
      error: ok ? undefined : stderrCaptured.slice(0, 4000) || `exit_code=${exitCode}`
    };
  }

  private async resolveConfig(
    asset: AssetRow,
    requestedMode: "safe" | "standard",
    requestedProfileId: string | null
  ): Promise<ResolvedScanConfig> {
    const allowStandard =
      requestedMode === "standard" && Boolean(asset.scope_policy && asset.scope_policy.allowStandard === true);
    let profile: ScanProfileRow | null = null;
    if (requestedProfileId) {
      try {
        const r = await this.db.query<ScanProfileRow>(
          `SELECT id, name, mode, config FROM asv_scan_profile WHERE id = $1`,
          [requestedProfileId]
        );
        profile = r.rows[0] ?? null;
      } catch {
        profile = null;
      }
    }
    const mode: "safe" | "standard" = profile?.mode === "standard" && allowStandard ? "standard" : "safe";
    const cfg = (profile?.config && typeof profile.config === "object" ? profile.config : {}) as Record<string, unknown>;

    const portsDefault =
      mode === "standard"
        ? [
            21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 993, 995, 1433, 1521,
            2049, 2375, 27017, 3000, 3306, 3389, 4000, 5000, 5432, 5601, 5900, 6379, 8000, 8080, 8443, 9000, 9200,
            9300, 11211
          ]
        : [80, 443, 8080, 8443, 22, 3389, 445];

    const httpPathsDefault =
      mode === "standard" ? ["/", "/robots.txt", "/.well-known/security.txt", "/sitemap.xml", "/favicon.ico"] : ["/"];

    const ports = Array.isArray(cfg.ports) ? (cfg.ports as unknown[]) : portsDefault;
    const httpPaths = Array.isArray(cfg.httpPaths) ? (cfg.httpPaths as unknown[]) : httpPathsDefault;

    const normPorts = ports
      .map((p) => Number(p))
      .filter((p) => Number.isFinite(p) && p > 0 && p <= 65535)
      .map((p) => Math.floor(p));
    const uniqPorts = [...new Set(normPorts)].slice(0, 256);

    const normPaths = httpPaths
      .map((p) => String(p))
      .map((p) => (p.startsWith("/") ? p : `/${p}`))
      .slice(0, 16);

    const tcpTimeoutMs = Math.max(200, Math.min(10_000, Math.floor(Number(cfg.tcpTimeoutMs ?? (mode === "standard" ? 800 : 800)))));
    const httpTimeoutMs = Math.max(400, Math.min(15_000, Math.floor(Number(cfg.httpTimeoutMs ?? (mode === "standard" ? 2200 : 2500)))));
    const maxPortConcurrency = Math.max(1, Math.min(256, Math.floor(Number(cfg.maxPortConcurrency ?? (mode === "standard" ? 64 : 24)))));
    const maxHttpConcurrency = Math.max(1, Math.min(64, Math.floor(Number(cfg.maxHttpConcurrency ?? (mode === "standard" ? 16 : 8)))));

    const profileName = profile?.name ?? mode;

    return {
      mode,
      profileName,
      ports: uniqPorts.length ? uniqPorts : portsDefault,
      httpPaths: normPaths.length ? normPaths : httpPathsDefault,
      tcpTimeoutMs,
      httpTimeoutMs,
      maxPortConcurrency,
      maxHttpConcurrency,
      nuclei: mergeNucleiConfig(mode, cfg.nuclei)
    };
  }

  private async expandTargets(asset: AssetRow): Promise<Array<{ target: string; ip?: string }>> {
    if (asset.asset_type === "domain") {
      try {
        const ips = await dns.resolve4(asset.key_norm);
        const uniq = [...new Set(ips)];
        return uniq.length ? uniq.map((ip) => ({ target: asset.key_norm, ip })) : [{ target: asset.key_norm }];
      } catch {
        return [{ target: asset.key_norm }];
      }
    }
    if (asset.asset_type === "url") {
      try {
        const u = new URL(asset.key_norm);
        const host = u.hostname;
        // Keep host target; do not expand further (safe default).
        return [{ target: host }];
      } catch {
        return [{ target: asset.key_norm }];
      }
    }
    if (asset.asset_type === "cidr") {
      const allow = Boolean(asset.scope_policy && asset.scope_policy.allowStandard === true);
      if (!allow) return [{ target: asset.key_norm }];
      const maxFromPolicy = Number((asset.scope_policy?.maxHosts ?? undefined) as unknown);
      const maxHosts = Number.isFinite(maxFromPolicy) && maxFromPolicy > 0 ? Math.floor(maxFromPolicy) : 64;
      const hardCap = 256;
      const limit = Math.max(1, Math.min(hardCap, maxHosts));
      return this.expandIpv4Cidr(asset.key_norm, limit).map((ip) => ({ target: ip, ip }));
    }
    // ip
    return [{ target: asset.key_norm, ip: asset.key_norm }];
  }

  private expandIpv4Cidr(cidr: string, limit: number): string[] {
    const m = cidr.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
    if (!m) return [];
    const base = m[1];
    if (!base) return [];
    const prefix = Number(m[2]);
    if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) return [];
    const parts = base.split(".").map((x) => Number(x));
    if (
      parts.length !== 4 ||
      parts[0] == null ||
      parts[1] == null ||
      parts[2] == null ||
      parts[3] == null ||
      parts.some((x) => !Number.isFinite(x) || x < 0 || x > 255)
    )
      return [];
    const ipInt = (((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0);
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const network = (ipInt & mask) >>> 0;
    const size = prefix === 32 ? 1 : 2 ** (32 - prefix);
    const start = prefix <= 30 ? network + 1 : network; // skip network for typical ipv4
    const end = prefix <= 30 ? network + size - 2 : network + size - 1; // skip broadcast
    const out: string[] = [];
    for (let cur = start; cur <= end && out.length < limit; cur++) {
      out.push(
        `${(cur >>> 24) & 255}.${(cur >>> 16) & 255}.${(cur >>> 8) & 255}.${cur & 255}`
      );
    }
    return out;
  }

  private checkTcpPort(
    host: string,
    port: number,
    timeoutMs: number
  ): Promise<{ state: "open" | "closed" | "filtered" | "unknown"; latencyMs: number | null; error?: string }> {
    const started = Date.now();
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let done = false;

      const finish = (state: "open" | "closed" | "filtered" | "unknown", error?: string) => {
        if (done) return;
        done = true;
        const ms = Date.now() - started;
        try {
          socket.destroy();
        } catch {
          // ignore
        }
        resolve({ state, latencyMs: ms, error });
      };

      socket.setTimeout(timeoutMs);
      socket.once("connect", () => finish("open"));
      socket.once("timeout", () => finish("filtered", "timeout"));
      socket.once("error", (e) => finish("closed", e instanceof Error ? e.message : String(e)));

      try {
        socket.connect(port, host);
      } catch (e) {
        finish("unknown", e instanceof Error ? e.message : String(e));
      }
    });
  }

  private async fetchHttp(url: string, timeoutMs: number): Promise<{
    finalUrl: string | null;
    status: number | null;
    title: string | null;
    server: string | null;
    headers: Record<string, string>;
    tech: string[];
    latencyMs: number | null;
    error?: string;
  }> {
    const started = Date.now();
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        method: "GET",
        redirect: "follow",
        signal: ac.signal,
        headers: {
          "user-agent":
            "Mozilla/5.0 (compatible; vuln-intel-asv/1.0; +https://local) AppleWebKit/537.36 (KHTML, like Gecko)"
        }
      });
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => {
        headers[k] = v;
      });
      const server = headers["server"] ?? null;
      const ctype = headers["content-type"] ?? "";
      const isHtml = ctype.includes("text/html");
      const body = isHtml ? await res.text().then((x) => x.slice(0, 200_000)) : "";
      const title = isHtml ? (body.match(/<title[^>]*>([^<]{0,180})<\/title>/i)?.[1]?.trim() ?? null) : null;
      const tech: string[] = [];
      if (server) tech.push(server);
      if (headers["x-powered-by"]) tech.push(headers["x-powered-by"]);
      return {
        finalUrl: res.url || null,
        status: res.status,
        title,
        server,
        headers,
        tech: [...new Set(tech)].slice(0, 10),
        latencyMs: Date.now() - started
      };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        finalUrl: null,
        status: null,
        title: null,
        server: null,
        headers: {},
        tech: [],
        latencyMs: Date.now() - started,
        error: msg
      };
    } finally {
      clearTimeout(t);
    }
  }
}


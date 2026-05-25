import {
  BadRequestException,
  Body,
  Controller,
  ForbiddenException,
  Get,
  NotFoundException,
  Param,
  Patch,
  Post,
  Query
} from "@nestjs/common";
import { randomUUID } from "node:crypto";
import { DbService } from "../services/db.service.js";
import { QueueService } from "../services/queue.service.js";
import { sha256Hex, stableJsonStringify } from "@vuln-intel/shared";
import { CurrentUser } from "../auth/current-user.decorator.js";
import type { AuthUser } from "../auth/jwt.strategy.js";

type AssetType = "domain" | "ip" | "cidr" | "url";

function severityRank(sev: string): number {
  const s = String(sev ?? "info").toLowerCase();
  if (s === "critical") return 5;
  if (s === "high") return 4;
  if (s === "medium") return 3;
  if (s === "low") return 2;
  return 1;
}

function normKey(type: AssetType, raw: string): { key: string; display: string } {
  const s = raw.trim();
  if (!s) throw new BadRequestException("key required");
  if (type === "domain") {
    const k = s.toLowerCase().replace(/\.$/, "");
    return { key: k, display: k };
  }
  if (type === "ip") {
    const k = s.trim();
    return { key: k, display: k };
  }
  if (type === "cidr") {
    const k = s.trim();
    return { key: k, display: k };
  }
  // url
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    throw new BadRequestException("invalid url");
  }
  const key = u.toString();
  return { key, display: key };
}

@Controller("asv")
export class AsvController {
  constructor(
    private readonly db: DbService,
    private readonly queue: QueueService
  ) {}

  @Get("assets")
  async listAssets(
    @Query("type") typeRaw?: string,
    @Query("q") qRaw?: string,
    @Query("limit") limitRaw?: string
  ) {
    const limit = Math.max(1, Math.min(200, Number(limitRaw ?? 50)));
    const q = qRaw?.trim().toLowerCase() ?? "";
    const type = (typeRaw?.trim().toLowerCase() ?? "") as AssetType | "";
    const params: any[] = [];
    const where: string[] = [];
    if (type && ["domain", "ip", "cidr", "url"].includes(type)) {
      params.push(type);
      where.push(`asset_type = $${params.length}`);
    }
    if (q) {
      params.push(`%${q}%`);
      where.push(`(lower(key_norm) LIKE $${params.length} OR lower(display_name) LIKE $${params.length})`);
    }
    params.push(limit);
    const sql = `SELECT id, asset_type, key_norm, display_name, scope_policy, created_at, updated_at
                   FROM asv_asset
                  WHERE ${where.length ? where.join(" AND ") : "TRUE"}
               ORDER BY updated_at DESC
                  LIMIT $${params.length}`;
    const r = await this.db.query(sql, params);
    return { items: r.rows };
  }

  @Post("assets")
  async createAsset(@Body() body: { type?: string; key?: string; displayName?: string }) {
    const type = (body.type?.trim().toLowerCase() ?? "") as AssetType;
    if (!["domain", "ip", "cidr", "url"].includes(type)) throw new BadRequestException("invalid type");
    const { key, display } = normKey(type, body.key ?? "");
    const displayName = (body.displayName?.trim() || display).trim();
    // For single URL assets we can safely allow "standard" by default (no CIDR expansion).
    const scopePolicy = type === "url" ? { allowStandard: true } : {};

    const r = await this.db.query(
      `INSERT INTO asv_asset (asset_type, key_norm, display_name, scope_policy)
       VALUES ($1,$2,$3,$4::jsonb)
       ON CONFLICT (asset_type, key_norm)
       DO UPDATE SET display_name = EXCLUDED.display_name,
                     scope_policy = CASE
                                      WHEN asv_asset.scope_policy = '{}'::jsonb THEN EXCLUDED.scope_policy
                                      ELSE asv_asset.scope_policy
                                    END,
                     updated_at = now()
       RETURNING id, asset_type, key_norm, display_name, scope_policy, created_at, updated_at`,
      [type, key, displayName, JSON.stringify(scopePolicy)]
    );
    return r.rows[0];
  }

  @Patch("assets/:id")
  async updateAsset(
    @Param("id") id: string,
    @Body()
    body: {
      displayName?: string;
      scopePolicy?: { allowStandard?: boolean; maxHosts?: number } | null;
    }
  ) {
    const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
    const allowStandard =
      typeof body.scopePolicy?.allowStandard === "boolean" ? body.scopePolicy.allowStandard : undefined;
    const maxHostsRaw = body.scopePolicy?.maxHosts;
    const maxHosts = Number.isFinite(Number(maxHostsRaw)) ? Math.floor(Number(maxHostsRaw)) : undefined;

    const cur = await this.db.query<{ scope_policy: any; display_name: string }>(
      `SELECT scope_policy, display_name FROM asv_asset WHERE id = $1`,
      [id]
    );
    const row = cur.rows[0];
    if (!row) throw new NotFoundException();
    const curPolicy = (row.scope_policy && typeof row.scope_policy === "object" ? row.scope_policy : {}) as Record<
      string,
      unknown
    >;
    let nextPolicy = curPolicy;
    if (allowStandard !== undefined) nextPolicy = { ...nextPolicy, allowStandard: Boolean(allowStandard) };
    if (maxHosts !== undefined) nextPolicy = { ...nextPolicy, maxHosts };

    const nextName = displayName.length > 0 ? displayName : row.display_name;
    const r = await this.db.query(
      `UPDATE asv_asset
          SET display_name = $2,
              scope_policy = $3::jsonb,
              updated_at = now()
        WHERE id = $1
    RETURNING id, asset_type, key_norm, display_name, scope_policy, created_at, updated_at`,
      [id, nextName, JSON.stringify(nextPolicy)]
    );
    return r.rows[0];
  }

  @Get("assets/:id")
  async getAsset(@Param("id") id: string) {
    const r = await this.db.query(
      `SELECT id, asset_type, key_norm, display_name, scope_policy, created_at, updated_at
         FROM asv_asset WHERE id = $1`,
      [id]
    );
    const row = r.rows[0];
    if (!row) throw new NotFoundException();
    return row;
  }

  @Post("scan-runs")
  async createScanRun(
    @Body()
    body: { assetId?: string; profileId?: string | null; mode?: "safe" | "standard" }
  ) {
    if (!body.assetId) throw new BadRequestException("assetId required");
    let mode = body.mode === "standard" ? "standard" : "safe";
    if (body.profileId) {
      const p = await this.db.query<{ mode: "safe" | "standard" }>(
        `SELECT mode FROM asv_scan_profile WHERE id = $1`,
        [body.profileId]
      );
      const pmode = p.rows[0]?.mode;
      if (!pmode) throw new BadRequestException("profileId not found");
      mode = pmode;
    }

    if (mode === "standard") {
      const a = await this.db.query<{ scope_policy: any }>(
        `SELECT scope_policy FROM asv_asset WHERE id = $1`,
        [body.assetId]
      );
      const policy = a.rows[0]?.scope_policy;
      const allow = Boolean(policy && typeof policy === "object" && policy.allowStandard === true);
      if (!allow) throw new ForbiddenException("standard mode allowed only for allowlisted assets");
    }
    const r = await this.db.query(
      `INSERT INTO asv_scan_run (asset_id, profile_id, scan_mode, status)
       VALUES ($1, $2, $3, 'queued')
       RETURNING id, asset_id, profile_id, scan_mode, status, started_at, ended_at, tool_versions, stats, error, created_at, updated_at`,
      [body.assetId, body.profileId ?? null, mode]
    );
    const row = r.rows[0];
    if (!row?.id) throw new Error("Failed to create scan run");
    // Fire-and-forget: a worker (apps/ingest) consumes and performs scan.
    await this.queue.publish("vuln.events", "asv.scan.requested.v1", {
      id: randomUUID(),
      type: "asv.scan.requested.v1",
      ts: new Date().toISOString(),
      producer: { service: "api" },
      idempotencyKey: `asv:scan:${row.id}`,
      payload: { scanRunId: row.id, mode, profileId: row.profile_id ?? null }
    });
    return row;
  }

  @Get("profiles")
  async listProfiles() {
    const r = await this.db.query(
      `SELECT id, name, mode, config, created_at, updated_at
         FROM asv_scan_profile
     ORDER BY CASE WHEN name = 'safe' THEN 0 WHEN name = 'standard' THEN 1 ELSE 2 END, name ASC`
    );
    return { items: r.rows };
  }

  @Patch("profiles/:id")
  async updateProfile(
    @Param("id") id: string,
    @Body()
    body: {
      config?: unknown;
      nuclei?: { enabled?: boolean; tags?: string[]; severity?: string[]; rateLimitPerMin?: number } | null;
    }
  ) {
    const cur = await this.db.query<{ config: any }>(`SELECT config FROM asv_scan_profile WHERE id = $1`, [id]);
    const row = cur.rows[0];
    if (!row) throw new NotFoundException();

    const base =
      row.config && typeof row.config === "object" ? (row.config as Record<string, unknown>) : ({} as Record<string, unknown>);
    let next = base;
    if (body.config && typeof body.config === "object") next = { ...next, ...(body.config as Record<string, unknown>) };
    if (body.nuclei && typeof body.nuclei === "object") {
      const n0 =
        next.nuclei && typeof next.nuclei === "object" ? (next.nuclei as Record<string, unknown>) : ({} as Record<string, unknown>);
      next = { ...next, nuclei: { ...n0, ...(body.nuclei as Record<string, unknown>) } };
    }

    const r = await this.db.query(
      `UPDATE asv_scan_profile
          SET config = $2::jsonb,
              updated_at = now()
        WHERE id = $1
    RETURNING id, name, mode, config, created_at, updated_at`,
      [id, JSON.stringify(next)]
    );
    return r.rows[0];
  }

  @Get("scan-runs")
  async listScanRuns(@Query("assetId") assetId?: string, @Query("limit") limitRaw?: string) {
    const limit = Math.max(1, Math.min(200, Number(limitRaw ?? 50)));
    const params: any[] = [];
    const where: string[] = [];
    if (assetId) {
      params.push(assetId);
      where.push(`asset_id = $${params.length}`);
    }
    params.push(limit);
    const r = await this.db.query(
      `SELECT id, asset_id, profile_id, scan_mode, status, started_at, ended_at, tool_versions, stats, error, created_at, updated_at
         FROM asv_scan_run
        WHERE ${where.length ? where.join(" AND ") : "TRUE"}
     ORDER BY created_at DESC
        LIMIT $${params.length}`,
      params
    );
    return { items: r.rows };
  }

  @Get("findings")
  async listFindings(@Query("assetId") assetId?: string, @Query("limit") limitRaw?: string) {
    const limit = Math.max(1, Math.min(200, Number(limitRaw ?? 100)));
    const params: any[] = [];
    const where: string[] = [];
    if (assetId) {
      params.push(assetId);
      where.push(`asset_id = $${params.length}`);
    }
    params.push(limit);
    const r = await this.db.query(
      `SELECT id, asset_id, scan_run_id, fingerprint, title, severity, confidence, tool, external_id,
              affected, evidence, status, first_seen, last_seen, created_at, updated_at
         FROM asv_finding
        WHERE ${where.length ? where.join(" AND ") : "TRUE"}
     ORDER BY last_seen DESC
        LIMIT $${params.length}`,
      params
    );
    return { items: r.rows };
  }

  @Get("findings/:id/ai/triage")
  async getFindingTriage(@Param("id") id: string) {
    const r = await this.db.query<{ asset_id: string }>(`SELECT asset_id FROM asv_finding WHERE id = $1`, [id]);
    const row = r.rows[0];
    if (!row) throw new NotFoundException();
    const n = await this.db.query(
      `SELECT id, kind, model, prompt_version, output_json, output_text, created_at
         FROM asv_ai_note
        WHERE finding_id = $1 AND kind = 'finding_triage'
     ORDER BY created_at DESC
        LIMIT 1`,
      [id]
    );
    return { item: n.rows[0] ?? null };
  }

  @Get("findings/:id/msf-runs")
  async listMsfRunsByFinding(@Param("id") findingId: string) {
    const r = await this.db.query(
      `SELECT id, finding_id, scan_run_id, asset_id, status, mode, action, module, options, ack_risks, summary, error,
              created_by, started_at, ended_at, created_at, updated_at
         FROM asv_msf_run
        WHERE finding_id = $1
     ORDER BY created_at DESC
        LIMIT 50`,
      [findingId]
    );
    return { items: r.rows };
  }

  @Post("findings/:id/msf-runs")
  async createMsfRun(
    @Param("id") findingId: string,
    @CurrentUser() user: AuthUser,
    @Body()
    body: {
      mode?: "safe" | "exploit";
      action?: "search" | "check" | "run" | "exploit";
      module?: string | null;
      options?: Record<string, unknown> | null;
      ackRisks?: boolean;
      autoPick?: boolean;
    }
  ) {
    const mode = body.mode === "exploit" ? "exploit" : "safe";
    const actionRaw = String(body.action ?? "check").trim().toLowerCase();
    const action =
      actionRaw === "search" || actionRaw === "run" || actionRaw === "exploit" || actionRaw === "check"
        ? (actionRaw as "search" | "check" | "run" | "exploit")
        : "check";

    const module = typeof body.module === "string" ? body.module.trim() : "";
    const options = body.options && typeof body.options === "object" ? body.options : {};
    const ackRisks = Boolean(body.ackRisks === true);
    const autoPick = Boolean(body.autoPick === true);

    if (mode === "exploit" && !ackRisks) {
      throw new BadRequestException("exploit mode requires ackRisks=true");
    }
    if (action === "exploit" && mode !== "exploit") {
      throw new BadRequestException("action=exploit requires mode=exploit");
    }
    if (autoPick && action === "search") {
      throw new BadRequestException("autoPick requires a validation action (check/run/exploit), not search");
    }

    const f = await this.db.query<{ id: string; scan_run_id: string | null; asset_id: string }>(
      `SELECT id, scan_run_id, asset_id FROM asv_finding WHERE id = $1`,
      [findingId]
    );
    const fr = f.rows[0];
    if (!fr) throw new NotFoundException("finding not found");

    const r = await this.db.query(
      `INSERT INTO asv_msf_run (finding_id, scan_run_id, asset_id, status, mode, action, module, options, ack_risks, created_by)
       VALUES ($1,$2,$3,'queued',$4,$5,$6,$7::jsonb,$8,$9)
       RETURNING id, finding_id, scan_run_id, asset_id, status, mode, action, module, options, ack_risks, summary, error, created_by,
                 started_at, ended_at, created_at, updated_at`,
      [
        findingId,
        fr.scan_run_id ?? null,
        fr.asset_id ?? null,
        mode,
        action,
        module.length ? module : null,
        JSON.stringify({ ...options, autoPick: autoPick || undefined }),
        ackRisks,
        user?.email ?? null
      ]
    );
    const row = r.rows[0];
    if (!row?.id) throw new Error("failed to create msf run");

    await this.db.query(
      `INSERT INTO asv_msf_event (run_id, actor, action, before, after, meta)
       VALUES ($1,$2,'created',NULL,$3::jsonb,$4::jsonb)`,
      [row.id, user?.email ?? null, JSON.stringify({ status: "queued" }), JSON.stringify({ mode, action })]
    );

    await this.queue.publish("vuln.events", "asv.msf.requested.v1", {
      id: randomUUID(),
      type: "asv.msf.requested.v1",
      ts: new Date().toISOString(),
      producer: { service: "api" },
      idempotencyKey: `asv:msf:${row.id}`,
      payload: { runId: row.id }
    });

    return row;
  }

  @Get("msf-runs/:id")
  async getMsfRun(@Param("id") id: string) {
    const r = await this.db.query(
      `SELECT id, finding_id, scan_run_id, asset_id, status, mode, action, module, options, ack_risks, summary, error,
              created_by, started_at, ended_at, created_at, updated_at
         FROM asv_msf_run
        WHERE id = $1`,
      [id]
    );
    const row = r.rows[0];
    if (!row) throw new NotFoundException();
    return row;
  }

  @Get("msf-runs/:id/events")
  async getMsfRunEvents(@Param("id") id: string) {
    const r = await this.db.query(
      `SELECT id, run_id, ts, actor, action, before, after, meta
         FROM asv_msf_event
        WHERE run_id = $1
     ORDER BY ts DESC
        LIMIT 200`,
      [id]
    );
    return { items: r.rows };
  }

  @Get("msf-runs/:id/artifacts")
  async listMsfRunArtifacts(@Param("id") id: string) {
    const r = await this.db.query(
      `SELECT id, run_id, kind, bytes, sha256, storage, created_at
         FROM asv_msf_artifact
        WHERE run_id = $1
     ORDER BY created_at DESC`,
      [id]
    );
    return { items: r.rows };
  }

  @Get("msf-runs/:runId/artifacts/:artifactId")
  async getMsfRunArtifact(@Param("runId") runId: string, @Param("artifactId") artifactId: string) {
    const r = await this.db.query(
      `SELECT id, run_id, kind, bytes, sha256, storage, content_text, created_at
         FROM asv_msf_artifact
        WHERE run_id = $1 AND id = $2`,
      [runId, artifactId]
    );
    const row = r.rows[0];
    if (!row) throw new NotFoundException();
    return row;
  }

  @Post("findings/:id/ai/triage")
  async requestFindingTriage(@Param("id") id: string) {
    const r = await this.db.query<{
      id: string;
      asset_id: string;
      tool: string;
      title: string;
      severity: string;
      confidence: string;
      external_id: string | null;
      affected: any;
      evidence: any;
    }>(
      `SELECT id, asset_id, tool, title, severity, confidence, external_id, affected, evidence
         FROM asv_finding
        WHERE id = $1`,
      [id]
    );
    const f = r.rows[0];
    if (!f) throw new NotFoundException();

    const input = {
      kind: "asv_finding_triage_v1",
      finding: {
        id: f.id,
        tool: f.tool,
        title: f.title,
        severity: f.severity,
        confidence: f.confidence,
        external_id: f.external_id,
        affected: f.affected,
        evidence: f.evidence
      }
    };
    const inputHash = await sha256Hex(stableJsonStringify(input));

    const env = {
      id: randomUUID(),
      type: "asv.ai.triage.requested.v1",
      ts: new Date().toISOString(),
      idempotencyKey: `asv:ai:triage:finding:${f.id}:${inputHash.slice(0, 16)}`,
      payload: { findingId: f.id }
    };
    await this.queue.publish("vuln.events", "asv.ai.triage.requested.v1", env);
    return { ok: true };
  }

  @Get("issues")
  async listIssues(
    @Query("assetId") assetId?: string,
    @Query("status") statusRaw?: string,
    @Query("limit") limitRaw?: string
  ) {
    const limit = Math.max(1, Math.min(500, Number(limitRaw ?? 200)));
    const status = String(statusRaw ?? "").trim().toLowerCase();
    const params: any[] = [];
    const where: string[] = [];
    if (assetId) {
      params.push(assetId);
      where.push(`asset_id = $${params.length}`);
    }
    if (status && ["open", "resolved", "accepted", "false_positive"].includes(status)) {
      params.push(status);
      where.push(`status = $${params.length}`);
    }
    params.push(limit);
    const r = await this.db.query(
      `SELECT id, asset_id, issue_key, title, tool, external_id, endpoint_key, severity, confidence, status,
              first_seen, last_seen, last_scan_run_id, occurrences, fix_guidance, created_at, updated_at
         FROM asv_issue
        WHERE ${where.length ? where.join(" AND ") : "TRUE"}
     ORDER BY (status = 'open') DESC, last_seen DESC
        LIMIT $${params.length}`,
      params
    );
    return { items: r.rows };
  }

  @Get("issues/:id/ai/priority")
  async getIssuePriority(@Param("id") id: string) {
    const r = await this.db.query<{ asset_id: string }>(`SELECT asset_id FROM asv_issue WHERE id = $1`, [id]);
    const row = r.rows[0];
    if (!row) throw new NotFoundException();
    const n = await this.db.query(
      `SELECT id, kind, model, prompt_version, output_json, output_text, created_at
         FROM asv_ai_note
        WHERE issue_id = $1 AND kind = 'issue_priority'
     ORDER BY created_at DESC
        LIMIT 1`,
      [id]
    );
    return { item: n.rows[0] ?? null };
  }

  @Post("issues/:id/ai/priority")
  async requestIssuePriority(@Param("id") id: string) {
    const r = await this.db.query<{
      id: string;
      asset_id: string;
      title: string;
      tool: string;
      external_id: string | null;
      endpoint_key: string | null;
      severity: string;
      confidence: string;
      status: string;
      occurrences: number;
      fix_guidance: any;
      first_seen: string;
      last_seen: string;
    }>(
      `SELECT id, asset_id, title, tool, external_id, endpoint_key, severity, confidence, status, occurrences, fix_guidance,
              first_seen::text, last_seen::text
         FROM asv_issue
        WHERE id = $1`,
      [id]
    );
    const it = r.rows[0];
    if (!it) throw new NotFoundException();

    const input = { kind: "asv_issue_priority_v1", issue: it };
    const inputHash = await sha256Hex(stableJsonStringify(input));

    const env = {
      id: randomUUID(),
      type: "asv.ai.priority.requested.v1",
      ts: new Date().toISOString(),
      idempotencyKey: `asv:ai:priority:issue:${it.id}:${inputHash.slice(0, 16)}`,
      payload: { issueId: it.id }
    };
    await this.queue.publish("vuln.events", "asv.ai.priority.requested.v1", env);
    return { ok: true };
  }

  @Get("scan-runs/diff")
  async diffScanRuns(@Query("from") fromId?: string, @Query("to") toId?: string) {
    const from = String(fromId ?? "").trim();
    const to = String(toId ?? "").trim();
    if (!from || !to) throw new BadRequestException("from and to required");

    const fromFindings = await this.db.query<{
      fingerprint: string;
      title: string;
      severity: string;
      tool: string;
      external_id: string | null;
      affected: unknown;
    }>(
      `SELECT fingerprint, title, severity, tool, external_id, affected
         FROM asv_finding
        WHERE scan_run_id = $1`,
      [from]
    );
    const toFindings = await this.db.query<{
      fingerprint: string;
      title: string;
      severity: string;
      tool: string;
      external_id: string | null;
      affected: unknown;
    }>(
      `SELECT fingerprint, title, severity, tool, external_id, affected
         FROM asv_finding
        WHERE scan_run_id = $1`,
      [to]
    );

    const fromMap = new Map<string, (typeof fromFindings)["rows"][number]>();
    for (const f of fromFindings.rows) fromMap.set(f.fingerprint, f);
    const toMap = new Map<string, (typeof toFindings)["rows"][number]>();
    for (const f of toFindings.rows) toMap.set(f.fingerprint, f);

    const added: any[] = [];
    const resolved: any[] = [];
    const changed: Array<{
      fingerprint: string;
      title: string;
      fromSeverity: string;
      toSeverity: string;
      tool: string;
      external_id: string | null;
      affected: unknown;
    }> = [];

    for (const [fp, f] of toMap.entries()) {
      if (!fromMap.has(fp)) {
        added.push(f);
      } else {
        const prev = fromMap.get(fp)!;
        const a = severityRank(prev.severity);
        const b = severityRank(f.severity);
        if (a !== b) {
          changed.push({
            fingerprint: fp,
            title: f.title,
            fromSeverity: prev.severity,
            toSeverity: f.severity,
            tool: f.tool,
            external_id: f.external_id,
            affected: f.affected
          });
        }
      }
    }
    for (const [fp, f] of fromMap.entries()) {
      if (!toMap.has(fp)) resolved.push(f);
    }

    // Sort by severity desc for readability.
    added.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
    resolved.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
    changed.sort((a, b) => severityRank(b.toSeverity) - severityRank(a.toSeverity));

    return {
      from,
      to,
      added,
      resolved,
      changed
    };
  }

  @Get("observations/ports")
  async listPortObservations(@Query("assetId") assetId?: string, @Query("limit") limitRaw?: string) {
    const limit = Math.max(1, Math.min(500, Number(limitRaw ?? 200)));
    const params: any[] = [];
    const where: string[] = [];
    if (assetId) {
      params.push(assetId);
      where.push(`asset_id = $${params.length}`);
    }
    params.push(limit);
    const r = await this.db.query(
      `SELECT id, asset_id, scan_run_id, target, ip, port, transport, state, latency_ms, evidence, observed_at
         FROM asv_port_observation
        WHERE ${where.length ? where.join(" AND ") : "TRUE"}
     ORDER BY observed_at DESC
        LIMIT $${params.length}`,
      params
    );
    return { items: r.rows };
  }

  @Get("observations/http")
  async listHttpObservations(@Query("assetId") assetId?: string, @Query("limit") limitRaw?: string) {
    const limit = Math.max(1, Math.min(500, Number(limitRaw ?? 200)));
    const params: any[] = [];
    const where: string[] = [];
    if (assetId) {
      params.push(assetId);
      where.push(`asset_id = $${params.length}`);
    }
    params.push(limit);
    const r = await this.db.query(
      `SELECT id, asset_id, scan_run_id, url, final_url, status, title, server, headers, tech, latency_ms, evidence, observed_at
         FROM asv_http_observation
        WHERE ${where.length ? where.join(" AND ") : "TRUE"}
     ORDER BY observed_at DESC
        LIMIT $${params.length}`,
      params
    );
    return { items: r.rows };
  }

  @Get("inventory")
  async inventory(@Query("assetId") assetId?: string) {
    if (!assetId) throw new BadRequestException("assetId required");

    const ports = await this.db.query<{
      port: number;
      state: string;
      n: number;
      last_observed_at: string;
    }>(
      `SELECT port,
              state,
              COUNT(*)::int AS n,
              MAX(observed_at)::text AS last_observed_at
         FROM asv_port_observation
        WHERE asset_id = $1
     GROUP BY port, state
     ORDER BY port ASC, state ASC`,
      [assetId]
    );

    const http = await this.db.query<{
      url: string;
      status: number | null;
      server: string | null;
      title: string | null;
      last_observed_at: string;
    }>(
      `SELECT url,
              status,
              server,
              title,
              MAX(observed_at)::text AS last_observed_at
         FROM asv_http_observation
        WHERE asset_id = $1
     GROUP BY url, status, server, title
     ORDER BY MAX(observed_at) DESC
        LIMIT 120`,
      [assetId]
    );

    const findingCounts = await this.db.query<{ tool: string; severity: string; n: number }>(
      `SELECT tool, severity, COUNT(*)::int AS n
         FROM asv_finding
        WHERE asset_id = $1
     GROUP BY tool, severity
     ORDER BY tool ASC, severity ASC`,
      [assetId]
    );

    return {
      ports: ports.rows,
      http: http.rows,
      findingCounts: findingCounts.rows
    };
  }

  @Get("scan-runs/:id/artifacts")
  async listArtifacts(@Param("id") scanRunId: string) {
    const r = await this.db.query(
      `SELECT id, scan_run_id, kind, bytes, sha256, storage, created_at
         FROM asv_scan_artifact
        WHERE scan_run_id = $1
     ORDER BY created_at DESC`,
      [scanRunId]
    );
    return { items: r.rows };
  }

  @Get("scan-runs/:scanRunId/artifacts/:artifactId")
  async getArtifact(
    @Param("scanRunId") scanRunId: string,
    @Param("artifactId") artifactId: string
  ) {
    const r = await this.db.query(
      `SELECT id, scan_run_id, kind, bytes, sha256, storage, content_text, created_at
         FROM asv_scan_artifact
        WHERE scan_run_id = $1 AND id = $2`,
      [scanRunId, artifactId]
    );
    const row = r.rows[0];
    if (!row) throw new NotFoundException();
    return row;
  }

  @Get("nuclei/templates")
  async listNucleiTemplates(@Query("templateIds") templateIdsRaw?: string) {
    const ids = String(templateIdsRaw ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0)
      .slice(0, 60);
    if (ids.length === 0) return { items: [] };
    const r = await this.db.query(
      `SELECT template_id, name, severity, tags, description, reference, updated_at
         FROM asv_nuclei_template
        WHERE template_id = ANY($1::text[])`,
      [ids]
    );
    return { items: r.rows };
  }

  @Get("nuclei/templates/:templateId")
  async getNucleiTemplate(@Param("templateId") templateId: string) {
    const id = String(templateId ?? "").trim();
    if (!id) throw new BadRequestException("templateId required");
    const r = await this.db.query(
      `SELECT template_id, name, severity, tags, description, reference, updated_at
         FROM asv_nuclei_template
        WHERE template_id = $1`,
      [id]
    );
    const row = r.rows[0];
    if (!row) throw new NotFoundException();
    return row;
  }
}


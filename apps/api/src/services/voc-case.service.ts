import { BadRequestException, Injectable, Logger, NotFoundException, OnModuleInit } from "@nestjs/common";
import {
  computeSlaDueAt,
  VOC_OUTCOMES,
  vocDedupKey,
  vocPriorityToTaskPriority,
  buildVocPlaybookFromContext,
  runVocPlaybookLlm,
  type VocCaseStatus,
  type VocOutcome,
  type VocPlaybook,
  type VocPlaybookContextInput,
  type VocPriority,
  type VocSource
} from "@vuln-intel/shared";
import type { AuthUser } from "../auth/jwt.strategy.js";
import { DbService } from "./db.service.js";
import { IntegrationSettingsService } from "./integration-settings.service.js";
import { VulnTaskService } from "./vuln-task.service.js";
import { VocShiftService } from "./voc-shift.service.js";

export type VocCaseEvidenceRow = {
  id: string;
  body: string;
  url: string | null;
  authorEmail: string | null;
  createdAt: string;
};

export type VocCaseRow = {
  id: string;
  title: string;
  status: VocCaseStatus;
  dedupKey: string;
  primaryRefKey: string;
  assigneeUserId: string | null;
  assigneeEmail: string | null;
  slaDueAt: string | null;
  vocPriority: VocPriority;
  taskId: string | null;
  createdByEmail: string | null;
  createdAt: string;
  updatedAt: string;
  refCount: number;
  refs: Array<{ refKey: string; source: VocSource; refId: string; addedAt: string }>;
  outcome?: VocOutcome | null;
  outcomeNotes?: string | null;
  resolvedAt?: string | null;
  playbook?: VocPlaybook | null;
  evidence?: VocCaseEvidenceRow[];
};

type CaseRefHit = {
  ref_key: string;
  case_id: string;
  status: VocCaseStatus;
  assignee_email: string | null;
  sla_due_at: Date | null;
  task_id: string | null;
  ref_count: number;
};

@Injectable()
export class VocCaseService implements OnModuleInit {
  private readonly logger = new Logger(VocCaseService.name);

  constructor(
    private readonly db: DbService,
    private readonly vulnTasks: VulnTaskService,
    private readonly integration: IntegrationSettingsService,
    private readonly vocShift: VocShiftService
  ) {}

  onModuleInit() {
    if (process.env.VOC_TASK_BACKFILL === "false") return;
    const delayMs = Math.max(5_000, Number(process.env.VOC_TASK_BACKFILL_ON_START_MS ?? 45_000));
    setTimeout(() => {
      void this.backfillMissingTasks({ limit: Number(process.env.VOC_TASK_BACKFILL_LIMIT ?? 200) })
        .then((r) => {
          if (r.created > 0 || r.failed > 0) {
            this.logger.log(
              `orphan task backfill scanned=${r.scanned} created=${r.created} failed=${r.failed}`
            );
          }
        })
        .catch((e) =>
          this.logger.warn(`orphan task backfill failed: ${e instanceof Error ? e.message : String(e)}`)
        );
    }, delayMs);
  }

  async listCases(opts?: { status?: string; limit?: number }): Promise<VocCaseRow[]> {
    const limit = Math.max(1, Math.min(200, opts?.limit ?? 80));
    const statusFilter = (opts?.status ?? "active").toLowerCase();
    const params: unknown[] = [];
    let where = "1=1";
    if (statusFilter === "active") {
      where = "c.status IN ('open','in_progress')";
    } else if (statusFilter !== "all") {
      const statuses = statusFilter.split(",").map((s) => s.trim()).filter(Boolean);
      if (statuses.length) {
        params.push(statuses);
        where = `c.status = ANY($${params.length}::text[])`;
      }
    }

    const r = await this.db.query<{
      id: string;
      title: string;
      status: VocCaseStatus;
      dedup_key: string;
      primary_ref_key: string;
      assignee_user_id: string | null;
      assignee_email: string | null;
      sla_due_at: Date | null;
      voc_priority: VocPriority;
      task_id: string | null;
      created_by_email: string | null;
      created_at: Date;
      updated_at: Date;
      ref_count: string;
    }>(
      `SELECT c.*,
              (SELECT count(*)::text FROM voc_case_ref r WHERE r.case_id = c.id) AS ref_count
         FROM voc_case c
        WHERE ${where}
        ORDER BY
          CASE WHEN c.sla_due_at IS NULL THEN 1 ELSE 0 END,
          c.sla_due_at ASC NULLS LAST,
          c.updated_at DESC
        LIMIT ${limit}`,
      params
    );

    return this.mapCaseRows(r.rows);
  }

  /**
   * Cases where this CVE/BDU/TG ref participated — via voc_case_ref and/or a linked vuln_task.
   * Includes closed/cancelled (history), unlike the default active list.
   */
  async listCasesByRef(opts: {
    source: VocSource;
    refId: string;
    limit?: number;
  }): Promise<VocCaseRow[]> {
    const source = opts.source;
    const refId = String(opts.refId ?? "").trim();
    if (!refId) throw new BadRequestException("refId required");
    if (source !== "cve" && source !== "bdu" && source !== "tg") {
      throw new BadRequestException("source must be cve|bdu|tg");
    }

    const limit = Math.max(1, Math.min(100, opts.limit ?? 50));
    const refKey =
      source === "cve"
        ? refId.toUpperCase().startsWith("CVE:")
          ? refId.toUpperCase()
          : `CVE:${refId.toUpperCase()}`
        : source === "bdu"
          ? refId.toUpperCase().startsWith("BDU:")
            ? refId.toUpperCase()
            : `BDU:${refId}`
          : refId.toUpperCase().startsWith("TG:")
            ? refId
            : `TG:${refId}`;
    const bareId =
      source === "cve"
        ? refId.replace(/^CVE:/i, "").toUpperCase()
        : source === "bdu"
          ? refId.replace(/^BDU:/i, "")
          : refId.replace(/^TG:/i, "");

    const r = await this.db.query<{
      id: string;
      title: string;
      status: VocCaseStatus;
      dedup_key: string;
      primary_ref_key: string;
      assignee_user_id: string | null;
      assignee_email: string | null;
      sla_due_at: Date | null;
      voc_priority: VocPriority;
      task_id: string | null;
      created_by_email: string | null;
      created_at: Date;
      updated_at: Date;
      ref_count: string;
    }>(
      `SELECT c.*,
              (SELECT count(*)::text FROM voc_case_ref r0 WHERE r0.case_id = c.id) AS ref_count
         FROM voc_case c
        WHERE c.id IN (
                SELECT r.case_id
                  FROM voc_case_ref r
                 WHERE (r.source = $1 AND upper(r.ref_id) = upper($2))
                    OR upper(r.ref_key) = upper($3)
              )
           OR (
                $1 = 'cve'
                AND c.task_id IS NOT NULL
                AND EXISTS (
                  SELECT 1 FROM vuln_task_cve l
                   WHERE l.task_id = c.task_id AND l.cve_id = $2
                )
              )
        ORDER BY c.updated_at DESC
        LIMIT ${limit}`,
      [source, bareId, refKey]
    );

    return this.mapCaseRows(r.rows);
  }

  private async mapCaseRows(
    rows: Array<{
      id: string;
      title: string;
      status: VocCaseStatus;
      dedup_key: string;
      primary_ref_key: string;
      assignee_user_id: string | null;
      assignee_email: string | null;
      sla_due_at: Date | null;
      voc_priority: VocPriority;
      task_id: string | null;
      created_by_email: string | null;
      created_at: Date;
      updated_at: Date;
      ref_count: string;
    }>
  ): Promise<VocCaseRow[]> {
    const ids = rows.map((row) => row.id);
    const refsByCase = await this.loadRefsForCases(ids);

    return rows.map((row) => ({
      id: row.id,
      title: row.title,
      status: row.status,
      dedupKey: row.dedup_key,
      primaryRefKey: row.primary_ref_key,
      assigneeUserId: row.assignee_user_id,
      assigneeEmail: row.assignee_email,
      slaDueAt: row.sla_due_at?.toISOString?.() ?? null,
      vocPriority: row.voc_priority,
      taskId: row.task_id,
      createdByEmail: row.created_by_email,
      createdAt: row.created_at.toISOString(),
      updatedAt: row.updated_at.toISOString(),
      refCount: Number(row.ref_count) || 0,
      refs: refsByCase.get(row.id) ?? []
    }));
  }

  async loadCaseMapByRefKeys(refKeys: string[]): Promise<Map<string, CaseRefHit>> {
    const keys = [...new Set(refKeys.map((k) => k.trim()).filter(Boolean))];
    if (!keys.length) return new Map();

    const r = await this.db.query<CaseRefHit & { ref_count: string }>(
      `SELECT r.ref_key,
              c.id AS case_id,
              c.status,
              c.assignee_email,
              c.sla_due_at,
              c.task_id,
              (SELECT count(*)::text FROM voc_case_ref r2 WHERE r2.case_id = c.id) AS ref_count
         FROM voc_case_ref r
         JOIN voc_case c ON c.id = r.case_id
        WHERE r.ref_key = ANY($1::text[])
          AND c.status IN ('open','in_progress')`,
      [keys]
    );

    const map = new Map<string, CaseRefHit>();
    for (const row of r.rows) {
      map.set(row.ref_key, {
        ref_key: row.ref_key,
        case_id: row.case_id,
        status: row.status,
        assignee_email: row.assignee_email,
        sla_due_at: row.sla_due_at,
        task_id: row.task_id,
        ref_count: Number(row.ref_count) || 1
      });
    }
    return map;
  }

  async createFromRef(
    user: AuthUser,
    input: {
      refKey: string;
      source: VocSource;
      refId: string;
      title: string;
      subtitle?: string | null;
      vocPriority?: VocPriority;
      vocReasons?: string[];
      linkedCveIds?: string[];
      assigneeEmail?: string | null;
      createTask?: boolean;
      vendorKey?: string;
      vendorDisplay?: string;
      productKeyNorm?: string;
      productDisplay?: string;
      tgChannel?: string | null;
    }
  ) {
    const refKey = String(input.refKey ?? "").trim();
    const source = input.source;
    const refId = String(input.refId ?? "").trim();
    const title = String(input.title ?? "").trim();
    if (!refKey || !refId || !title) throw new BadRequestException("refKey/refId/title required");

    const vocPriority = input.vocPriority ?? "p4";
    const linkedCveIds = (input.linkedCveIds ?? []).map((x) => String(x).trim().toUpperCase()).filter(Boolean);
    const dedupKey = vocDedupKey({ refKey, source, refId, linkedCveIds });
    const assigneeEmail = (input.assigneeEmail?.trim() || user.email || null) ?? null;
    const slaDueAt = computeSlaDueAt(vocPriority);

    const existing = await this.db.query<{ id: string }>(
      `SELECT id FROM voc_case
        WHERE dedup_key = $1 AND status IN ('open','in_progress')
        ORDER BY updated_at DESC
        LIMIT 1`,
      [dedupKey]
    );

    if (existing.rows[0]) {
      const caseId = existing.rows[0].id;
      await this.db.query(
        `INSERT INTO voc_case_ref (case_id, ref_key, source, ref_id)
         VALUES ($1,$2,$3,$4)
         ON CONFLICT (case_id, ref_key) DO NOTHING`,
        [caseId, refKey, source, refId]
      );
      await this.db.query(`UPDATE voc_case SET updated_at = now() WHERE id = $1`, [caseId]);
      let taskId: string | null = null;
      if (input.createTask !== false) {
        try {
          taskId = await this.ensureTaskForCase(caseId, {
            refKey,
            source,
            refId,
            title,
            subtitle: input.subtitle,
            vocPriority,
            vocReasons: input.vocReasons,
            linkedCveIds,
            vendorKey: input.vendorKey,
            vendorDisplay: input.vendorDisplay,
            productKeyNorm: input.productKeyNorm,
            productDisplay: input.productDisplay,
            tgChannel: input.tgChannel,
            slaDueAt
          });
        } catch (e) {
          this.logger.error(
            `ensureTask failed for existing case ${caseId}: ${e instanceof Error ? e.message : String(e)}`
          );
        }
      }
      const row = await this.getCaseById(caseId);
      return { ok: true, deduped: true, taskId: taskId ?? row.taskId, case: row };
    }

    const ins = await this.db.query<{ id: string }>(
      `INSERT INTO voc_case (
         title, status, dedup_key, primary_ref_key,
         assignee_user_id, assignee_email, sla_due_at, voc_priority,
         created_by_user_id, created_by_email, meta
       ) VALUES ($1,'in_progress',$2,$3,$4,$5,$6,$7,$8,$9,'{}'::jsonb)
       RETURNING id`,
      [
        title,
        dedupKey,
        refKey,
        user.userId || null,
        assigneeEmail,
        slaDueAt,
        vocPriority,
        user.userId || null,
        user.email || null
      ]
    );
    const caseId = ins.rows[0]!.id;

    await this.db.query(
      `INSERT INTO voc_case_ref (case_id, ref_key, source, ref_id) VALUES ($1,$2,$3,$4)`,
      [caseId, refKey, source, refId]
    );

    let taskId: string | null = null;
    if (input.createTask !== false) {
      try {
        taskId = await this.ensureTaskForCase(caseId, {
          refKey,
          source,
          refId,
          title,
          subtitle: input.subtitle,
          vocPriority,
          vocReasons: input.vocReasons,
          linkedCveIds,
          vendorKey: input.vendorKey,
          vendorDisplay: input.vendorDisplay,
          productKeyNorm: input.productKeyNorm,
          productDisplay: input.productDisplay,
          tgChannel: input.tgChannel,
          slaDueAt
        });
      } catch (e) {
        this.logger.error(
          `ensureTask failed for new case ${caseId}: ${e instanceof Error ? e.message : String(e)}`
        );
      }
    }

    // Playbook after task — best-effort so LLM/DB slowness cannot leave a case without a task.
    try {
      const playbookCtx = await this.collectPlaybookContext({
        refKey,
        source,
        refId,
        title,
        subtitle: input.subtitle,
        vocPriority,
        vocReasons: input.vocReasons,
        linkedCveIds,
        vendorDisplay: input.vendorDisplay,
        productDisplay: input.productDisplay,
        tgChannel: input.tgChannel
      });
      await this.generateAndSavePlaybook(caseId, playbookCtx);
    } catch (e) {
      this.logger.warn(
        `playbook deferred for case ${caseId}: ${e instanceof Error ? e.message : String(e)}`
      );
    }

    const row = await this.getCaseById(caseId);
    return { ok: true, deduped: false, taskId, case: row };
  }

  async patchCase(
    user: AuthUser,
    caseId: string,
    input: {
      status?: VocCaseStatus;
      assigneeEmail?: string | null;
      slaDueAt?: string | null;
      title?: string;
    }
  ) {
    const existing = await this.db.query(`SELECT id FROM voc_case WHERE id = $1`, [caseId]);
    if (!existing.rows[0]) throw new NotFoundException("case not found");

    const sets: string[] = ["updated_at = now()"];
    const params: unknown[] = [];
    const add = (col: string, val: unknown) => {
      params.push(val);
      sets.push(`${col} = $${params.length}`);
    };

    if (input.status) add("status", input.status);
    if (input.title?.trim()) add("title", input.title.trim());
    if (input.slaDueAt !== undefined) add("sla_due_at", input.slaDueAt ? new Date(input.slaDueAt) : null);
    if (input.assigneeEmail !== undefined) {
      add("assignee_email", input.assigneeEmail?.trim() || null);
      add("assignee_user_id", input.assigneeEmail?.trim() ? user.userId || null : null);
    }

    if (sets.length === 1) throw new BadRequestException("nothing to update");

    params.push(caseId);
    await this.db.query(`UPDATE voc_case SET ${sets.join(", ")} WHERE id = $${params.length}`, params);
    const row = await this.getCaseById(caseId);
    return { ok: true, case: row };
  }

  async addEvidence(
    user: AuthUser,
    caseId: string,
    input: { body?: string; url?: string | null }
  ) {
    const body = String(input.body ?? "").trim();
    if (!body) throw new BadRequestException("body required");
    await this.getCaseById(caseId);

    const url = input.url?.trim() || null;
    const ins = await this.db.query<{ id: string; created_at: Date }>(
      `INSERT INTO voc_case_evidence (case_id, author_email, body, url)
       VALUES ($1,$2,$3,$4)
       RETURNING id, created_at`,
      [caseId, user.email || null, body, url]
    );

    await this.markPlaybookStep(caseId, "evidence", true, user.email || null);
    const detail = await this.getCaseById(caseId, { withEvidence: true });
    const ev = detail.evidence?.find((e) => e.id === ins.rows[0]!.id);
    return { ok: true, evidence: ev, case: detail };
  }

  async patchPlaybookStep(
    user: AuthUser,
    caseId: string,
    input: { stepId?: string; done?: boolean }
  ) {
    const stepId = String(input.stepId ?? "").trim();
    if (!stepId) throw new BadRequestException("stepId required");
    const done = Boolean(input.done);

    const detail = await this.getCaseById(caseId, { withEvidence: true });
    const playbook = detail.playbook;
    if (!playbook) throw new BadRequestException("playbook not initialized");

    const step = playbook.steps.find((s) => s.id === stepId);
    if (!step) throw new BadRequestException("unknown playbook step");

    step.done = done;
    step.doneAt = done ? new Date().toISOString() : null;
    step.doneBy = done ? user.email || null : null;

    await this.db.query(`UPDATE voc_case SET playbook = $2::jsonb, updated_at = now() WHERE id = $1`, [
      caseId,
      JSON.stringify(playbook)
    ]);
    const updated = await this.getCaseById(caseId, { withEvidence: true });
    return { ok: true, case: updated };
  }

  async regeneratePlaybook(caseId: string) {
    const row = await this.getCaseById(caseId);
    const primaryRef = row.refs.find((r) => r.refKey === row.primaryRefKey) ?? row.refs[0];
    if (!primaryRef) throw new BadRequestException("case has no refs");

    const ctx = await this.collectPlaybookContext({
      refKey: primaryRef.refKey,
      source: primaryRef.source,
      refId: primaryRef.refId,
      title: row.title,
      subtitle: null,
      vocPriority: row.vocPriority,
      vocReasons: [],
      linkedCveIds: row.refs.filter((r) => r.source === "cve").map((r) => r.refId),
      vendorDisplay: undefined,
      productDisplay: undefined,
      tgChannel: null
    });

    const prev = row.playbook;
    await this.generateAndSavePlaybook(caseId, ctx, prev);
    const updated = await this.getCaseById(caseId, { withEvidence: true });
    return { ok: true, case: updated };
  }

  async resolveCase(
    user: AuthUser,
    caseId: string,
    input: { outcome?: VocOutcome; notes?: string | null }
  ) {
    const outcome = input.outcome;
    if (!outcome || !VOC_OUTCOMES.includes(outcome)) throw new BadRequestException("invalid outcome");

    const existing = await this.getCaseById(caseId);
    const notes = input.notes?.trim() || null;

    await this.db.query(
      `UPDATE voc_case
          SET status = 'resolved',
              outcome = $2,
              outcome_notes = $3,
              resolved_at = now(),
              updated_at = now()
        WHERE id = $1`,
      [caseId, outcome, notes]
    );

    await this.syncTriageOnResolve(caseId);
    if (existing.taskId) {
      await this.syncTaskOnResolve(existing.taskId, outcome, notes);
    }

    if (outcome === "exposed") {
      void this.vocShift.fireCaseExposedAlert(existing.title, caseId);
    }

    const detail = await this.getCaseById(caseId, { withEvidence: true });
    return { ok: true, case: detail };
  }

  getEscalationTarget(caseRow: VocCaseRow): { kind: "cve" | "bdu"; entityId: string } | null {
    const primary = caseRow.refs.find((r) => r.refKey === caseRow.primaryRefKey) ?? caseRow.refs[0];
    if (!primary) return null;
    if (primary.source === "cve") return { kind: "cve", entityId: primary.refId };
    if (primary.source === "bdu") return { kind: "bdu", entityId: primary.refId };
    const cveRef = caseRow.refs.find((r) => r.source === "cve");
    if (cveRef) return { kind: "cve", entityId: cveRef.refId };
    const bduRef = caseRow.refs.find((r) => r.source === "bdu");
    if (bduRef) return { kind: "bdu", entityId: bduRef.refId };
    return null;
  }

  async getCaseById(caseId: string, opts?: { withEvidence?: boolean }): Promise<VocCaseRow> {
    const r = await this.db.query<{
      id: string;
      title: string;
      status: VocCaseStatus;
      dedup_key: string;
      primary_ref_key: string;
      assignee_user_id: string | null;
      assignee_email: string | null;
      sla_due_at: Date | null;
      voc_priority: VocPriority;
      task_id: string | null;
      created_by_email: string | null;
      created_at: Date;
      updated_at: Date;
      outcome: VocOutcome | null;
      outcome_notes: string | null;
      resolved_at: Date | null;
      playbook: VocPlaybook | null;
    }>(`SELECT * FROM voc_case WHERE id = $1`, [caseId]);
    const row = r.rows[0];
    if (!row) throw new NotFoundException("case not found");

    const refsByCase = await this.loadRefsForCases([caseId]);
    const refs = refsByCase.get(caseId) ?? [];
    const evidence = opts?.withEvidence ? await this.loadEvidence(caseId) : undefined;
    const primaryRef = refs.find((r) => r.refKey === row.primary_ref_key) ?? refs[0];
    const playbook = await this.ensurePlaybook(caseId, row.playbook, {
      refKey: primaryRef?.refKey ?? row.primary_ref_key,
      source: primaryRef?.source ?? "cve",
      refId: primaryRef?.refId ?? row.primary_ref_key,
      title: row.title,
      subtitle: null,
      vocPriority: row.voc_priority,
      vocReasons: [],
      linkedCveIds: refs.filter((r) => r.source === "cve").map((r) => r.refId),
      hasCve: refs.some((r) => r.source === "cve")
    });

    return {
      id: row.id,
      title: row.title,
      status: row.status,
      dedupKey: row.dedup_key,
      primaryRefKey: row.primary_ref_key,
      assigneeUserId: row.assignee_user_id,
      assigneeEmail: row.assignee_email,
      slaDueAt: row.sla_due_at?.toISOString?.() ?? null,
      vocPriority: row.voc_priority,
      taskId: row.task_id,
      createdByEmail: row.created_by_email,
      createdAt: row.created_at.toISOString(),
      updatedAt: row.updated_at.toISOString(),
      refCount: refs.length,
      refs,
      outcome: row.outcome,
      outcomeNotes: row.outcome_notes,
      resolvedAt: row.resolved_at?.toISOString?.() ?? null,
      playbook,
      evidence
    };
  }

  private async ensurePlaybook(
    caseId: string,
    raw: unknown,
    ctx: {
      refKey: string;
      source: VocSource;
      refId: string;
      title: string;
      subtitle?: string | null;
      vocPriority: VocPriority;
      vocReasons?: string[];
      linkedCveIds?: string[];
      hasCve?: boolean;
    }
  ): Promise<VocPlaybook> {
    const existing = this.normalizePlaybook(raw);
    if (existing?.aiGenerated && (existing.steps?.length ?? 0) >= 3) return existing;

    const fullCtx = await this.collectPlaybookContext({
      refKey: ctx.refKey,
      source: ctx.source,
      refId: ctx.refId,
      title: ctx.title,
      subtitle: ctx.subtitle,
      vocPriority: ctx.vocPriority,
      vocReasons: ctx.vocReasons,
      linkedCveIds:
        ctx.linkedCveIds ??
        (ctx.hasCve && ctx.source === "cve" ? [ctx.refId] : []),
      vendorDisplay: undefined,
      productDisplay: undefined,
      tgChannel: null
    });

    return this.generateAndSavePlaybook(caseId, fullCtx, existing);
  }

  private async generateAndSavePlaybook(
    caseId: string,
    ctx: VocPlaybookContextInput,
    preserveFrom?: VocPlaybook | null
  ): Promise<VocPlaybook> {
    const textEngine = await this.integration.getTextEngineSettings();
    let playbook =
      textEngine.textEngine === "llm"
        ? await runVocPlaybookLlm(ctx, await this.integration.getEffectiveLlmConfig())
        : buildVocPlaybookFromContext(ctx);
    if (preserveFrom) playbook = this.mergePlaybookProgress(preserveFrom, playbook);
    await this.db.query(`UPDATE voc_case SET playbook = $2::jsonb, updated_at = now() WHERE id = $1`, [
      caseId,
      JSON.stringify(playbook)
    ]);
    return playbook;
  }

  private mergePlaybookProgress(prev: VocPlaybook, fresh: VocPlaybook): VocPlaybook {
    for (const step of fresh.steps) {
      const old =
        prev.steps.find((s) => s.id === step.id) ??
        prev.steps.find((s) => s.label.trim().toLowerCase() === step.label.trim().toLowerCase());
      if (old?.done) {
        step.done = true;
        step.doneAt = old.doneAt ?? null;
        step.doneBy = old.doneBy ?? null;
      }
    }
    return fresh;
  }

  private async collectPlaybookContext(input: {
    refKey: string;
    source: VocSource;
    refId: string;
    title: string;
    subtitle?: string | null;
    vocPriority: VocPriority;
    vocReasons?: string[];
    linkedCveIds: string[];
    vendorDisplay?: string;
    productDisplay?: string;
    tgChannel?: string | null;
  }): Promise<VocPlaybookContextInput> {
    const cveIds = this.resolveCveIds(input.source, input.refId, input.linkedCveIds);
    const taskCtx = await this.resolveTaskContext(input.source, input.refId, input.linkedCveIds, {
      vendorDisplay: input.vendorDisplay,
      productDisplay: input.productDisplay,
      tgChannel: input.tgChannel,
      subtitle: input.subtitle
    });

    const cveDetails =
      cveIds.length > 0
        ? await this.loadCveDetailsForPlaybook(cveIds.slice(0, 5))
        : [];

    let bdu: VocPlaybookContextInput["bdu"];
    if (input.source === "bdu") {
      const r = await this.db.query<{
        bdu_id: string;
        name: string;
        description: string | null;
        vendors: string | null;
        software_names: string | null;
        solution: string | null;
        cvss_score: number | null;
        has_exploit: boolean;
        severity: string | null;
      }>(
        `SELECT bdu_id, name, description, vendors, software_names, solution, cvss_score, has_exploit, severity
           FROM bdu_vuln WHERE bdu_id = $1 LIMIT 1`,
        [input.refId]
      );
      const row = r.rows[0];
      if (row) {
        bdu = {
          bduId: row.bdu_id,
          name: row.name,
          description: row.description?.slice(0, 600) ?? null,
          vendors: row.vendors,
          softwareNames: row.software_names,
          solution: row.solution?.slice(0, 400) ?? null,
          cvss: row.cvss_score,
          hasExploit: row.has_exploit,
          severity: row.severity
        };
      }
    }

    const reasons = input.vocReasons ?? [];
    const signals = {
      kev: cveDetails.some((c) => c.kev) || reasons.some((r) => /kev/i.test(r)),
      vckevOnly: cveDetails.some((c) => c.vckevOnly) || reasons.some((r) => /vulncheck kev \(не cisa\)/i.test(r)),
      vulncheckKev: cveDetails.some((c) => c.vulncheckKev) || reasons.some((r) => /vulncheck kev/i.test(r)),
      epssSpike: cveDetails.some((c) => c.epssSpike) || reasons.some((r) => /epss spike/i.test(r)),
      hasPoc: cveDetails.some((c) => c.hasPoc) || reasons.some((r) => /\bpoc\b/i.test(r)),
      hasPublicExploit:
        cveDetails.some((c) => c.hasPublicExploit) ||
        reasons.some((r) => /публичный эксплойт|public exploit/i.test(r)),
      highEpss: cveDetails.some((c) => (c.epss ?? 0) >= 0.3),
      hasExploit:
        bdu?.hasExploit ||
        cveDetails.some((c) => c.hasPublicExploit || c.hasPoc || c.vckevOnly || c.kev) ||
        reasons.some((r) => /exploit|эксплуат/i.test(r)),
      watchlist: reasons.some((r) => r.startsWith("watchlist:")),
      fstec: input.source === "bdu" || reasons.some((r) => /fstec|бду|фстэк/i.test(r))
    };

    return {
      refKey: input.refKey,
      source: input.source,
      refId: input.refId,
      title: input.title,
      subtitle: input.subtitle ?? bdu?.name ?? null,
      vocPriority: input.vocPriority,
      vocReasons: reasons.slice(0, 12),
      cveIds,
      vendorDisplay: taskCtx.vendorDisplay,
      productDisplay: taskCtx.productDisplay || null,
      tgChannel: taskCtx.tgChannel,
      cveDetails,
      bdu,
      signals
    };
  }

  private async loadCveDetailsForPlaybook(cveIds: string[]) {
    if (!cveIds.length) return [];
    const r = await this.db.query<{
      cve_id: string;
      cvss_base: number | null;
      epss: number | null;
      exploit_known: boolean;
      vckev_only: boolean;
      vulncheck_kev: boolean;
      epss_spike: boolean;
      has_poc: boolean;
      has_public_exploit: boolean;
      description: string | null;
      vendor: string | null;
      product: string | null;
    }>(
      `SELECT c.cve_id,
              c.cvss_base,
              es.score AS epss,
              (k.cve_id IS NOT NULL) AS exploit_known,
              COALESCE(ei.vckev_only, false) AS vckev_only,
              COALESCE(ei.vulncheck_kev, false) AS vulncheck_kev,
              COALESCE(ei.epss_spike, false) AS epss_spike,
              COALESCE(ei.has_poc, false) AS has_poc,
              COALESCE(ei.has_public_exploit, false) AS has_public_exploit,
              substring(
                COALESCE(
                  c.raw->'descriptions'->0->>'value',
                  c.raw->'cve'->'descriptions'->0->>'value',
                  ''
                ) FOR 400
              ) AS description,
              vp.vendor,
              vp.product
         FROM cve c
    LEFT JOIN epss_score es ON es.cve_id = c.cve_id
    LEFT JOIN kev k ON k.cve_id = c.cve_id
    LEFT JOIN cve_exploit_intel ei ON ei.cve_id = c.cve_id
    LEFT JOIN LATERAL (
          SELECT vendor, product
            FROM cve_vendor_product
           WHERE cve_id = c.cve_id
           ORDER BY updated_at DESC NULLS LAST
           LIMIT 1
        ) vp ON true
        WHERE c.cve_id = ANY($1::text[])`,
      [cveIds]
    );
    return r.rows.map((row) => ({
      cveId: row.cve_id,
      cvss: row.cvss_base,
      epss: row.epss,
      kev: row.exploit_known,
      vckevOnly: row.vckev_only,
      vulncheckKev: row.vulncheck_kev,
      epssSpike: row.epss_spike,
      hasPoc: row.has_poc,
      hasPublicExploit: row.has_public_exploit,
      description: row.description,
      vendor: row.vendor,
      product: row.product
    }));
  }

  private normalizePlaybook(raw: unknown): VocPlaybook | null {
    if (!raw || typeof raw !== "object") return null;
    const p = raw as VocPlaybook;
    if (!Array.isArray(p.steps)) return null;
    return {
      version: 1,
      generatedAt: typeof p.generatedAt === "string" ? p.generatedAt : new Date().toISOString(),
      aiGenerated: Boolean(p.aiGenerated),
      contextSummary: typeof p.contextSummary === "string" ? p.contextSummary : null,
      steps: p.steps.map((s) => ({
        id: String(s.id),
        label: String(s.label),
        done: Boolean(s.done),
        doneAt: s.doneAt ?? null,
        doneBy: s.doneBy ?? null
      }))
    };
  }

  private async loadEvidence(caseId: string): Promise<VocCaseEvidenceRow[]> {
    const r = await this.db.query<{
      id: string;
      body: string;
      url: string | null;
      author_email: string | null;
      created_at: Date;
    }>(
      `SELECT id, body, url, author_email, created_at
         FROM voc_case_evidence
        WHERE case_id = $1
        ORDER BY created_at DESC
        LIMIT 80`,
      [caseId]
    );
    return r.rows.map((row) => ({
      id: row.id,
      body: row.body,
      url: row.url,
      authorEmail: row.author_email,
      createdAt: row.created_at.toISOString()
    }));
  }

  private async markPlaybookStep(
    caseId: string,
    stepId: string,
    done: boolean,
    doneBy: string | null
  ) {
    const r = await this.db.query<{ playbook: VocPlaybook | null }>(
      `SELECT playbook FROM voc_case WHERE id = $1`,
      [caseId]
    );
    const playbook = this.normalizePlaybook(r.rows[0]?.playbook);
    if (!playbook) return;
    const step = playbook.steps.find((s) => s.id === stepId);
    if (!step || step.done === done) return;
    step.done = done;
    step.doneAt = done ? new Date().toISOString() : null;
    step.doneBy = done ? doneBy : null;
    await this.db.query(`UPDATE voc_case SET playbook = $2::jsonb WHERE id = $1`, [
      caseId,
      JSON.stringify(playbook)
    ]);
  }

  private async syncTriageOnResolve(caseId: string) {
    const refs = await this.db.query<{ ref_key: string; source: VocSource; ref_id: string }>(
      `SELECT ref_key, source, ref_id FROM voc_case_ref WHERE case_id = $1`,
      [caseId]
    );
    for (const ref of refs.rows) {
      await this.db.query(
        `INSERT INTO voc_triage (ref_key, source, ref_id, status, updated_at)
         VALUES ($1,$2,$3,'done',now())
         ON CONFLICT (ref_key) DO UPDATE
           SET status = 'done', updated_at = now()`,
        [ref.ref_key, ref.source, ref.ref_id]
      );
    }
  }

  private async syncTaskOnResolve(taskId: string, outcome: VocOutcome, notes: string | null) {
    const decision =
      outcome === "accepted_risk"
        ? "risk_accepted"
        : outcome === "not_affected"
          ? "not_applicable"
          : outcome === "patched"
            ? "patched"
            : outcome === "exposed"
              ? "exposed_confirmed"
              : outcome === "monitoring"
                ? "monitoring"
                : "needs_info";

    const evidence = [
      `VOC outcome: ${outcome}`,
      notes ? `Notes: ${notes}` : null
    ]
      .filter(Boolean)
      .join("\n");

    await this.vulnTasks.patch(taskId, {
      status: "closed",
      decision,
      decisionNotes: notes ?? undefined,
      evidence
    });
  }

  /**
   * Create vuln_task for active VOC cases that are missing task_id (orphans after timeouts).
   */
  async backfillMissingTasks(opts?: { limit?: number }): Promise<{
    scanned: number;
    created: number;
    failed: number;
    errors: string[];
  }> {
    const limit = Math.max(1, Math.min(500, opts?.limit ?? 200));
    const r = await this.db.query<{
      id: string;
      title: string;
      voc_priority: VocPriority;
      sla_due_at: Date | null;
      primary_ref_key: string;
    }>(
      `SELECT id, title, voc_priority, sla_due_at, primary_ref_key
         FROM voc_case
        WHERE task_id IS NULL
          AND status IN ('open', 'in_progress')
        ORDER BY updated_at DESC
        LIMIT $1`,
      [limit]
    );

    let created = 0;
    let failed = 0;
    const errors: string[] = [];

    for (const row of r.rows) {
      try {
        const refs = await this.loadRefsForCases([row.id]);
        const refList = refs.get(row.id) ?? [];
        const primary =
          refList.find((x) => x.refKey.toUpperCase() === row.primary_ref_key.toUpperCase()) ??
          refList[0] ??
          this.parsePrimaryRefKey(row.primary_ref_key);
        if (!primary) {
          failed++;
          errors.push(`${row.id}: no ref`);
          continue;
        }
        const linkedCveIds =
          primary.source === "cve"
            ? [primary.refId]
            : refList.filter((x) => x.source === "cve").map((x) => x.refId);
        const slaDueAt =
          row.sla_due_at?.toISOString?.() ?? computeSlaDueAt(row.voc_priority ?? "p4");
        const taskId = await this.ensureTaskForCase(row.id, {
          refKey: primary.refKey,
          source: primary.source,
          refId: primary.refId,
          title: row.title,
          vocPriority: row.voc_priority ?? "p4",
          linkedCveIds,
          slaDueAt
        });
        if (taskId) created++;
        else failed++;
      } catch (e) {
        failed++;
        errors.push(`${row.id}: ${e instanceof Error ? e.message : String(e)}`.slice(0, 200));
      }
    }

    return { scanned: r.rows.length, created, failed, errors: errors.slice(0, 20) };
  }

  private parsePrimaryRefKey(
    primary: string
  ): { refKey: string; source: VocSource; refId: string } | null {
    const raw = String(primary ?? "").trim();
    if (!raw) return null;
    const upper = raw.toUpperCase();
    if (upper.startsWith("CVE:")) {
      const refId = upper.slice(4);
      return { refKey: `CVE:${refId}`, source: "cve", refId };
    }
    if (upper.startsWith("BDU:")) {
      const refId = raw.slice(4);
      return { refKey: `BDU:${refId}`, source: "bdu", refId };
    }
    if (upper.startsWith("TG:")) {
      const refId = raw.slice(3);
      return { refKey: raw, source: "tg", refId };
    }
    if (/^CVE-\d{4}-\d+/i.test(raw)) {
      const refId = raw.toUpperCase();
      return { refKey: `CVE:${refId}`, source: "cve", refId };
    }
    return null;
  }

  private async ensureTaskForCase(
    caseId: string,
    input: {
      refKey: string;
      source: VocSource;
      refId: string;
      title: string;
      subtitle?: string | null;
      vocPriority: VocPriority;
      vocReasons?: string[];
      linkedCveIds: string[];
      vendorKey?: string;
      vendorDisplay?: string;
      productKeyNorm?: string;
      productDisplay?: string;
      tgChannel?: string | null;
      slaDueAt: string;
    }
  ): Promise<string | null> {
    const existing = await this.db.query<{ task_id: string | null }>(
      `SELECT task_id FROM voc_case WHERE id = $1`,
      [caseId]
    );
    if (existing.rows[0]?.task_id) return existing.rows[0].task_id;

    const ctx = await this.resolveTaskContext(input.source, input.refId, input.linkedCveIds, {
      vendorKey: input.vendorKey,
      vendorDisplay: input.vendorDisplay,
      productKeyNorm: input.productKeyNorm,
      productDisplay: input.productDisplay,
      tgChannel: input.tgChannel,
      subtitle: input.subtitle
    });

    const created = await this.vulnTasks.createFromVocCase({
      caseId,
      refKey: input.refKey,
      source: input.source,
      refId: input.refId,
      title: input.title,
      subtitle: input.subtitle ?? ctx.bduName ?? null,
      vocPriority: input.vocPriority,
      vocReasons: input.vocReasons,
      cveIds: ctx.cveIds,
      vendorKey: ctx.vendorKey,
      vendorDisplay: ctx.vendorDisplay,
      productKeyNorm: ctx.productKeyNorm,
      productDisplay: ctx.productDisplay,
      bduName: ctx.bduName,
      tgChannel: ctx.tgChannel,
      dueDate: input.slaDueAt,
      priorityLocal: vocPriorityToTaskPriority(input.vocPriority)
    });

    await this.db.query(`UPDATE voc_case SET task_id = $2, updated_at = now() WHERE id = $1`, [
      caseId,
      created.id
    ]);
    return created.id;
  }

  private async resolveTaskContext(
    source: VocSource,
    refId: string,
    linked: string[],
    hints: {
      vendorKey?: string;
      vendorDisplay?: string;
      productKeyNorm?: string;
      productDisplay?: string;
      tgChannel?: string | null;
      subtitle?: string | null;
    }
  ) {
    let cveIds = this.resolveCveIds(source, refId, linked);
    let vendorKey = hints.vendorKey?.trim().toLowerCase() || "";
    let vendorDisplay = hints.vendorDisplay?.trim() || "";
    let productKeyNorm = hints.productKeyNorm?.trim().toLowerCase() || "";
    let productDisplay = hints.productDisplay?.trim() || "";
    let bduName: string | null = null;
    let tgChannel = hints.tgChannel?.trim() || null;

    if (source === "bdu") {
      const r = await this.db.query<{
        name: string;
        vendors: string | null;
        software_names: string | null;
        cve_ids: string[] | null;
      }>(`SELECT name, vendors, software_names, cve_ids FROM bdu_vuln WHERE bdu_id = $1 LIMIT 1`, [refId]);
      const row = r.rows[0];
      if (row) {
        bduName = row.name || null;
        if (!cveIds.length) {
          cveIds = (row.cve_ids ?? [])
            .map((id) => String(id).trim().toUpperCase())
            .filter((id) => /^CVE-\d{4}-\d+/.test(id));
        }
        if (!cveIds.length) {
          const links = await this.db.query<{ cve_id: string }>(
            `SELECT cve_id FROM cve_bdu_link WHERE bdu_id = $1 ORDER BY cve_id LIMIT 20`,
            [refId]
          );
          cveIds = links.rows.map((x) => x.cve_id.toUpperCase());
        }
        if (!vendorDisplay) {
          vendorDisplay = (row.vendors || row.software_names || "БДУ ФСТЭК").split(/[;,]/)[0]?.trim() || "БДУ ФСТЭК";
        }
      } else if (!vendorDisplay) {
        vendorDisplay = "БДУ ФСТЭК";
      }
    }

    if (source === "tg" && !vendorDisplay) {
      vendorDisplay = tgChannel ? `Telegram / ${tgChannel}` : "Telegram OSINT";
    }

    if (cveIds.length > 0 && (!vendorDisplay || !productDisplay)) {
      const vp = await this.db.query<{ vendor: string | null; product: string | null }>(
        `SELECT vendor, product
           FROM cve_vendor_product
          WHERE cve_id = $1
          ORDER BY updated_at DESC NULLS LAST
          LIMIT 1`,
        [cveIds[0]]
      );
      const row = vp.rows[0];
      if (row) {
        if (!vendorDisplay && row.vendor) vendorDisplay = row.vendor;
        if (!productDisplay && row.product) productDisplay = row.product;
      }
    }

    if (!vendorDisplay) vendorDisplay = source === "cve" ? "CVE/NVD" : source === "bdu" ? "БДУ ФСТЭК" : "VOC";
    if (!vendorKey) vendorKey = vendorDisplay.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 64) || "voc";
    if (!productKeyNorm && productDisplay) productKeyNorm = productDisplay.toLowerCase();

    return { cveIds, vendorKey, vendorDisplay, productKeyNorm, productDisplay, bduName, tgChannel };
  }

  private resolveCveIds(source: VocSource, refId: string, linked: string[]): string[] {
    if (source === "cve") return [refId.toUpperCase()];
    const fromLinked = linked.filter((id) => /^CVE-\d{4}-\d+/i.test(id));
    return fromLinked;
  }

  private async loadRefsForCases(caseIds: string[]) {
    const map = new Map<string, VocCaseRow["refs"]>();
    if (!caseIds.length) return map;

    const r = await this.db.query<{
      case_id: string;
      ref_key: string;
      source: VocSource;
      ref_id: string;
      added_at: Date;
    }>(
      `SELECT case_id, ref_key, source, ref_id, added_at
         FROM voc_case_ref
        WHERE case_id = ANY($1::uuid[])
        ORDER BY added_at ASC`,
      [caseIds]
    );

    for (const row of r.rows) {
      const list = map.get(row.case_id) ?? [];
      list.push({
        refKey: row.ref_key,
        source: row.source,
        refId: row.ref_id,
        addedAt: row.added_at.toISOString()
      });
      map.set(row.case_id, list);
    }
    return map;
  }
}

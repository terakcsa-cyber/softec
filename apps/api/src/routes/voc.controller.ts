import { Body, Controller, Delete, Get, Param, Patch, Post, Query } from "@nestjs/common";
import type { VocAlertCondition, VocCaseStatus, VocOutcome, VocPriority, VocSource, VocTriageStatus, VocWatchlistKind } from "@vuln-intel/shared";
import { CurrentUser } from "../auth/current-user.decorator.js";
import type { AuthUser } from "../auth/jwt.strategy.js";
import { VocCaseService } from "../services/voc-case.service.js";
import { VocShiftService } from "../services/voc-shift.service.js";
import { VocService, type VocQueueItem } from "../services/voc.service.js";

@Controller("voc")
export class VocController {
  constructor(
    private readonly voc: VocService,
    private readonly vocCases: VocCaseService,
    private readonly vocShift: VocShiftService
  ) {}

  @Get("queue")
  async queue(
    @Query("source") source?: string,
    @Query("status") status?: string,
    @Query("limit") limitRaw?: string
  ): Promise<{ items: VocQueueItem[]; stats: Record<string, number> }> {
    return this.voc.queue({
      source,
      status,
      limit: limitRaw ? Number(limitRaw) : undefined
    });
  }

  @Get("triage")
  async listTriage(@Query("source") source?: string, @Query("limit") limitRaw?: string) {
    return this.voc.listTriage({
      source,
      limit: limitRaw ? Number(limitRaw) : undefined
    });
  }

  @Patch("triage")
  async patchTriage(
    @CurrentUser() user: AuthUser,
    @Body()
    body: {
      refKey?: string;
      source?: VocSource;
      refId?: string;
      status?: VocTriageStatus;
      title?: string;
      vocScore?: number;
      vocPriority?: VocPriority;
      vocReasons?: string[];
      meta?: Record<string, unknown>;
    }
  ) {
    return this.voc.upsertTriage(user, {
      refKey: String(body.refKey ?? ""),
      source: body.source ?? "cve",
      refId: String(body.refId ?? ""),
      status: body.status ?? "open",
      title: body.title,
      vocScore: body.vocScore,
      vocPriority: body.vocPriority,
      vocReasons: body.vocReasons,
      meta: body.meta
    });
  }

  @Get("watchlist")
  async listWatchlist() {
    return this.voc.listWatchlist();
  }

  @Post("watchlist")
  async addWatchlist(
    @CurrentUser() user: AuthUser,
    @Body() body: { kind?: VocWatchlistKind; value?: string; label?: string }
  ) {
    return this.voc.addWatchlist(user, body);
  }

  @Patch("watchlist/:id")
  async updateWatchlist(
    @Param("id") id: string,
    @Body() body: { active?: boolean; label?: string }
  ) {
    return this.voc.updateWatchlist(id, body);
  }

  @Delete("watchlist/:id")
  async removeWatchlist(@Param("id") id: string) {
    return this.voc.removeWatchlist(id);
  }

  @Get("cases")
  async listCases(@Query("status") status?: string, @Query("limit") limitRaw?: string) {
    return this.vocCases.listCases({
      status,
      limit: limitRaw ? Number(limitRaw) : undefined
    });
  }

  @Get("cases/by-ref")
  async listCasesByRef(
    @Query("source") source?: string,
    @Query("refId") refId?: string,
    @Query("limit") limitRaw?: string
  ) {
    return this.vocCases.listCasesByRef({
      source: (source ?? "cve") as VocSource,
      refId: String(refId ?? ""),
      limit: limitRaw ? Number(limitRaw) : undefined
    });
  }

  @Post("cases/from-ref")
  async createCaseFromRef(
    @CurrentUser() user: AuthUser,
    @Body()
    body: {
      refKey?: string;
      source?: VocSource;
      refId?: string;
      title?: string;
      vocPriority?: VocPriority;
      vocReasons?: string[];
      linkedCveIds?: string[];
      subtitle?: string | null;
      tgChannel?: string | null;
      assigneeEmail?: string | null;
      createTask?: boolean;
      vendorKey?: string;
      vendorDisplay?: string;
      productKeyNorm?: string;
      productDisplay?: string;
    }
  ) {
    return this.vocCases.createFromRef(user, {
      refKey: String(body.refKey ?? ""),
      source: body.source ?? "cve",
      refId: String(body.refId ?? ""),
      title: String(body.title ?? ""),
      vocPriority: body.vocPriority,
      vocReasons: body.vocReasons,
      linkedCveIds: body.linkedCveIds,
      subtitle: body.subtitle,
      tgChannel: body.tgChannel,
      assigneeEmail: body.assigneeEmail,
      createTask: body.createTask,
      vendorKey: body.vendorKey,
      vendorDisplay: body.vendorDisplay,
      productKeyNorm: body.productKeyNorm,
      productDisplay: body.productDisplay
    });
  }

  @Patch("cases/:id")
  async patchCase(
    @CurrentUser() user: AuthUser,
    @Param("id") id: string,
    @Body()
    body: {
      status?: VocCaseStatus;
      assigneeEmail?: string | null;
      slaDueAt?: string | null;
      title?: string;
    }
  ) {
    return this.vocCases.patchCase(user, id, body);
  }

  @Get("cases/:id")
  async getCase(@Param("id") id: string) {
    return this.vocCases.getCaseById(id, { withEvidence: true });
  }

  @Post("cases/:id/evidence")
  async addCaseEvidence(
    @CurrentUser() user: AuthUser,
    @Param("id") id: string,
    @Body() body: { body?: string; url?: string | null }
  ) {
    return this.vocCases.addEvidence(user, id, body);
  }

  @Patch("cases/:id/playbook")
  async patchCasePlaybook(
    @CurrentUser() user: AuthUser,
    @Param("id") id: string,
    @Body() body: { stepId?: string; done?: boolean }
  ) {
    return this.vocCases.patchPlaybookStep(user, id, body);
  }

  @Post("cases/:id/playbook/regenerate")
  async regenerateCasePlaybook(@Param("id") id: string) {
    return this.vocCases.regeneratePlaybook(id);
  }

  @Post("cases/:id/resolve")
  async resolveCase(
    @CurrentUser() user: AuthUser,
    @Param("id") id: string,
    @Body() body: { outcome?: string; notes?: string | null }
  ) {
    return this.vocCases.resolveCase(user, id, {
      outcome: body.outcome as VocOutcome,
      notes: body.notes
    });
  }

  @Get("kpis")
  async kpis(@Query("hours") hoursRaw?: string) {
    return this.vocShift.kpis(hoursRaw ? Number(hoursRaw) : 8);
  }

  @Post("handover")
  async handover(
    @CurrentUser() user: AuthUser,
    @Body() body: { hours?: number; notes?: string | null }
  ) {
    return this.vocShift.handover(user, body.hours ?? 8, body.notes);
  }

  @Get("alert-rules")
  async listAlertRules() {
    return this.vocShift.listAlertRules();
  }

  @Post("alert-rules")
  async addAlertRule(
    @Body()
    body: {
      name?: string;
      condition?: VocAlertCondition;
      channel?: "telegram" | "webhook";
      webhookUrl?: string | null;
    }
  ) {
    return this.vocShift.addAlertRule(body);
  }

  @Patch("alert-rules/:id")
  async patchAlertRule(
    @Param("id") id: string,
    @Body() body: { active?: boolean; name?: string; webhookUrl?: string | null }
  ) {
    return this.vocShift.patchAlertRule(id, body);
  }

  @Delete("alert-rules/:id")
  async removeAlertRule(@Param("id") id: string) {
    return this.vocShift.removeAlertRule(id);
  }

  @Post("alerts/evaluate")
  async evaluateAlerts() {
    return this.vocShift.evaluateAlerts();
  }
}

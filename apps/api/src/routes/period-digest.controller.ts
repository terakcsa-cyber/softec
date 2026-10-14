import { BadRequestException, Body, Controller, Get, Header, Param, Post, StreamableFile } from "@nestjs/common";
import type { AuthUser } from "../auth/jwt.strategy.js";
import { CurrentUser } from "../auth/current-user.decorator.js";
import { MonthlyDigestHistoryService } from "../services/monthly-digest-history.service.js";
import { OpenMonthDigestService } from "../services/open-month-digest.service.js";
import { PeriodDigestPdfService } from "../services/period-digest-pdf.service.js";

@Controller("stats")
export class PeriodDigestController {
  constructor(
    private readonly pdf: PeriodDigestPdfService,
    private readonly openMonth: OpenMonthDigestService,
    private readonly history: MonthlyDigestHistoryService
  ) {}

  @Post("monthly-digest/preview")
  @Header("Cache-Control", "no-store")
  async monthlyPreview(@Body() body: unknown, @CurrentUser() _user: AuthUser) {
    const { year, month } = readMonth(body);
    return this.openMonth.preview(year, month);
  }

  @Post("monthly-digest/pdf")
  @Header("Cache-Control", "no-store")
  async monthlyPdf(@Body() body: unknown, @CurrentUser() user: AuthUser): Promise<StreamableFile> {
    const built = await this.openMonth.pdf(body, user.email);
    await this.history.remember(user.userId, body, built);
    return new StreamableFile(built.buffer, {
      type: "application/pdf",
      disposition: `attachment; filename="${built.filename}"`,
      length: built.buffer.length
    });
  }

  @Get("monthly-digest/history")
  @Header("Cache-Control", "no-store")
  monthlyHistory(@CurrentUser() user: AuthUser) {
    return this.history.list(user.userId);
  }

  @Get("monthly-digest/history/:id")
  @Header("Cache-Control", "no-store")
  async monthlyHistoryFile(@Param("id") id: string, @CurrentUser() user: AuthUser): Promise<StreamableFile> {
    const file = await this.history.read(user.userId, id);
    return new StreamableFile(file.buffer, {
      type: "application/pdf",
      disposition: `attachment; filename="${file.filename}"`,
      length: file.buffer.length
    });
  }

  @Post("period-digest/pdf")
  @Header("Cache-Control", "no-store")
  async periodDigestPdf(@Body() body: unknown, @CurrentUser() user: AuthUser): Promise<StreamableFile> {
    const built = await this.pdf.build(body, user.email);
    return new StreamableFile(built.buffer, {
      type: "application/pdf",
      disposition: `attachment; filename="${built.filename}"`,
      length: built.buffer.length
    });
  }
}

function readMonth(body: unknown): { year: number; month: number } {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new BadRequestException("Нужен месяц");
  const raw = body as Record<string, unknown>;
  const year = Number(raw.year);
  const month = Number(raw.month);
  if (!Number.isInteger(year) || !Number.isInteger(month)) throw new BadRequestException("Нужен месяц");
  return { year, month };
}

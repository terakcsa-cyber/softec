import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpException,
  HttpStatus,
  Param,
  Post,
  Query
} from "@nestjs/common";
import { FstecBulletinService } from "../services/fstec-bulletin.service.js";

@Controller("fstec/bulletins")
export class FstecBulletinController {
  constructor(private readonly bulletins: FstecBulletinService) {}

  @Get()
  list(@Query("limit") limit?: string, @Query("offset") offset?: string) {
    const lim = Math.min(100, Math.max(1, Number(limit) || 30));
    const off = Math.max(0, Number(offset) || 0);
    return this.bulletins.list(lim, off);
  }

  @Get(":id")
  get(@Param("id") id: string) {
    return this.bulletins.getById(id);
  }

  @Delete(":id")
  async remove(@Param("id") id: string) {
    return this.bulletins.deleteById(id);
  }

  @Post()
  @HttpCode(201)
  async create(
    @Body()
    body: {
      plainText?: string;
      title?: string | null;
      referenceNo?: string | null;
      sourceFilename?: string | null;
    }
  ) {
    const text = typeof body.plainText === "string" ? body.plainText.trim() : "";
    if (text.length < 80) {
      throw new BadRequestException({ ok: false, error: "plainText too short (min 80 chars)" });
    }
    try {
      return await this.bulletins.createFromPlainText({
        plainText: text,
        title: body.title ?? null,
        referenceNo: body.referenceNo ?? null,
        sourceFilename: body.sourceFilename ?? null
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new HttpException({ ok: false, error: msg.slice(0, 2000) }, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Post(":id/analyze")
  @HttpCode(202)
  analyze(@Param("id") id: string, @Body() body?: { force?: boolean }) {
    return this.bulletins.scheduleAnalyze(id, { force: Boolean(body?.force) });
  }
}

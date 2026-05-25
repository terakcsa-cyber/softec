import { BadRequestException, Body, Controller, HttpCode, Param, Post } from "@nestjs/common";
import { TelegramPostService } from "../services/telegram-post.service.js";

type TelegramPostBody = { status?: string };

@Controller("telegram")
export class TelegramController {
  constructor(private readonly telegram: TelegramPostService) {}

  private requireStatus(body: TelegramPostBody | undefined): string {
    const s = body?.status?.trim();
    if (!s) throw new BadRequestException("Укажите статус (поле status) перед публикацией");
    return s;
  }

  @Post("post/cve/:cveId")
  @HttpCode(200)
  postCve(@Param("cveId") cveId: string, @Body() body: TelegramPostBody) {
    return this.telegram.postCve(cveId, this.requireStatus(body));
  }

  @Post("post/bdu/:bduId")
  @HttpCode(200)
  postBdu(@Param("bduId") bduId: string, @Body() body: TelegramPostBody) {
    return this.telegram.postBdu(bduId, this.requireStatus(body));
  }
}

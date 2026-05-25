import { Body, Controller, Get, HttpCode, Post, Put } from "@nestjs/common";
import { IntegrationSettingsService } from "../services/integration-settings.service.js";
import { MpvmSyncService } from "../services/mpvm-sync.service.js";
import { TelegramPostService } from "../services/telegram-post.service.js";

@Controller("settings/integrations")
export class IntegrationSettingsController {
  constructor(
    private readonly integration: IntegrationSettingsService,
    private readonly mpvmSync: MpvmSyncService,
    private readonly telegram: TelegramPostService
  ) {}

  @Get()
  getState() {
    return this.integration.getUiState();
  }

  @Put()
  putState(@Body() body: unknown) {
    return this.integration.updateFromUi(body);
  }

  /** Проверить черновик или сохранённый ключ NVD без записи в БД (если apiKey не передан). */
  @Post("nvd/verify")
  verifyNvd(@Body() body: unknown) {
    const key =
      body != null && typeof body === "object" && !Array.isArray(body) && "apiKey" in body
        ? (body as { apiKey?: unknown }).apiKey
        : undefined;
    if (key != null && typeof key !== "string") {
      return { ok: false, error: "apiKey must be a string" };
    }
    return this.integration.verifyNvdApiKey(typeof key === "string" ? key : undefined);
  }

  @Post("mpvm/verify")
  verifyMpvm(@Body() body: unknown) {
    const o = body != null && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : {};
    return this.integration.verifyMpvm({
      baseUrl: typeof o.baseUrl === "string" ? o.baseUrl : undefined,
      username: typeof o.username === "string" ? o.username : undefined,
      apiToken: typeof o.apiToken === "string" ? o.apiToken : undefined,
      password: typeof o.password === "string" ? o.password : undefined,
      clientSecret: typeof o.clientSecret === "string" ? o.clientSecret : undefined,
      tlsInsecure: o.tlsInsecure === true,
      pdql: typeof o.pdql === "string" ? o.pdql : undefined
    });
  }

  @Post("mpvm/sync")
  @HttpCode(200)
  syncMpvm() {
    return this.mpvmSync.syncAssets();
  }

  @Post("telegram/verify")
  verifyTelegram(@Body() body: unknown) {
    const o = body != null && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : {};
    return this.telegram.verify({
      botToken: typeof o.botToken === "string" ? o.botToken : undefined,
      chatId: typeof o.chatId === "string" ? o.chatId : undefined
    });
  }
}

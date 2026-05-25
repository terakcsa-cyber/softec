import { Global, Module } from "@nestjs/common";
import { IntegrationSettingsService } from "../services/integration-settings.service.js";
import { LlmService } from "../services/llm.service.js";

@Global()
@Module({
  providers: [IntegrationSettingsService, LlmService],
  exports: [LlmService]
})
export class LlmModule {}


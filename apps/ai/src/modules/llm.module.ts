import { Global, Module } from "@nestjs/common";
import { LlmService } from "../services/llm.service.js";

@Global()
@Module({
  providers: [LlmService],
  exports: [LlmService]
})
export class LlmModule {}


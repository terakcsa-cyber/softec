import { Controller, Get } from "@nestjs/common";
import { Public } from "../auth/public.decorator.js";

@Controller("health")
export class HealthController {
  @Public()
  @Get()
  get() {
    return { ok: true };
  }
}


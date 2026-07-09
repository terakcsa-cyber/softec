import { Controller, Get } from "@nestjs/common";
import { SkipThrottle } from "@nestjs/throttler";
import { Public } from "../auth/public.decorator.js";

@Controller("health")
@SkipThrottle()
export class HealthController {
  @Public()
  @Get()
  get() {
    return { ok: true };
  }
}


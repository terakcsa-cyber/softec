import { Controller, Get, HttpCode, Post } from "@nestjs/common";
import { Roles } from "../auth/roles.decorator.js";
import { UserRole } from "@vuln-intel/shared";
import { PlatformUpdateService } from "../services/platform-update.service.js";

@Controller("settings/updates")
@Roles(UserRole.Admin)
export class PlatformUpdateController {
  constructor(private readonly updates: PlatformUpdateService) {}

  @Get()
  status() {
    return this.updates.getStatus();
  }

  @Post("check")
  @HttpCode(200)
  check() {
    return this.updates.check();
  }

  @Post("apply")
  @HttpCode(200)
  apply() {
    return this.updates.apply();
  }
}

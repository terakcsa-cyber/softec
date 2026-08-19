import { Body, Controller, Get, HttpCode, Post } from "@nestjs/common";
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

  @Get("storage")
  storage() {
    return this.updates.getStorage();
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

  @Post("cleanup")
  @HttpCode(200)
  cleanup(
    @Body()
    body?: {
      keepBackups?: number;
      pruneDocker?: boolean;
      mode?: "backups" | "machine";
    }
  ) {
    return this.updates.cleanupStorage({
      keepBackups: typeof body?.keepBackups === "number" ? body.keepBackups : undefined,
      pruneDocker: body?.pruneDocker === true,
      mode: body?.mode === "machine" ? "machine" : "backups"
    });
  }

  @Post("cards-refresh")
  @HttpCode(200)
  refreshCards() {
    return this.updates.refreshCardTemplates();
  }
}

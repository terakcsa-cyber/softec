import { Body, Controller, Get, HttpCode, Post } from "@nestjs/common";
import { Roles } from "../auth/roles.decorator.js";
import { UserRole } from "@vuln-intel/shared";
import { WebTlsService } from "../services/web-tls.service.js";

@Controller("settings/tls")
@Roles(UserRole.Admin)
export class WebTlsController {
  constructor(private readonly tls: WebTlsService) {}

  @Get()
  getStatus() {
    return this.tls.getStatus();
  }

  @Post("generate")
  @HttpCode(200)
  generate(
    @Body()
    body: {
      domain?: string;
      days?: number;
      extraSans?: string[];
    }
  ) {
    return this.tls.generateAndApply({
      domain: typeof body?.domain === "string" ? body.domain : undefined,
      days: typeof body?.days === "number" ? body.days : undefined,
      extraSans: Array.isArray(body?.extraSans)
        ? body.extraSans.filter((s): s is string => typeof s === "string")
        : undefined
    });
  }

  @Post("letsencrypt")
  @HttpCode(200)
  letsencrypt(
    @Body()
    body: {
      domain?: string;
      email?: string;
      staging?: boolean;
    }
  ) {
    const email = typeof body?.email === "string" ? body.email : "";
    return this.tls.issueLetsEncrypt({
      domain: typeof body?.domain === "string" ? body.domain : undefined,
      email,
      staging: body?.staging === true
    });
  }

  @Post("letsencrypt/renew")
  @HttpCode(200)
  renewLetsencrypt() {
    return this.tls.renewLetsEncrypt();
  }
}

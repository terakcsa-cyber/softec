import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  Patch,
  Post
} from "@nestjs/common";
import { AuthService } from "./auth.service.js";
import { CurrentUser } from "./current-user.decorator.js";
import { Public } from "./public.decorator.js";
import type { AuthUser } from "./jwt.strategy.js";
import { Roles } from "./roles.decorator.js";
import { UserRole } from "@vuln-intel/shared";

@Controller("auth")
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Public()
  @Get("setup")
  async setupStatus() {
    return this.auth.setupStatus();
  }

  @Public()
  @Post("setup")
  @HttpCode(200)
  async setupFirstAdmin(@Body() body: { email?: string; password?: string }) {
    if (!body.email || !body.password) {
      throw new BadRequestException("email and password required");
    }
    return this.auth.setupFirstAdmin(body.email, body.password);
  }

  @Public()
  @Post("register")
  async register(@Body() body: { email?: string; password?: string }) {
    if (!body.email || !body.password) {
      throw new BadRequestException("email and password required");
    }
    return this.auth.register(body.email, body.password);
  }

  @Public()
  @Post("login")
  @HttpCode(200)
  async login(@Body() body: { email?: string; password?: string }) {
    if (!body.email || !body.password) {
      throw new BadRequestException("email and password required");
    }
    return this.auth.login(body.email, body.password);
  }

  @Public()
  @Post("login/totp")
  @HttpCode(200)
  async loginTotp(@Body() body: { pendingToken?: string; code?: string }) {
    if (!body.pendingToken || !body.code) {
      throw new BadRequestException("pendingToken and code required");
    }
    return this.auth.completeLoginWithTotp(body.pendingToken, body.code);
  }

  @Public()
  @Post("refresh")
  @HttpCode(200)
  async refresh(@Body() body: { refreshToken?: string }) {
    if (!body.refreshToken) {
      throw new BadRequestException("refreshToken required");
    }
    return this.auth.refresh(body.refreshToken);
  }

  @Post("logout")
  @HttpCode(200)
  async logout(
    @CurrentUser() user: AuthUser,
    @Body() body: { refreshToken?: string }
  ) {
    return this.auth.logout(user.userId, body.refreshToken);
  }

  @Get("me")
  async me(@CurrentUser() user: AuthUser) {
    return this.auth.me(user.userId);
  }

  @Post("change-password")
  @HttpCode(200)
  async changePassword(
    @CurrentUser() user: AuthUser,
    @Body() body: { currentPassword?: string; newPassword?: string }
  ) {
    if (!body.newPassword) throw new BadRequestException("newPassword required");
    return this.auth.changePassword(user.userId, body.currentPassword, body.newPassword);
  }

  @Roles(UserRole.Admin)
  @Get("users")
  async listUsers() {
    return this.auth.listUsers();
  }

  @Roles(UserRole.Admin)
  @Post("users")
  async createUser(
    @Body()
    body: {
      email?: string;
      password?: string;
      role?: string;
      enabled?: boolean;
      mustChangePassword?: boolean;
    }
  ) {
    return this.auth.createUser(body);
  }

  @Roles(UserRole.Admin)
  @Patch("users/:id")
  async updateUser(
    @CurrentUser() user: AuthUser,
    @Param("id") id: string,
    @Body() body: { email?: string; role?: string; enabled?: boolean; mustChangePassword?: boolean }
  ) {
    return this.auth.updateUser(user.userId, id, body);
  }

  @Roles(UserRole.Admin)
  @Post("users/:id/reset-password")
  @HttpCode(200)
  async resetUserPassword(
    @Param("id") id: string,
    @Body() body: { password?: string; mustChangePassword?: boolean }
  ) {
    if (!body.password) throw new BadRequestException("password required");
    return this.auth.resetUserPassword(id, body.password, body.mustChangePassword !== false);
  }

  @Post("2fa/setup")
  @HttpCode(200)
  async setupTotp(@CurrentUser() user: AuthUser) {
    return this.auth.setupTotp(user.userId);
  }

  @Post("2fa/enable")
  @HttpCode(200)
  async enableTotp(@CurrentUser() user: AuthUser, @Body() body: { code?: string }) {
    if (!body.code) throw new BadRequestException("code required");
    return this.auth.enableTotp(user.userId, body.code);
  }

  @Post("2fa/disable")
  @HttpCode(200)
  async disableTotp(
    @CurrentUser() user: AuthUser,
    @Body() body: { password?: string; code?: string }
  ) {
    if (!body.password || !body.code) {
      throw new BadRequestException("password and code required");
    }
    return this.auth.disableTotp(user.userId, body.password, body.code);
  }
}

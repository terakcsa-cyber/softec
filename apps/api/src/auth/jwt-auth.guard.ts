import { ExecutionContext, Injectable } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { AuthGuard } from "@nestjs/passport";
import type { Request } from "express";
import { IS_PUBLIC_KEY } from "./public.decorator.js";
import type { AuthUser } from "./jwt.strategy.js";

@Injectable()
export class JwtAuthGuard extends AuthGuard("jwt") {
  constructor(private readonly reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass()
    ]);
    if (isPublic) return true;

    const req = context.switchToHttp().getRequest<Request>();
    const internal = process.env.INTERNAL_API_BEARER?.trim();
    const auth = req.headers.authorization?.trim();
    const allowInternalBearer =
      process.env.NODE_ENV !== "production" ||
      process.env.ALLOW_INTERNAL_API_BEARER?.trim().toLowerCase() === "true";
    if (allowInternalBearer && internal && auth === `Bearer ${internal}`) {
      (req as Request & { user: AuthUser }).user = {
        userId: "internal",
        email: "internal@system"
      };
      return true;
    }

    return super.canActivate(context);
  }
}

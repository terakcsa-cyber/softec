import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { UserRole, canWriteData, parseUserRole } from "@vuln-intel/shared";
import type { AuthUser } from "./jwt.strategy.js";
import { IS_PUBLIC_KEY } from "./public.decorator.js";

const READ_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

@Injectable()
export class WriteRoleGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass()
    ]);
    if (isPublic) return true;

    const req = context.switchToHttp().getRequest<{ method?: string; user?: AuthUser }>();
    const method = String(req.method ?? "GET").toUpperCase();
    if (READ_METHODS.has(method)) return true;

    const user = req.user;
    if (!user || user.userId === "internal") return true;

    const role = parseUserRole(user.role, UserRole.Analyst);
    if (!canWriteData(role)) {
      throw new ForbiddenException("read-only role");
    }
    return true;
  }
}

import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { UserRole, isAdminUser, parseUserRole } from "@vuln-intel/shared";
import type { AuthUser } from "./jwt.strategy.js";
import { ROLES_KEY } from "./roles.decorator.js";

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<UserRole[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass()
    ]);
    if (!required?.length) return true;

    const req = context.switchToHttp().getRequest<{ user?: AuthUser }>();
    const user = req.user;
    if (!user) throw new ForbiddenException();

    const role = parseUserRole(user.role, UserRole.Analyst);

    if (required.includes(UserRole.Admin)) {
      if (
        isAdminUser({
          userId: user.userId,
          email: user.email,
          role: user.role,
          adminEmailsEnv: process.env.ADMIN_EMAILS
        })
      ) {
        return true;
      }
      throw new ForbiddenException("admin only");
    }

    if (!required.includes(role)) {
      throw new ForbiddenException("insufficient role");
    }
    return true;
  }
}

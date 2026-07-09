import { Injectable, UnauthorizedException } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import type { Request } from "express";
import { ExtractJwt, Strategy } from "passport-jwt";
import { UserRole, parseUserRole } from "@vuln-intel/shared";

export type AuthUser = { userId: string; email: string; role: UserRole };

type AccessPayload = {
  sub: string;
  email: string;
  role?: string;
  typ: string;
};

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, "jwt") {
  constructor() {
    const secret = process.env.JWT_SECRET?.trim();
    if (!secret || secret.length < 32) {
      throw new Error("JWT_SECRET must be set and at least 32 characters");
    }
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: secret,
      passReqToCallback: true
    });
  }

  validate(_req: Request, payload: AccessPayload): AuthUser {
    if (payload.typ !== "access") {
      throw new UnauthorizedException();
    }
    return {
      userId: payload.sub,
      email: payload.email,
      role: parseUserRole(payload.role, UserRole.Analyst)
    };
  }
}

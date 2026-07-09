import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  Logger,
  OnApplicationBootstrap,
  UnauthorizedException
} from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import argon2 from "argon2";
import { generateSecret, verifySync } from "otplib";
import QRCode from "qrcode";
import { DbService } from "../services/db.service.js";
import { UserRole, parseUserRole } from "@vuln-intel/shared";

const ACCESS_TTL_SEC = 60 * 15;
const REFRESH_TTL_SEC = 60 * 60 * 24 * 7;
const PENDING_TOTP_TTL_SEC = 60 * 5;

function sha256Hex(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

function timingSafeEqualHex(a: string, b: string): boolean {
  try {
    const ba = Buffer.from(a, "hex");
    const bb = Buffer.from(b, "hex");
    if (ba.length !== bb.length) return false;
    return timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}

type UserRow = {
  id: string;
  email: string;
  password_hash: string;
  totp_secret: string | null;
  totp_pending_secret: string | null;
  totp_enabled: boolean;
  role: string;
};

function normalizeEmail(emailRaw: string): string {
  const email = emailRaw.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new BadRequestException("Invalid email");
  }
  return email;
}

function assertPasswordPolicy(password: string): void {
  if (password.length < 12) {
    throw new BadRequestException("Password must be at least 12 characters");
  }
}

@Injectable()
export class AuthService implements OnApplicationBootstrap {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly db: DbService,
    private readonly jwt: JwtService
  ) {}

  async onApplicationBootstrap() {
    await this.bootstrapFirstUserIfEmpty();
  }

  private async bootstrapFirstUserIfEmpty() {
    const email = process.env.AUTH_BOOTSTRAP_EMAIL?.trim().toLowerCase();
    const password = process.env.AUTH_BOOTSTRAP_PASSWORD;
    if (!email || !password) return;
    if (password.length < 12) {
      throw new Error("AUTH_BOOTSTRAP_PASSWORD must be at least 12 characters");
    }

    const n = await this.db.query<{ c: string }>(
      `SELECT COUNT(*)::text AS c FROM auth_user`
    );
    if (Number(n.rows[0]?.c ?? "0") > 0) return;

    const hash = await argon2.hash(password, { type: argon2.argon2id });
    try {
      await this.db.query(
        `INSERT INTO auth_user (email, password_hash, role) VALUES ($1, $2, $3)`,
        [email, hash, UserRole.Admin]
      );
      this.logger.log(`Bootstrap: created first user ${email}`);
    } catch (e: unknown) {
      const err = e as { code?: string };
      if (err.code === "23505") return;
      throw e;
    }
  }

  async setupStatus() {
    return { required: await this.isInitialSetupRequired() };
  }

  async setupFirstAdmin(emailRaw: string, password: string) {
    const email = normalizeEmail(emailRaw);
    assertPasswordPolicy(password);
    const hash = await argon2.hash(password, { type: argon2.argon2id });
    const inserted = await this.db.query<UserRow>(
      `INSERT INTO auth_user (email, password_hash, role)
       SELECT $1, $2, $3
        WHERE NOT EXISTS (SELECT 1 FROM auth_user)
       RETURNING id, email, password_hash, totp_secret, totp_pending_secret, totp_enabled, role`,
      [email, hash, UserRole.Admin]
    );
    const row = inserted.rows[0];
    if (!row) {
      throw new ForbiddenException("Initial setup is already completed");
    }
    this.logger.log(`Initial setup: created admin user ${email}`);
    return { setupCompleted: true as const, ...(await this.issueTokenPair(row)) };
  }

  async register(emailRaw: string, password: string) {
    if (process.env.AUTH_ALLOW_REGISTER?.trim() !== "true") {
      throw new ForbiddenException("Registration is disabled");
    }
    if (
      process.env.NODE_ENV === "production" &&
      process.env.AUTH_ALLOW_REGISTER_IN_PRODUCTION?.trim().toLowerCase() !== "true"
    ) {
      throw new ForbiddenException("Registration is disabled in production");
    }
    const email = normalizeEmail(emailRaw);
    assertPasswordPolicy(password);
    const hash = await argon2.hash(password, { type: argon2.argon2id });
    try {
      await this.db.query(
        `INSERT INTO auth_user (email, password_hash, role) VALUES ($1, $2, $3)`,
        [email, hash, UserRole.Analyst]
      );
    } catch (e: unknown) {
      const err = e as { code?: string };
      if (err.code === "23505") {
        throw new BadRequestException("Email already registered");
      }
      throw e;
    }
    return { ok: true };
  }

  async login(emailRaw: string, password: string) {
    const email = emailRaw.trim().toLowerCase();
    const row = await this.findUserByEmail(email);
    if (!row) throw new UnauthorizedException("Invalid credentials");
    const ok = await argon2.verify(row.password_hash, password);
    if (!ok) throw new UnauthorizedException("Invalid credentials");

    if (row.totp_enabled) {
      const pendingToken = await this.signPendingTotp(row.id);
      return { requiresTotp: true as const, pendingToken };
    }
    return { requiresTotp: false as const, ...(await this.issueTokenPair(row)) };
  }

  async completeLoginWithTotp(pendingToken: string, code: string) {
    let sub: string;
    try {
      const secret = process.env.JWT_SECRET?.trim();
      if (!secret) throw new Error("no secret");
      const decoded = await this.jwt.verifyAsync<{ sub: string; typ: string }>(
        pendingToken,
        { secret }
      );
      if (decoded.typ !== "pending_totp") {
        throw new UnauthorizedException();
      }
      sub = decoded.sub;
    } catch {
      throw new UnauthorizedException("Invalid or expired second step");
    }

    const row = await this.findUserById(sub);
    if (!row?.totp_enabled || !row.totp_secret) {
      throw new UnauthorizedException();
    }
    const v = verifySync({
      secret: row.totp_secret,
      token: code.replace(/\s/g, ""),
      epochTolerance: 30
    });
    if (!v.valid) throw new UnauthorizedException("Invalid authenticator code");

    return this.issueTokenPair(row);
  }

  async refresh(refreshTokenRaw: string) {
    const refreshToken = refreshTokenRaw?.trim();
    if (!refreshToken) throw new UnauthorizedException();
    const tokenHash = sha256Hex(refreshToken);
    const res = await this.db.query<{
      id: string;
      user_id: string;
      expires_at: Date;
    }>(
      `SELECT id, user_id, expires_at
         FROM refresh_token
        WHERE token_hash = $1
          AND revoked_at IS NULL`,
      [tokenHash]
    );
    const rt = res.rows[0];
    if (!rt) throw new UnauthorizedException();
    if (rt.expires_at.getTime() < Date.now()) {
      await this.db.query(`UPDATE refresh_token SET revoked_at = now() WHERE id = $1`, [
        rt.id
      ]);
      throw new UnauthorizedException();
    }

    const user = await this.findUserById(rt.user_id);
    if (!user) throw new UnauthorizedException();

    await this.db.query(`UPDATE refresh_token SET revoked_at = now() WHERE id = $1`, [
      rt.id
    ]);
    return this.issueTokenPair(user);
  }

  async logout(userId: string, refreshTokenRaw?: string) {
    if (refreshTokenRaw?.trim()) {
      const tokenHash = sha256Hex(refreshTokenRaw.trim());
      await this.db.query(
        `UPDATE refresh_token
            SET revoked_at = now()
          WHERE token_hash = $1
            AND user_id = $2
            AND revoked_at IS NULL`,
        [tokenHash, userId]
      );
    } else {
      await this.db.query(
        `UPDATE refresh_token SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
        [userId]
      );
    }
    return { ok: true };
  }

  async me(userId: string): Promise<{
    id: string;
    email: string;
    totpEnabled: boolean;
    role: UserRole;
  }> {
    if (userId === "internal") {
      return {
        id: "internal",
        email: "internal@system",
        totpEnabled: false,
        role: UserRole.Admin
      };
    }
    const row = await this.findUserById(userId);
    if (!row) throw new UnauthorizedException();
    return {
      id: row.id,
      email: row.email,
      totpEnabled: row.totp_enabled,
      role: parseUserRole(row.role, UserRole.Analyst)
    };
  }

  async setupTotp(userId: string) {
    if (userId === "internal") throw new ForbiddenException();
    const row = await this.findUserById(userId);
    if (!row) throw new UnauthorizedException();
    const secret = generateSecret();
    await this.db.query(`UPDATE auth_user SET totp_pending_secret = $2 WHERE id = $1`, [
      userId,
      secret
    ]);
    const label = encodeURIComponent(row.email);
    const issuer = encodeURIComponent(process.env.AUTH_TOTP_ISSUER?.trim() || "VulnIntel");
    const otpauthUrl = `otpauth://totp/${issuer}:${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
    const qrDataUrl = await QRCode.toDataURL(otpauthUrl);
    return { secret, otpauthUrl, qrDataUrl };
  }

  async enableTotp(userId: string, code: string) {
    if (userId === "internal") throw new ForbiddenException();
    const row = await this.findUserById(userId);
    if (!row?.totp_pending_secret) {
      throw new BadRequestException("Run POST /auth/2fa/setup first");
    }
    const vr = verifySync({
      secret: row.totp_pending_secret,
      token: code.replace(/\s/g, ""),
      epochTolerance: 30
    });
    if (!vr.valid) throw new BadRequestException("Invalid code");
    await this.db.query(
      `UPDATE auth_user
          SET totp_secret = totp_pending_secret,
              totp_pending_secret = NULL,
              totp_enabled = true,
              updated_at = now()
        WHERE id = $1`,
      [userId]
    );
    return { ok: true };
  }

  async disableTotp(userId: string, password: string, code: string) {
    if (userId === "internal") throw new ForbiddenException();
    const row = await this.findUserById(userId);
    if (!row?.totp_enabled || !row.totp_secret) {
      throw new BadRequestException("2FA is not enabled");
    }
    const pwOk = await argon2.verify(row.password_hash, password);
    if (!pwOk) throw new UnauthorizedException("Invalid password");
    const totpV = verifySync({
      secret: row.totp_secret,
      token: code.replace(/\s/g, ""),
      epochTolerance: 30
    });
    if (!totpV.valid) throw new UnauthorizedException("Invalid authenticator code");
    await this.db.query(
      `UPDATE auth_user
          SET totp_secret = NULL,
              totp_pending_secret = NULL,
              totp_enabled = false,
              updated_at = now()
        WHERE id = $1`,
      [userId]
    );
    return { ok: true };
  }

  private async findUserByEmail(email: string): Promise<UserRow | null> {
    const res = await this.db.query<UserRow>(
      `SELECT id, email, password_hash, totp_secret, totp_pending_secret, totp_enabled, role
         FROM auth_user
        WHERE lower(email) = lower($1)
        LIMIT 1`,
      [email]
    );
    return res.rows[0] ?? null;
  }

  private async isInitialSetupRequired(): Promise<boolean> {
    const n = await this.db.query<{ c: string }>(`SELECT COUNT(*)::text AS c FROM auth_user`);
    return Number(n.rows[0]?.c ?? "0") === 0;
  }

  private async findUserById(id: string): Promise<UserRow | null> {
    const res = await this.db.query<UserRow>(
      `SELECT id, email, password_hash, totp_secret, totp_pending_secret, totp_enabled, role
         FROM auth_user
        WHERE id = $1`,
      [id]
    );
    return res.rows[0] ?? null;
  }

  private async signPendingTotp(userId: string): Promise<string> {
    const secret = process.env.JWT_SECRET?.trim();
    if (!secret) throw new Error("JWT_SECRET missing");
    return this.jwt.signAsync(
      { sub: userId, typ: "pending_totp" },
      { secret, expiresIn: PENDING_TOTP_TTL_SEC }
    );
  }

  private async issueTokenPair(row: UserRow) {
    const role = parseUserRole(row.role, UserRole.Analyst);
    const accessToken = await this.signAccess(row.id, row.email, role);
    const refreshRaw = randomBytes(48).toString("hex");
    const tokenHash = sha256Hex(refreshRaw);
    const expiresAt = new Date(Date.now() + REFRESH_TTL_SEC * 1000);
    await this.db.query(
      `INSERT INTO refresh_token (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
      [row.id, tokenHash, expiresAt]
    );
    return {
      accessToken,
      refreshToken: refreshRaw,
      expiresIn: ACCESS_TTL_SEC,
      tokenType: "Bearer" as const
    };
  }

  private async signAccess(userId: string, email: string, role: UserRole): Promise<string> {
    const secret = process.env.JWT_SECRET?.trim();
    if (!secret) throw new Error("JWT_SECRET missing");
    return this.jwt.signAsync(
      { sub: userId, email, role, typ: "access" },
      { secret, expiresIn: ACCESS_TTL_SEC }
    );
  }
}

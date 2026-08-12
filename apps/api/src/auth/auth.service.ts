import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
  OnApplicationBootstrap,
  UnauthorizedException
} from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import argon2 from "argon2";
import { generateSecret, verifySync } from "otplib";
import QRCode from "qrcode";
import { DbService } from "../services/db.service.js";
import { UserRole, parseUserRole } from "@vuln-intel/shared";

/** Access JWT TTL. Short values cause periodic 401 on live polls (e.g. stats/summary). */
const ACCESS_TTL_SEC = Math.max(
  5 * 60,
  Math.min(24 * 60 * 60, Number(process.env.JWT_ACCESS_TTL_SEC ?? 60 * 60))
);
const REFRESH_TTL_SEC = 60 * 60 * 24 * 7;
const PENDING_TOTP_TTL_SEC = 60 * 5;
/** Allow a just-rotated refresh token to mint again briefly (parallel apiFetch 401 races). */
const REFRESH_REUSE_GRACE_MS = Math.max(
  0,
  Math.min(120_000, Number(process.env.JWT_REFRESH_REUSE_GRACE_MS ?? 30_000))
);

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
  enabled: boolean;
  must_change_password: boolean;
  created_at?: Date;
  updated_at?: Date;
};

type AuthUserSummary = {
  id: string;
  email: string;
  role: UserRole;
  enabled: boolean;
  mustChangePassword: boolean;
  createdAt: string | null;
  updatedAt: string | null;
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
    const email = normalizeEmail(process.env.AUTH_BOOTSTRAP_EMAIL ?? "admin@vuln-intel.local");
    const password = process.env.AUTH_BOOTSTRAP_PASSWORD ?? "ChangeMe!Admin1";
    if (password.length < 12) throw new Error("AUTH_BOOTSTRAP_PASSWORD must be at least 12 characters");

    const n = await this.db.query<{ c: string }>(
      `SELECT COUNT(*)::text AS c FROM auth_user`
    );
    if (Number(n.rows[0]?.c ?? "0") > 0) return;

    const hash = await argon2.hash(password, { type: argon2.argon2id });
    try {
      await this.db.query(
        `INSERT INTO auth_user (email, password_hash, role, enabled, must_change_password)
         VALUES ($1, $2, $3, true, true)`,
        [email, hash, UserRole.Admin]
      );
      this.logger.log(`Bootstrap: created admin user ${email}; password change required`);
    } catch (e: unknown) {
      const err = e as { code?: string };
      if (err.code === "23505") return;
      throw e;
    }
  }

  async setupStatus() {
    return { required: false, bootstrapEmail: process.env.AUTH_BOOTSTRAP_EMAIL ?? "admin@vuln-intel.local" };
  }

  async setupFirstAdmin(emailRaw: string, password: string) {
    const email = normalizeEmail(emailRaw);
    assertPasswordPolicy(password);
    const hash = await argon2.hash(password, { type: argon2.argon2id });
    const inserted = await this.db.query<UserRow>(
      `INSERT INTO auth_user (email, password_hash, role, enabled, must_change_password)
       SELECT $1, $2, $3, true, false
        WHERE NOT EXISTS (SELECT 1 FROM auth_user)
       RETURNING id, email, password_hash, totp_secret, totp_pending_secret, totp_enabled, role, enabled, must_change_password`,
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
    if (!row.enabled) throw new UnauthorizedException("User is disabled");
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
    if (!row.enabled) throw new UnauthorizedException("User is disabled");
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

    // Atomic claim: first concurrent refresh wins; others fall into reuse grace.
    const claimed = await this.db.query<{
      id: string;
      user_id: string;
      expires_at: Date;
    }>(
      `UPDATE refresh_token
          SET revoked_at = now()
        WHERE token_hash = $1
          AND revoked_at IS NULL
          AND expires_at > now()
      RETURNING id, user_id, expires_at`,
      [tokenHash]
    );

    let userId = claimed.rows[0]?.user_id ?? null;
    if (!userId) {
      const prior = await this.db.query<{
        user_id: string;
        expires_at: Date;
        revoked_at: Date | null;
      }>(
        `SELECT user_id, expires_at, revoked_at
           FROM refresh_token
          WHERE token_hash = $1
          ORDER BY COALESCE(revoked_at, expires_at) DESC
          LIMIT 1`,
        [tokenHash]
      );
      const row = prior.rows[0];
      if (!row) throw new UnauthorizedException();
      if (row.expires_at.getTime() < Date.now()) throw new UnauthorizedException();
      const revokedAt = row.revoked_at?.getTime() ?? 0;
      const withinGrace =
        REFRESH_REUSE_GRACE_MS > 0 &&
        revokedAt > 0 &&
        Date.now() - revokedAt <= REFRESH_REUSE_GRACE_MS;
      if (!withinGrace) throw new UnauthorizedException();
      userId = row.user_id;
    }

    const user = await this.findUserById(userId);
    if (!user) throw new UnauthorizedException();
    if (!user.enabled) throw new UnauthorizedException("User is disabled");

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
    mustChangePassword: boolean;
    must_change_password: boolean;
  }> {
    if (userId === "internal") {
      return {
        id: "internal",
        email: "internal@system",
        totpEnabled: false,
        role: UserRole.Admin,
        mustChangePassword: false,
        must_change_password: false
      };
    }
    const row = await this.findUserById(userId);
    if (!row) throw new UnauthorizedException();
    if (!row.enabled) throw new UnauthorizedException("User is disabled");
    return {
      id: row.id,
      email: row.email,
      totpEnabled: row.totp_enabled,
      role: parseUserRole(row.role, UserRole.Analyst),
      mustChangePassword: row.must_change_password,
      must_change_password: row.must_change_password
    };
  }

  async changePassword(userId: string, currentPassword: string | undefined, newPassword: string) {
    if (userId === "internal") throw new ForbiddenException();
    assertPasswordPolicy(newPassword);
    const row = await this.findUserById(userId);
    if (!row) throw new UnauthorizedException();
    if (!row.enabled) throw new UnauthorizedException("User is disabled");
    if (currentPassword?.length) {
      const ok = await argon2.verify(row.password_hash, currentPassword);
      if (!ok) throw new UnauthorizedException("Invalid password");
    }
    const hash = await argon2.hash(newPassword, { type: argon2.argon2id });
    await this.db.query(
      `UPDATE auth_user
          SET password_hash = $2,
              must_change_password = false,
              updated_at = now()
        WHERE id = $1`,
      [userId, hash]
    );
    await this.revokeRefreshTokens(userId);
    return { ok: true };
  }

  async listUsers(): Promise<AuthUserSummary[]> {
    const rows = await this.db.query<UserRow>(
      `SELECT id, email, password_hash, totp_secret, totp_pending_secret, totp_enabled,
              role, enabled, must_change_password, created_at, updated_at
         FROM auth_user
        ORDER BY lower(email)`
    );
    return rows.rows.map((row) => this.toUserSummary(row));
  }

  async createUser(input: {
    email?: string;
    password?: string;
    role?: string;
    enabled?: boolean;
    mustChangePassword?: boolean;
  }): Promise<AuthUserSummary> {
    if (!input.email || !input.password) throw new BadRequestException("email and password required");
    const email = normalizeEmail(input.email);
    assertPasswordPolicy(input.password);
    const role = parseUserRole(input.role, UserRole.Analyst);
    const enabled = input.enabled !== false;
    const mustChangePassword = input.mustChangePassword !== false;
    const hash = await argon2.hash(input.password, { type: argon2.argon2id });
    try {
      const inserted = await this.db.query<UserRow>(
        `INSERT INTO auth_user (email, password_hash, role, enabled, must_change_password)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, email, password_hash, totp_secret, totp_pending_secret, totp_enabled,
                   role, enabled, must_change_password, created_at, updated_at`,
        [email, hash, role, enabled, mustChangePassword]
      );
      return this.toUserSummary(inserted.rows[0]!);
    } catch (e: unknown) {
      const err = e as { code?: string };
      if (err.code === "23505") throw new BadRequestException("Email already registered");
      throw e;
    }
  }

  async updateUser(
    actorUserId: string,
    id: string,
    input: { email?: string; role?: string; enabled?: boolean; mustChangePassword?: boolean }
  ): Promise<AuthUserSummary> {
    if (id === "internal") throw new ForbiddenException();
    const row = await this.findUserById(id);
    if (!row) throw new NotFoundException("User not found");
    const next = {
      email: input.email == null ? row.email : normalizeEmail(input.email),
      role: input.role == null ? parseUserRole(row.role, UserRole.Analyst) : parseUserRole(input.role, UserRole.Analyst),
      enabled: input.enabled == null ? row.enabled : input.enabled !== false,
      mustChangePassword:
        input.mustChangePassword == null ? row.must_change_password : input.mustChangePassword === true
    };
    await this.assertAdminSafety(actorUserId, row, next.role, next.enabled);
    try {
      const updated = await this.db.query<UserRow>(
        `UPDATE auth_user
            SET email = $2,
                role = $3,
                enabled = $4,
                must_change_password = $5,
                updated_at = now()
          WHERE id = $1
          RETURNING id, email, password_hash, totp_secret, totp_pending_secret, totp_enabled,
                    role, enabled, must_change_password, created_at, updated_at`,
        [id, next.email, next.role, next.enabled, next.mustChangePassword]
      );
      return this.toUserSummary(updated.rows[0]!);
    } catch (e: unknown) {
      const err = e as { code?: string };
      if (err.code === "23505") throw new BadRequestException("Email already registered");
      throw e;
    }
  }

  async resetUserPassword(id: string, password: string, mustChangePassword = true) {
    if (id === "internal") throw new ForbiddenException();
    assertPasswordPolicy(password);
    const row = await this.findUserById(id);
    if (!row) throw new NotFoundException("User not found");
    const hash = await argon2.hash(password, { type: argon2.argon2id });
    await this.db.query(
      `UPDATE auth_user
          SET password_hash = $2,
              must_change_password = $3,
              updated_at = now()
        WHERE id = $1`,
      [id, hash, mustChangePassword]
    );
    await this.revokeRefreshTokens(id);
    return { ok: true };
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
      `SELECT id, email, password_hash, totp_secret, totp_pending_secret, totp_enabled,
              role, enabled, must_change_password, created_at, updated_at
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
      `SELECT id, email, password_hash, totp_secret, totp_pending_secret, totp_enabled,
              role, enabled, must_change_password, created_at, updated_at
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

  private async revokeRefreshTokens(userId: string): Promise<void> {
    await this.db.query(
      `UPDATE refresh_token
          SET revoked_at = now()
        WHERE user_id = $1
          AND revoked_at IS NULL`,
      [userId]
    );
  }

  private toUserSummary(row: UserRow): AuthUserSummary {
    return {
      id: row.id,
      email: row.email,
      role: parseUserRole(row.role, UserRole.Analyst),
      enabled: row.enabled,
      mustChangePassword: row.must_change_password,
      createdAt: row.created_at ? row.created_at.toISOString() : null,
      updatedAt: row.updated_at ? row.updated_at.toISOString() : null
    };
  }

  private async assertAdminSafety(
    actorUserId: string,
    current: UserRow,
    nextRole: UserRole,
    nextEnabled: boolean
  ): Promise<void> {
    const currentRole = parseUserRole(current.role, UserRole.Analyst);
    const wouldRemoveAdmin = current.enabled && currentRole === UserRole.Admin && (!nextEnabled || nextRole !== UserRole.Admin);
    const selfLockout = actorUserId === current.id && (!nextEnabled || nextRole !== UserRole.Admin);
    if (!wouldRemoveAdmin && !selfLockout) return;

    const admins = await this.db.query<{ c: string }>(
      `SELECT COUNT(*)::text AS c
         FROM auth_user
        WHERE id <> $1
          AND enabled = true
          AND role = $2`,
      [current.id, UserRole.Admin]
    );
    if (Number(admins.rows[0]?.c ?? "0") < 1) {
      throw new ForbiddenException("At least one enabled admin must remain");
    }
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
      tokenType: "Bearer" as const,
      mustChangePassword: row.must_change_password,
      must_change_password: row.must_change_password
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

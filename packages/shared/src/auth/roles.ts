/** Platform user roles (stored in auth_user.role). */
export const UserRole = {
  Admin: "admin",
  Analyst: "analyst",
  Viewer: "viewer"
} as const;

export type UserRole = (typeof UserRole)[keyof typeof UserRole];

const VALID = new Set<string>(Object.values(UserRole));

export function parseUserRole(raw: unknown, fallback: UserRole = UserRole.Analyst): UserRole {
  if (typeof raw === "string" && VALID.has(raw)) return raw as UserRole;
  return fallback;
}

/** Admin if explicit role or legacy ADMIN_EMAILS list (when role column absent / unset). */
export function isAdminUser(opts: {
  role?: UserRole | string | null;
  email?: string | null;
  adminEmailsEnv?: string | null;
  userId?: string | null;
}): boolean {
  if (opts.userId === "internal") return true;
  const role = parseUserRole(opts.role, UserRole.Analyst);
  if (role === UserRole.Admin) return true;
  const raw = opts.adminEmailsEnv?.trim();
  if (!raw) return false;
  const allow = raw
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  return allow.includes(String(opts.email ?? "").toLowerCase());
}

export function canWriteData(role: UserRole | string): boolean {
  const r = parseUserRole(role);
  return r === UserRole.Admin || r === UserRole.Analyst;
}

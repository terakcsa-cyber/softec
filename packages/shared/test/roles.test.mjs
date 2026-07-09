import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { UserRole, isAdminUser, parseUserRole, canWriteData } from "../dist/index.js";

describe("roles", () => {
  it("parseUserRole falls back for invalid", () => {
    assert.equal(parseUserRole("nope", UserRole.Viewer), UserRole.Viewer);
    assert.equal(parseUserRole("admin"), UserRole.Admin);
  });

  it("isAdminUser respects role admin", () => {
    assert.equal(
      isAdminUser({ role: UserRole.Admin, email: "a@b.c", adminEmailsEnv: "" }),
      true
    );
    assert.equal(
      isAdminUser({ role: UserRole.Analyst, email: "a@b.c", adminEmailsEnv: "other@b.c" }),
      false
    );
  });

  it("isAdminUser legacy ADMIN_EMAILS", () => {
    assert.equal(
      isAdminUser({
        role: UserRole.Analyst,
        email: "admin@corp.local",
        adminEmailsEnv: "admin@corp.local"
      }),
      true
    );
  });

  it("isAdminUser unset ADMIN_EMAILS allows all (dev compat)", () => {
    assert.equal(isAdminUser({ role: UserRole.Viewer, email: "x@y.z" }), true);
  });

  it("canWriteData", () => {
    assert.equal(canWriteData(UserRole.Viewer), false);
    assert.equal(canWriteData(UserRole.Analyst), true);
    assert.equal(canWriteData(UserRole.Admin), true);
  });
});

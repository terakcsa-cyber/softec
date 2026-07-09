import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { isAdminUser, UserRole, canWriteData } from "../dist/index.js";

describe("write role policy", () => {
  it("viewer cannot write", () => {
    assert.equal(canWriteData(UserRole.Viewer), false);
  });

  it("analyst can write but is not admin without ADMIN_EMAILS", () => {
    assert.equal(canWriteData(UserRole.Analyst), true);
    assert.equal(
      isAdminUser({
        role: UserRole.Analyst,
        email: "a@b.c",
        adminEmailsEnv: "other@b.c"
      }),
      false
    );
  });
});

-- 002: forced password-change and user enablement flags
ALTER TABLE auth_user
  ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT true;

ALTER TABLE auth_user
  ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false;


-- 002: forced password-change and user enablement flags

DO $$
BEGIN
  IF to_regclass('public.auth_user') IS NULL THEN
    RAISE NOTICE '002_auth_user_password_policy: auth_user missing, skip';
    RETURN;
  END IF;

  ALTER TABLE auth_user
    ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT true;

  ALTER TABLE auth_user
    ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false;
END $$;

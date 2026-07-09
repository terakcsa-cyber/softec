-- 001: RBAC role column on auth_user
ALTER TABLE auth_user
  ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'analyst';

UPDATE auth_user SET role = 'admin' WHERE role = 'analyst' AND id IN (
  SELECT id FROM auth_user ORDER BY created_at ASC LIMIT 1
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'auth_user_role_check'
  ) THEN
    ALTER TABLE auth_user
      ADD CONSTRAINT auth_user_role_check
      CHECK (role IN ('admin', 'analyst', 'viewer'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS auth_user_role_idx ON auth_user (role);

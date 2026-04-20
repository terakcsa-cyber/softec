-- Сигналы о бюллетенях/патчах вендоров (RSS/Atom), модуль patch management.

CREATE TABLE IF NOT EXISTS vendor_advisory (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  dedupe_key TEXT NOT NULL UNIQUE,
  feed_url TEXT NOT NULL,
  vendor_slug TEXT NOT NULL,
  title TEXT NOT NULL,
  link TEXT NOT NULL,
  summary TEXT,
  published_at TIMESTAMPTZ,
  cve_ids TEXT[] NOT NULL DEFAULT '{}',
  raw_item JSONB,
  fetched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS vendor_advisory_published_idx ON vendor_advisory (published_at DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS vendor_advisory_vendor_idx ON vendor_advisory (vendor_slug);
CREATE INDEX IF NOT EXISTS vendor_advisory_cve_ids_gin_idx ON vendor_advisory USING gin (cve_ids);

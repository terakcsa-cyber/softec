-- Core schema (minimal baseline). Migrations will evolve this.

CREATE TABLE IF NOT EXISTS audit_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_type TEXT NOT NULL,
  actor_id TEXT,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  ip INET,
  user_agent TEXT,
  request_id UUID,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS audit_log_action_idx ON audit_log (action);

CREATE TABLE IF NOT EXISTS app_integration_settings (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS mpvm_asset (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  external_id TEXT NOT NULL,
  hostname TEXT,
  ip_address TEXT,
  os_name TEXT,
  os_version TEXT,
  display_name TEXT NOT NULL,
  raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (external_id)
);

CREATE INDEX IF NOT EXISTS mpvm_asset_last_synced_idx ON mpvm_asset (last_synced_at DESC);
CREATE INDEX IF NOT EXISTS mpvm_asset_ip_idx ON mpvm_asset (ip_address) WHERE ip_address IS NOT NULL;

CREATE TABLE IF NOT EXISTS cve (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id TEXT UNIQUE NOT NULL,
  source TEXT NOT NULL,
  published_at TIMESTAMPTZ,
  modified_at TIMESTAMPTZ,
  cvss_base DOUBLE PRECISION CHECK (cvss_base >= 0 AND cvss_base <= 10),
  raw JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cve_published_at_idx ON cve (published_at DESC);

-- Normalized vendor/product index (for fast filters and analytics).
CREATE TABLE IF NOT EXISTS cve_vendor_product (
  cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
  vendor TEXT NOT NULL,
  product TEXT,
  vendor_key TEXT NOT NULL,
  product_key TEXT,
  product_key_norm TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL,
  cve_updated_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (cve_id, vendor_key, product_key_norm)
);

CREATE INDEX IF NOT EXISTS cve_vendor_product_vendor_idx ON cve_vendor_product (vendor_key);
CREATE INDEX IF NOT EXISTS cve_vendor_product_vendor_product_idx ON cve_vendor_product (vendor_key, product_key_norm);
CREATE INDEX IF NOT EXISTS cve_vendor_product_cve_idx ON cve_vendor_product (cve_id);

CREATE TABLE IF NOT EXISTS enrichment_ai (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
  model TEXT NOT NULL,
  prompt_version TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  output_json JSONB NOT NULL,
  output_text TEXT,
  tokens_input INT,
  tokens_output INT,
  cost_usd NUMERIC(10, 6),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (cve_id, model, prompt_version, input_hash)
);

CREATE TABLE IF NOT EXISTS risk_score (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id TEXT UNIQUE NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
  score INT NOT NULL CHECK (score >= 0 AND score <= 100),
  factors JSONB NOT NULL DEFAULT '{}'::jsonb,
  model_version TEXT NOT NULL,
  computed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Idempotency keys for queue consumers / API endpoints
CREATE TABLE IF NOT EXISTS idempotency_key (
  key TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- External intelligence feeds

-- EPSS scores (FIRST). Stored as probability 0..1 and percentile 0..1 when provided.
CREATE TABLE IF NOT EXISTS epss_score (
  cve_id TEXT PRIMARY KEY,
  score DOUBLE PRECISION NOT NULL CHECK (score >= 0 AND score <= 1),
  percentile DOUBLE PRECISION CHECK (percentile >= 0 AND percentile <= 1),
  scored_at DATE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS epss_score_score_idx ON epss_score (score DESC);
CREATE INDEX IF NOT EXISTS epss_score_updated_at_idx ON epss_score (updated_at DESC);

-- CISA Known Exploited Vulnerabilities (KEV) catalog.
CREATE TABLE IF NOT EXISTS kev (
  cve_id TEXT PRIMARY KEY,
  vendor_project TEXT,
  product TEXT,
  vulnerability_name TEXT,
  date_added DATE,
  due_date DATE,
  required_action TEXT,
  ransomware_use TEXT,
  notes TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS kev_date_added_idx ON kev (date_added DESC);
CREATE INDEX IF NOT EXISTS kev_updated_at_idx ON kev (updated_at DESC);

-- VulnCheck KEV (also created by API SchemaService for older volumes).
CREATE TABLE IF NOT EXISTS vulncheck_kev (
  cve_id TEXT PRIMARY KEY,
  date_added TIMESTAMPTZ,
  cisa_date_added TIMESTAMPTZ,
  vckev_only BOOLEAN NOT NULL DEFAULT false,
  ransomware_use TEXT,
  evidence_count INT NOT NULL DEFAULT 0,
  xdb_url TEXT,
  raw JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS vulncheck_kev_date_added_idx ON vulncheck_kev (date_added DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS vulncheck_kev_vckev_only_idx ON vulncheck_kev (vckev_only) WHERE vckev_only = true;


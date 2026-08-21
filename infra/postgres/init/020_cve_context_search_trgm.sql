-- Полнотекстовый поиск по контексту CVE (см. GET /cves?q=): GIN + pg_trgm.
-- Запрос использует `lower(col) LIKE '%' || needle || '%' ESCAPE E'\\'`.

CREATE INDEX IF NOT EXISTS cve_cve_id_lower_trgm_idx ON cve USING gin (lower(cve_id) gin_trgm_ops);

CREATE INDEX IF NOT EXISTS cve_raw_lower_text_trgm_idx ON cve USING gin (lower(raw::text) gin_trgm_ops);

CREATE INDEX IF NOT EXISTS cve_vendor_product_vendor_lower_trgm_idx ON cve_vendor_product USING gin (lower(vendor) gin_trgm_ops);

CREATE INDEX IF NOT EXISTS cve_vendor_product_product_lower_trgm_idx ON cve_vendor_product USING gin (lower(COALESCE(product, '')) gin_trgm_ops);

CREATE INDEX IF NOT EXISTS cve_vendor_product_vendor_key_lower_trgm_idx ON cve_vendor_product USING gin (lower(vendor_key) gin_trgm_ops);

CREATE INDEX IF NOT EXISTS cve_vendor_product_product_key_norm_lower_trgm_idx ON cve_vendor_product USING gin (lower(product_key_norm) gin_trgm_ops);

CREATE INDEX IF NOT EXISTS enrichment_ai_cve_id_idx ON enrichment_ai (cve_id);

CREATE INDEX IF NOT EXISTS enrichment_ai_cve_created_idx ON enrichment_ai (cve_id, created_at DESC);

CREATE INDEX IF NOT EXISTS enrichment_ai_output_text_lower_trgm_idx ON enrichment_ai USING gin (lower(COALESCE(output_text, '')) gin_trgm_ops);

CREATE INDEX IF NOT EXISTS enrichment_ai_output_json_text_lower_trgm_idx ON enrichment_ai USING gin (lower(output_json::text) gin_trgm_ops);

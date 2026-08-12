-- One-off: remove BDU tables if they were created earlier (integration removed).
-- Run manually: psql "$DATABASE_URL" -f infra/postgres/migrations/drop_bdu_tables.sql

DROP TABLE IF EXISTS cve_bdu_map CASCADE;
DROP TABLE IF EXISTS bdu_vuln CASCADE;

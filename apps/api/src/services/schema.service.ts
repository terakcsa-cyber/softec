import { Injectable, OnModuleInit } from "@nestjs/common";
import { DbService } from "./db.service.js";

@Injectable()
export class SchemaService implements OnModuleInit {
  constructor(private readonly db: DbService) {}

  async onModuleInit() {
    // Keep API compatible with existing DB volumes.
    await this.db.query(
      `ALTER TABLE cve
       ADD COLUMN IF NOT EXISTS cvss_base DOUBLE PRECISION CHECK (cvss_base >= 0 AND cvss_base <= 10)`
    );
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS cve_vendor_product (
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
      )`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS cve_vendor_product_vendor_idx ON cve_vendor_product (vendor_key)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS cve_vendor_product_vendor_product_idx ON cve_vendor_product (vendor_key, product_key_norm)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS cve_vendor_product_cve_idx ON cve_vendor_product (cve_id)`
    );
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS epss_score (
        cve_id TEXT PRIMARY KEY,
        score DOUBLE PRECISION NOT NULL CHECK (score >= 0 AND score <= 1),
        percentile DOUBLE PRECISION CHECK (percentile >= 0 AND percentile <= 1),
        scored_at DATE,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS kev (
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
      )`
    );
  }
}


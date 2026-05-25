import { Injectable } from "@nestjs/common";
import { fetchAllMpvmInventory, stableJsonStringify, type MpvmClientConfig } from "@vuln-intel/shared";
import { DbService } from "./db.service.js";
import { IntegrationSettingsService } from "./integration-settings.service.js";

@Injectable()
export class MpvmSyncService {
  constructor(
    private readonly db: DbService,
    private readonly integration: IntegrationSettingsService
  ) {}

  async syncAssets(): Promise<{
    ok: boolean;
    fetched: number;
    upserted: number;
    softwareUpserted: number;
    vulnerabilitiesUpserted: number;
    pdql: string;
    warning: string | null;
    error: string | null;
    ms: number;
  }> {
    const started = Date.now();
    const cfg = await this.integration.getMpvmClientConfig();
    if (!cfg) {
      return {
        ok: false,
        fetched: 0,
        upserted: 0,
        softwareUpserted: 0,
        vulnerabilitiesUpserted: 0,
        pdql: "",
        warning: null,
        error: "MaxPatrol VM не настроен (URL и API-токен)",
        ms: Date.now() - started
      };
    }

    try {
      const { assets, software, vulnerabilities, pdql, warning } = await fetchAllMpvmInventory(cfg);
      let upserted = 0;
      let softwareUpserted = 0;
      let vulnerabilitiesUpserted = 0;
      for (const a of assets) {
        const r = await this.db.query(
          `INSERT INTO mpvm_asset (
             external_id, hostname, ip_address, os_name, os_version,
             display_name, raw_json, last_synced_at
           ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, now())
           ON CONFLICT (external_id) DO UPDATE SET
             hostname = EXCLUDED.hostname,
             ip_address = EXCLUDED.ip_address,
             os_name = EXCLUDED.os_name,
             os_version = EXCLUDED.os_version,
             display_name = EXCLUDED.display_name,
             raw_json = EXCLUDED.raw_json,
             last_synced_at = now()`,
          [
            a.externalId,
            a.hostname,
            a.ipAddress,
            a.osName,
            a.osVersion,
            a.displayName,
            stableJsonStringify(a.raw)
          ]
        );
        upserted += r.rowCount ?? 0;
      }
      for (const s of software) {
        const r = await this.db.query(
          `INSERT INTO mpvm_asset_software (
             asset_external_id, software_key, kind, name, version, vendor, install_path, raw_json, last_seen_at
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,now())
           ON CONFLICT (asset_external_id, software_key) DO UPDATE SET
             kind = EXCLUDED.kind,
             name = EXCLUDED.name,
             version = EXCLUDED.version,
             vendor = EXCLUDED.vendor,
             install_path = EXCLUDED.install_path,
             raw_json = EXCLUDED.raw_json,
             last_seen_at = now()`,
          [
            s.assetExternalId,
            s.softwareKey,
            s.kind,
            s.name,
            s.version,
            s.vendor,
            s.installPath,
            stableJsonStringify(s.raw)
          ]
        );
        softwareUpserted += r.rowCount ?? 0;
      }
      for (const v of vulnerabilities) {
        const r = await this.db.query(
          `INSERT INTO mpvm_asset_vulnerability (
             asset_external_id, vuln_key, cve_id, title, severity, cvss_score, status,
             fix_available, solution, affected_software_key, affected_software_name,
             affected_software_version, raw_json, last_seen_at
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,now())
           ON CONFLICT (asset_external_id, vuln_key) DO UPDATE SET
             cve_id = EXCLUDED.cve_id,
             title = EXCLUDED.title,
             severity = EXCLUDED.severity,
             cvss_score = EXCLUDED.cvss_score,
             status = EXCLUDED.status,
             fix_available = EXCLUDED.fix_available,
             solution = EXCLUDED.solution,
             affected_software_key = EXCLUDED.affected_software_key,
             affected_software_name = EXCLUDED.affected_software_name,
             affected_software_version = EXCLUDED.affected_software_version,
             raw_json = EXCLUDED.raw_json,
             last_seen_at = now()`,
          [
            v.assetExternalId,
            v.vulnKey,
            v.cveId,
            v.title,
            v.severity,
            v.cvssScore,
            v.status,
            v.fixAvailable,
            v.solution,
            v.affectedSoftwareKey,
            v.affectedSoftwareName,
            v.affectedSoftwareVersion,
            stableJsonStringify(v.raw)
          ]
        );
        vulnerabilitiesUpserted += r.rowCount ?? 0;
      }

      await this.db.query(
        `INSERT INTO audit_log (actor_type, action, metadata) VALUES ('system', 'mpvm.sync', $1::jsonb)`,
        [
          JSON.stringify({
            fetched: assets.length,
            upserted,
            software: software.length,
            softwareUpserted,
            vulnerabilities: vulnerabilities.length,
            vulnerabilitiesUpserted,
            pdql,
            warning,
            baseUrl: cfg.baseUrl
          })
        ]
      );

      return {
        ok: true,
        fetched: assets.length,
        upserted,
        softwareUpserted,
        vulnerabilitiesUpserted,
        pdql,
        warning,
        error: null,
        ms: Date.now() - started
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      await this.db.query(
        `INSERT INTO audit_log (actor_type, action, metadata) VALUES ('system', 'mpvm.sync', $1::jsonb)`,
        [JSON.stringify({ ok: false, error: msg.slice(0, 2000) })]
      ).catch(() => undefined);
      return {
        ok: false,
        fetched: 0,
        upserted: 0,
        softwareUpserted: 0,
        vulnerabilitiesUpserted: 0,
        pdql: cfg.pdql ?? "",
        warning: null,
        error: msg.slice(0, 2000),
        ms: Date.now() - started
      };
    }
  }
}

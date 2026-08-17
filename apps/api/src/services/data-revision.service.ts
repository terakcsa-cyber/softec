import { Injectable } from "@nestjs/common";
import { DbService } from "./db.service.js";
import { ReadCacheService } from "./read-cache.service.js";

export type RevisionSlice =
  | "cves"
  | "bdu"
  | "voc"
  | "tasks"
  | "threat"
  | "fstec"
  | "patch"
  | "catalog";

export type DataRevision = Record<RevisionSlice, string>;

function stamp(v: unknown): string {
  if (v == null) return "0";
  if (v instanceof Date) return v.toISOString();
  return String(v);
}

@Injectable()
export class DataRevisionService {
  constructor(
    private readonly db: DbService,
    private readonly cache: ReadCacheService
  ) {}

  ttlSec(): number {
    return this.cache.ttlSec("read", 45);
  }

  async snapshot(): Promise<DataRevision> {
    return this.cache.getOrSet("data-revision:snapshot", 2, () => this.compute());
  }

  async withSlice<T>(slice: RevisionSlice, key: string, load: () => Promise<T>): Promise<T> {
    const ttl = this.ttlSec();
    if (ttl <= 0) return load();
    const snap = await this.snapshot();
    return this.cache.getOrSet(`${key}:${snap[slice]}`, ttl, load);
  }

  private async compute(): Promise<DataRevision> {
    const r = await this.db.query<{
      cves: Date | string | null;
      bdu: Date | string | null;
      voc: Date | string | null;
      tasks: Date | string | null;
      threat: Date | string | null;
      fstec: Date | string | null;
      patch: Date | string | null;
    }>(
      `SELECT
         GREATEST(
           (SELECT MAX(updated_at) FROM cve),
           (SELECT MAX(computed_at) FROM risk_score),
           (SELECT MAX(updated_at) FROM epss_score),
           (SELECT MAX(created_at) FROM enrichment_ai)
         ) AS cves,
         GREATEST(
           (SELECT MAX(updated_at) FROM bdu_vuln),
           (SELECT MAX(created_at) FROM enrichment_bdu)
         ) AS bdu,
         GREATEST(
           (SELECT MAX(updated_at) FROM voc_triage),
           (SELECT MAX(updated_at) FROM voc_case),
           (SELECT MAX(updated_at) FROM voc_watchlist)
         ) AS voc,
         (SELECT MAX(updated_at) FROM vuln_task) AS tasks,
         GREATEST(
           (SELECT MAX(intel_updated_at) FROM cve_exploit_intel),
           (SELECT MAX(updated_at) FROM kev),
           (SELECT MAX(updated_at) FROM epss_score)
         ) AS threat,
         GREATEST(
           (SELECT MAX(updated_at) FROM fstec_bulletin),
           (SELECT MAX(updated_at) FROM fstec_bulletin_analysis)
         ) AS fstec,
         GREATEST(
           (SELECT MAX(fetched_at) FROM vendor_advisory),
           (SELECT MAX(published_at) FROM vendor_advisory)
         ) AS patch`
    );
    const row = r.rows[0];
    const cves = stamp(row?.cves);
    const bdu = stamp(row?.bdu);
    const threat = stamp(row?.threat);
    return {
      cves,
      bdu,
      voc: stamp(row?.voc),
      tasks: stamp(row?.tasks),
      threat,
      fstec: stamp(row?.fstec),
      patch: stamp(row?.patch),
      catalog: `${cves}|${bdu}|${threat}`
    };
  }
}

export function revisionSliceForPath(pathname: string): RevisionSlice | null {
  const path = pathname.split("?")[0] ?? "";
  if (path.includes("/stats/revision")) return null;
  if (path.includes("/stats/summary") || path.includes("/stats/vendors")) return "catalog";
  if (path.includes("/stats/threat-feed") || path.includes("/stats/exploit-radar")) return "threat";
  if (path.includes("/stats/")) return null;
  if (path.includes("/settings") || path.includes("/auth") || path.includes("/health")) return null;
  if (path.includes("/metrics")) return null;
  if (path.includes("/cves")) return "cves";
  if (path.includes("/bdu")) return "bdu";
  if (path.includes("/voc")) return "voc";
  if (path.includes("/vuln-tasks")) return "tasks";
  if (path.includes("/fstec/feed")) return null;
  if (path.includes("/fstec")) return "fstec";
  if (path.includes("/vendor-advisories")) return "patch";
  return null;
}

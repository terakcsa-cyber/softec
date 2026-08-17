import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseEpssCsv, epssCandidateUrls, epssShouldSkipAsCurrent, epssUtcYmd } from "../dist/index.js";

describe("parseEpssCsv", () => {
  it("parses header and rows", () => {
    const csv = [
      "# comment score_date:2026-07-09",
      "cve,epss,percentile",
      "CVE-2024-0001,0.12345,0.67",
      "CVE-2024-0002,0.5,0.9"
    ].join("\n");
    const rows = parseEpssCsv(csv, new Date("2026-07-09T00:00:00.000Z"));
    assert.equal(rows.length, 2);
    assert.equal(rows[0].cveId, "CVE-2024-0001");
    assert.ok(Math.abs(rows[0].epss - 0.12345) < 1e-6);
    assert.equal(rows[1].cveId, "CVE-2024-0002");
  });

  it("returns empty for header-only feed", () => {
    assert.deepEqual(parseEpssCsv("cve,epss\n"), []);
  });
});

describe("epss daily freshness", () => {
  it("puts today's dated empiricalsecurity URL first and GitHub mirror last", () => {
    const urls = epssCandidateUrls();
    const today = epssUtcYmd();
    assert.equal(urls[0], `https://epss.empiricalsecurity.com/epss_scores-${today}.csv.gz`);
    assert.equal(urls[urls.length - 1], "https://lucacapacci.github.io/epss/epss_scores.csv");
  });

  it("skips fetch only when corpus already has today's score_date", () => {
    assert.equal(
      epssShouldSkipAsCurrent({
        rowCount: 80_000,
        maxScored: "2026-08-16",
        today: "2026-08-16"
      }),
      true
    );
    assert.equal(
      epssShouldSkipAsCurrent({
        rowCount: 80_000,
        maxScored: "2026-08-15",
        today: "2026-08-16"
      }),
      false
    );
    assert.equal(
      epssShouldSkipAsCurrent({
        force: true,
        rowCount: 80_000,
        maxScored: "2026-08-16",
        today: "2026-08-16"
      }),
      false
    );
  });
});

describe("listEpssRescoreCveIds", () => {
  it("ranks 24h / 7d / KEV before high EPSS and respects limit", async () => {
    const { listEpssRescoreCveIds } = await import("../dist/index.js");
    let capturedSql = "";
    const db = {
      query: async (sql, params) => {
        capturedSql = String(sql);
        assert.equal(params[2], 200);
        return { rows: [{ cve_id: "CVE-2026-1" }] };
      }
    };
    const ids = await listEpssRescoreCveIds(db, {
      scoreDate: "2026-08-17",
      sinceIso: "2026-08-17T08:00:00.000Z",
      limit: 200
    });
    assert.deepEqual(ids, ["CVE-2026-1"]);
    assert.match(capturedSql, /24 hours/);
    assert.match(capturedSql, /7 days/);
    assert.match(capturedSql, /epss_spike/);
    assert.match(capturedSql, /e\.score/);
  });
});

describe("rescoreCatalogRiskScores", () => {
  it("rewrites the whole CVE catalog without a row cap", async () => {
    const { rescoreCatalogRiskScores } = await import("../dist/index.js");
    let capturedSql = "";
    const db = {
      query: async (sql) => {
        capturedSql = String(sql);
        return { rows: [], rowCount: 12 };
      }
    };
    const n = await rescoreCatalogRiskScores(db);
    assert.equal(n, 12);
    assert.match(capturedSql, /INSERT INTO risk_score/);
    assert.match(capturedSql, /FROM cve c/);
    assert.match(capturedSql, /0\.22 \* epss_n/);
    assert.match(capturedSql, /LEFT JOIN epss_score/);
    assert.doesNotMatch(capturedSql, /LIMIT\s+20[_\s]?000/i);
  });
});

describe("nvd exploit refs stay live", () => {
  it("extracts GitHub PoC and Exploit-DB from NVD references", async () => {
    const { extractExploitSignalsFromNvdRaw } = await import("../dist/index.js");
    const signals = extractExploitSignalsFromNvdRaw({
      references: [
        { url: "https://github.com/foo/CVE-2024-1-poc", tags: ["Exploit"] },
        { url: "https://www.exploit-db.com/exploits/12345" }
      ]
    });
    assert.equal(signals.length, 2);
    assert.equal(signals[0].signal_type, "poc_github");
    assert.equal(signals[1].signal_type, "exploit_db");
  });

  it("stamps a scan watermark so later lastModified re-extracts refs", async () => {
    const { upsertNvdExploitSignalsFromRaw, NVD_REFS_SCANNED_SIGNAL_TYPE } = await import("../dist/index.js");
    const sqls = [];
    const db = {
      query: async (sql, params) => {
        sqls.push({ sql: String(sql), params });
        return { rows: [], rowCount: 1 };
      }
    };
    const raw = { references: [{ url: "https://github.com/x/poc-cve", tags: ["Exploit"] }] };
    const { signalCount } = await upsertNvdExploitSignalsFromRaw(db, "CVE-2026-1", raw);
    assert.equal(signalCount, 1);
    assert.equal(
      sqls.some((q) => q.params?.[1] === NVD_REFS_SCANNED_SIGNAL_TYPE),
      true
    );
    assert.equal(
      sqls.some((q) => String(q.sql).includes("DO UPDATE SET last_seen_at = now()")),
      true
    );
  });

  it("does not count the scan watermark as an exploit ref", async () => {
    const { EXPLOIT_INTEL_UPSERT_SQL } = await import("../dist/index.js");
    assert.match(EXPLOIT_INTEL_UPSERT_SQL, /nvd_refs_scanned/);
  });
});

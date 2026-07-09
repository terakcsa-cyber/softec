import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseEpssCsv } from "../dist/index.js";

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

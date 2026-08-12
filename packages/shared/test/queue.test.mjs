import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  EnrichCveRequestedEventSchema,
  publishScoreEvents,
  buildScoreEventsForCveIds,
  isAiScoreEnabled,
  shouldScoreViaQueue,
  getAiEnrichMaxDepth,
  shouldSkipEnrichPublishForDepth,
  enrichInflightIdempotencyKey,
  buildEnrichRequestedEvent,
  publishEnrichRequested,
  extractCvssBaseScoreFromNvdRaw,
  upsertRiskScoreForCve,
  applyRiskScoresForCveIds
} from "../dist/index.js";

describe("queue schemas", () => {
  it("EnrichCveRequestedEventSchema coerces legacy source", () => {
    const p = EnrichCveRequestedEventSchema.parse({
      cveId: "CVE-2024-0001",
      source: "legacy-unknown",
      raw: {}
    });
    assert.equal(p.source, "other");
  });
});

describe("isAiScoreEnabled", () => {
  it("defaults to enabled (deterministic risk score)", () => {
    assert.equal(isAiScoreEnabled({ TEXT_ENGINE: "baseline" }), true);
    assert.equal(isAiScoreEnabled({ TEXT_ENGINE: "translate" }), true);
    assert.equal(isAiScoreEnabled({}), true);
  });

  it("respects explicit AI_SCORE_ENABLED override", () => {
    assert.equal(isAiScoreEnabled({ TEXT_ENGINE: "llm" }), true);
    assert.equal(isAiScoreEnabled({ TEXT_ENGINE: "baseline", AI_SCORE_ENABLED: "true" }), true);
    assert.equal(isAiScoreEnabled({ TEXT_ENGINE: "llm", AI_SCORE_ENABLED: "false" }), false);
    assert.equal(isAiScoreEnabled({ AI_SCORE_ENABLED: "0" }), false);
  });
});

describe("shouldScoreViaQueue", () => {
  it("defaults to inline (queue off)", () => {
    assert.equal(shouldScoreViaQueue({}), false);
    assert.equal(shouldScoreViaQueue({ AI_SCORE_VIA_QUEUE: "false" }), false);
  });

  it("opt-in only", () => {
    assert.equal(shouldScoreViaQueue({ AI_SCORE_VIA_QUEUE: "true" }), true);
    assert.equal(shouldScoreViaQueue({ AI_SCORE_VIA_QUEUE: "1" }), true);
  });
});

describe("publishScoreEvents", () => {
  it("publishes only when via-queue is enabled", async () => {
    const prevFlag = process.env.AI_SCORE_ENABLED;
    const prevVia = process.env.AI_SCORE_VIA_QUEUE;
    process.env.AI_SCORE_ENABLED = "true";
    process.env.AI_SCORE_VIA_QUEUE = "true";
    try {
      const calls = [];
      const publisher = (ex, rk, body) => {
        calls.push({ ex, rk, body });
      };
      const events = await buildScoreEventsForCveIds(["CVE-2024-0001"], {
        producer: { service: "test", version: "0" },
        tag: "unit"
      });
      const n = publishScoreEvents(publisher, events);
      assert.equal(n, 1);
      assert.equal(calls[0].ex, "vuln.events");
      assert.equal(calls[0].rk, "vuln.score.requested.v1");
    } finally {
      if (prevFlag === undefined) delete process.env.AI_SCORE_ENABLED;
      else process.env.AI_SCORE_ENABLED = prevFlag;
      if (prevVia === undefined) delete process.env.AI_SCORE_VIA_QUEUE;
      else process.env.AI_SCORE_VIA_QUEUE = prevVia;
    }
  });

  it("no-ops by default (inline mode)", async () => {
    const prevFlag = process.env.AI_SCORE_ENABLED;
    const prevVia = process.env.AI_SCORE_VIA_QUEUE;
    process.env.AI_SCORE_ENABLED = "true";
    delete process.env.AI_SCORE_VIA_QUEUE;
    try {
      const calls = [];
      const events = await buildScoreEventsForCveIds(["CVE-2024-0001"], {
        producer: { service: "test", version: "0" },
        tag: "unit"
      });
      const n = publishScoreEvents((ex, rk, body) => calls.push({ ex, rk, body }), events);
      assert.equal(n, 0);
      assert.equal(calls.length, 0);
    } finally {
      if (prevFlag === undefined) delete process.env.AI_SCORE_ENABLED;
      else process.env.AI_SCORE_ENABLED = prevFlag;
      if (prevVia === undefined) delete process.env.AI_SCORE_VIA_QUEUE;
      else process.env.AI_SCORE_VIA_QUEUE = prevVia;
    }
  });

  it("no-ops when score disabled", async () => {
    const prevFlag = process.env.AI_SCORE_ENABLED;
    const prevVia = process.env.AI_SCORE_VIA_QUEUE;
    process.env.AI_SCORE_ENABLED = "false";
    process.env.AI_SCORE_VIA_QUEUE = "true";
    try {
      const calls = [];
      const events = await buildScoreEventsForCveIds(["CVE-2024-0001"], {
        producer: { service: "test", version: "0" },
        tag: "unit"
      });
      const n = publishScoreEvents((ex, rk, body) => calls.push({ ex, rk, body }), events);
      assert.equal(n, 0);
      assert.equal(calls.length, 0);
    } finally {
      if (prevFlag === undefined) delete process.env.AI_SCORE_ENABLED;
      else process.env.AI_SCORE_ENABLED = prevFlag;
      if (prevVia === undefined) delete process.env.AI_SCORE_VIA_QUEUE;
      else process.env.AI_SCORE_VIA_QUEUE = prevVia;
    }
  });
});

describe("ai.enrich backpressure helpers", () => {
  it("defaults max depth to 2000 and treats 0 as unlimited", () => {
    assert.equal(getAiEnrichMaxDepth({}), 2000);
    assert.equal(getAiEnrichMaxDepth({ AI_ENRICH_MAX_DEPTH: "500" }), 500);
    assert.equal(getAiEnrichMaxDepth({ AI_ENRICH_MAX_DEPTH: "0" }), 0);
    assert.equal(shouldSkipEnrichPublishForDepth(2000, 2000), true);
    assert.equal(shouldSkipEnrichPublishForDepth(1999, 2000), false);
    assert.equal(shouldSkipEnrichPublishForDepth(99999, 0), false);
  });

  it("builds stable inflight keys and enrich envelopes", () => {
    assert.equal(
      enrichInflightIdempotencyKey("CVE-2026-1", "translate"),
      "enrich:inflight:CVE-2026-1:translate"
    );
    const ev = buildEnrichRequestedEvent({
      cveId: "CVE-2026-1",
      producer: { service: "test", version: "0" },
      idempotencyKey: "enrich:hot24h:CVE-2026-1:x:translate",
      raw: { a: 1 }
    });
    assert.equal(ev.type, "vuln.enrich.requested.v1");
    assert.equal(ev.payload.cveId, "CVE-2026-1");
    const calls = [];
    publishEnrichRequested((ex, rk, body, opts) => calls.push({ ex, rk, body, opts }), ev, {
      priority: 9
    });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].ex, "vuln.events");
    assert.equal(calls[0].rk, "vuln.enrich.requested.v1");
    assert.equal(calls[0].opts.priority, 9);
  });
});

describe("inline risk score", () => {
  it("extracts CVSS from NVD-like raw", () => {
    const score = extractCvssBaseScoreFromNvdRaw({
      metrics: {
        cvssMetricV31: [{ cvssData: { baseScore: 9.8 } }]
      }
    });
    assert.equal(score, 9.8);
  });

  it("upserts risk_score via mock db", async () => {
    const sqls = [];
    const db = {
      async query(sql, params) {
        sqls.push({ sql, params });
        if (sql.includes("FROM cve ")) {
          return {
            rows: [
              {
                raw: { metrics: { cvssMetricV31: [{ cvssData: { baseScore: 7.5 } }] } },
                published_at: new Date("2026-01-01T00:00:00.000Z")
              }
            ],
            rowCount: 1
          };
        }
        if (sql.includes("FROM epss_score")) {
          return { rows: [{ score: 0.42 }], rowCount: 1 };
        }
        if (sql.includes("FROM kev ")) {
          return { rows: [], rowCount: 0 };
        }
        if (sql.includes("FROM cve_exploit_intel")) {
          return { rows: [], rowCount: 0 };
        }
        if (sql.includes("INSERT INTO risk_score")) {
          return { rows: [], rowCount: 1 };
        }
        return { rows: [], rowCount: 0 };
      }
    };
    const r = await upsertRiskScoreForCve(db, "CVE-2026-1");
    assert.equal(r.cveId, "CVE-2026-1");
    assert.equal(typeof r.score, "number");
    assert.ok(r.score >= 0 && r.score <= 100);
    assert.ok(sqls.some((s) => String(s.sql).includes("INSERT INTO risk_score")));
  });

  it("applyRiskScoresForCveIds uses inline path by default", async () => {
    const prevVia = process.env.AI_SCORE_VIA_QUEUE;
    delete process.env.AI_SCORE_VIA_QUEUE;
    try {
      let inserts = 0;
      const db = {
        async query(sql) {
          if (sql.includes("INSERT INTO risk_score")) {
            inserts++;
            return { rows: [], rowCount: 1 };
          }
          return { rows: [], rowCount: 0 };
        }
      };
      const n = await applyRiskScoresForCveIds(db, ["CVE-2026-1", "CVE-2026-2"], { concurrency: 2 });
      assert.equal(n, 2);
      assert.equal(inserts, 2);
    } finally {
      if (prevVia === undefined) delete process.env.AI_SCORE_VIA_QUEUE;
      else process.env.AI_SCORE_VIA_QUEUE = prevVia;
    }
  });
});

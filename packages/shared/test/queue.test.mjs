import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  EnrichCveRequestedEventSchema,
  publishScoreEvents,
  buildScoreEventsForCveIds,
  isAiScoreEnabled,
  getAiEnrichMaxDepth,
  shouldSkipEnrichPublishForDepth,
  enrichInflightIdempotencyKey,
  buildEnrichRequestedEvent,
  publishEnrichRequested
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

describe("publishScoreEvents", () => {
  it("publishes to vuln.events with count when enabled", async () => {
    const prevFlag = process.env.AI_SCORE_ENABLED;
    process.env.AI_SCORE_ENABLED = "true";
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
    }
  });

  it("no-ops when score disabled", async () => {
    const prevFlag = process.env.AI_SCORE_ENABLED;
    process.env.AI_SCORE_ENABLED = "false";
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

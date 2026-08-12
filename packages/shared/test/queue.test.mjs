import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  EnrichCveRequestedEventSchema,
  publishScoreEvents,
  buildScoreEventsForCveIds,
  isAiScoreEnabled
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

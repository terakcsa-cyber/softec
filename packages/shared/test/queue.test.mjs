import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  EnrichCveRequestedEventSchema,
  publishScoreEvents,
  buildScoreEventsForCveIds
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

describe("publishScoreEvents", () => {
  it("publishes to vuln.events with count", async () => {
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
  });
});

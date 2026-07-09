import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { counter, gauge, renderMetrics } from "../dist/index.js";

describe("prometheus metrics", () => {
  it("counter and gauge register with vuln_ prefix", async () => {
    const c = counter("test_counter_unit", "test help");
    c.inc();
    const g = gauge("test_gauge_unit", "gauge help");
    g.set(3);
    const body = await renderMetrics();
    assert.match(body, /vuln_test_counter_unit/);
    assert.match(body, /vuln_test_gauge_unit/);
  });

  it("reuses existing metric on second call", () => {
    const a = counter("test_reuse_counter", "reuse");
    const b = counter("test_reuse_counter", "reuse");
    assert.equal(a, b);
  });
});

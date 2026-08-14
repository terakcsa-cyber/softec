import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  CVE_HOT_WINDOW_HOURS,
  computeUnifiedRiskScoreV2,
  hot24ScoreHourBucket,
  hot24ScoreIdempotencyKey,
  isPublishedWithinHours,
  buildHashedScoreIdempotencyKey,
  buildScoreRequestedEvent,
  interpretBduFixStatus,
  interpretBduExploitStatus,
  resolveBduHasFix
} from "../dist/index.js";

describe("published-window", () => {
  it("isPublishedWithinHours respects 24h window", () => {
    const now = Date.now();
    const fresh = new Date(now - 2 * 60 * 60 * 1000).toISOString();
    const stale = new Date(now - 48 * 60 * 60 * 1000).toISOString();
    assert.equal(isPublishedWithinHours(fresh, CVE_HOT_WINDOW_HOURS, now), true);
    assert.equal(isPublishedWithinHours(stale, CVE_HOT_WINDOW_HOURS, now), false);
    assert.equal(isPublishedWithinHours(null, CVE_HOT_WINDOW_HOURS, now), false);
  });
});

describe("hot24-score-sweep keys", () => {
  it("hour bucket is stable within the same hour", () => {
    const t = new Date("2026-07-09T14:22:00.000Z");
    assert.equal(hot24ScoreHourBucket(t), "2026-07-09T14");
    assert.equal(hot24ScoreIdempotencyKey("CVE-2024-1", "2026-07-09T14"), "score:hot24h:CVE-2024-1:2026-07-09T14");
  });
});

describe("risk scoring v2", () => {
  it("KEV CVE scores higher than no-exploit baseline", () => {
    const base = computeUnifiedRiskScoreV2({ cvss: 7.5, epss: 0.1, exploitKnown: false });
    const kev = computeUnifiedRiskScoreV2({ cvss: 7.5, epss: 0.1, exploitKnown: true });
    assert.ok(kev.score > base.score);
    assert.equal(kev.modelVersion, "rule_v2");
  });

  it("clamps score to 0..100", () => {
    const high = computeUnifiedRiskScoreV2({
      cvss: 10,
      epss: 1,
      exploitKnown: true,
      hasPublicExploit: true,
      tgMentions24h: 100
    });
    assert.ok(high.score >= 0 && high.score <= 100);
  });
});

describe("bdu status parsing", () => {
  it("treats official fix without «имеется» as has-fix", () => {
    assert.equal(interpretBduFixStatus("Официальное исправление"), true);
    assert.equal(interpretBduFixStatus("Официальное исправление имеется"), true);
    assert.equal(interpretBduFixStatus("Временное решение"), true);
  });

  it("does not treat «не имеется» / отсутствует as has-fix", () => {
    assert.equal(interpretBduFixStatus("Официальное исправление отсутствует"), false);
    assert.equal(interpretBduFixStatus("Исправление не имеется"), false);
    assert.equal(interpretBduFixStatus("Недоступно"), false);
  });

  it("does not treat «существование … не подтверждено» as exploit", () => {
    assert.equal(interpretBduExploitStatus("Существование эксплойта не подтверждено"), false);
    assert.equal(interpretBduExploitStatus("Эксплуатация отсутствует"), false);
    assert.equal(interpretBduExploitStatus("Эксплуатация существует"), true);
  });

  it("prefers status text over stale has_fix flag", () => {
    assert.equal(resolveBduHasFix({ fixStatus: "Официальное исправление имеется", hasFix: false }), true);
    assert.equal(resolveBduHasFix({ fixStatus: "Официальное исправление отсутствует", hasFix: true }), false);
  });
});

describe("score-request", () => {
  it("builds deterministic hashed idempotency keys", async () => {
    const seed = { t: "epss", cveId: "CVE-2024-1234", ts: "2026-07-09" };
    const a = await buildHashedScoreIdempotencyKey(seed);
    const b = await buildHashedScoreIdempotencyKey(seed);
    assert.equal(a, b);
    assert.ok(a.startsWith("score:epss:"));
  });

  it("buildScoreRequestedEvent includes cveId and producer", () => {
    const env = buildScoreRequestedEvent({
      cveId: "CVE-2024-1",
      producer: { service: "test", version: "0" },
      idempotencyKey: "score:test",
      ts: "2026-07-09T00:00:00.000Z"
    });
    assert.equal(env.type, "vuln.score.requested.v1");
    assert.equal(env.payload.cveId, "CVE-2024-1");
    assert.equal(env.producer.service, "test");
  });
});

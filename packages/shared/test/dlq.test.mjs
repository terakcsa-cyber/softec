import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { describe, it } from "node:test";
import { replayDlqMessages, QueueEventType, buildScoreRequestedEvent } from "../dist/index.js";

function enrichEnvelope(cveId = "CVE-2024-0001") {
  return {
    id: randomUUID(),
    type: QueueEventType.EnrichCveRequested,
    ts: new Date().toISOString(),
    producer: { service: "test", version: "0" },
    idempotencyKey: "enrich:test:key01",
    payload: { cveId, source: "nvd", raw: {} }
  };
}

function scoreEnvelope(cveId = "CVE-2024-0002") {
  return buildScoreRequestedEvent({
    cveId,
    producer: { service: "test", version: "0" },
    idempotencyKey: "score:test:key01"
  });
}

describe("replayDlqMessages", () => {
  it("replays valid enrich and score messages", async () => {
    const prevFlag = process.env.AI_SCORE_ENABLED;
    const prevVia = process.env.AI_SCORE_VIA_QUEUE;
    const prevEnrichVia = process.env.AI_ENRICH_VIA_QUEUE;
    const prevEngine = process.env.TEXT_ENGINE;
    process.env.AI_SCORE_ENABLED = "true";
    process.env.AI_SCORE_VIA_QUEUE = "true";
    process.env.AI_ENRICH_VIA_QUEUE = "true";
    process.env.TEXT_ENGINE = "llm";
    try {
      const queue = ["dlq.ai.enrich"];
      const bodies = [enrichEnvelope(), scoreEnvelope()];
      let idx = 0;
      const published = [];

      const channel = {
        async assertExchange() {},
        async get(_q, { noAck }) {
          assert.equal(noAck, false);
          if (idx >= bodies.length) return false;
          const body = bodies[idx++];
          return { content: Buffer.from(JSON.stringify(body), "utf8") };
        },
        ack() {},
        nack(_msg, _all, requeue) {
          assert.equal(requeue, true);
        },
        publish(ex, rk, buf, opts) {
          published.push({ ex, rk, body: JSON.parse(buf.toString("utf8")), opts });
          return true;
        }
      };

      const res = await replayDlqMessages(channel, { queues: queue, limitPerQueue: 10 });
      assert.equal(res.replayed, 2);
      assert.equal(res.skipped, 0);
      assert.equal(published.length, 2);
      assert.match(published[0].body.idempotencyKey, /:dlq:/);
      assert.equal(published[0].rk, "vuln.enrich.requested.v1");
      assert.equal(published[1].rk, "vuln.score.requested.v1");
    } finally {
      if (prevFlag === undefined) delete process.env.AI_SCORE_ENABLED;
      else process.env.AI_SCORE_ENABLED = prevFlag;
      if (prevVia === undefined) delete process.env.AI_SCORE_VIA_QUEUE;
      else process.env.AI_SCORE_VIA_QUEUE = prevVia;
      if (prevEnrichVia === undefined) delete process.env.AI_ENRICH_VIA_QUEUE;
      else process.env.AI_ENRICH_VIA_QUEUE = prevEnrichVia;
      if (prevEngine === undefined) delete process.env.TEXT_ENGINE;
      else process.env.TEXT_ENGINE = prevEngine;
    }
  });

  it("skips score replay when scoring is inline (default)", async () => {
    const prevFlag = process.env.AI_SCORE_ENABLED;
    const prevVia = process.env.AI_SCORE_VIA_QUEUE;
    process.env.AI_SCORE_ENABLED = "true";
    delete process.env.AI_SCORE_VIA_QUEUE;
    try {
      let nacked = 0;
      const channel = {
        async assertExchange() {},
        async get() {
          return { content: Buffer.from(JSON.stringify(scoreEnvelope()), "utf8") };
        },
        ack() {},
        nack() {
          nacked++;
        },
        publish() {
          throw new Error("should not publish score when inline");
        }
      };
      const res = await replayDlqMessages(channel, {
        queues: ["dlq.ai.score"],
        limitPerQueue: 1
      });
      assert.equal(res.replayed, 0);
      assert.equal(res.skipped, 1);
      assert.equal(nacked, 1);
    } finally {
      if (prevFlag === undefined) delete process.env.AI_SCORE_ENABLED;
      else process.env.AI_SCORE_ENABLED = prevFlag;
      if (prevVia === undefined) delete process.env.AI_SCORE_VIA_QUEUE;
      else process.env.AI_SCORE_VIA_QUEUE = prevVia;
    }
  });

  it("skips score replay when ai.score disabled", async () => {
    const prevFlag = process.env.AI_SCORE_ENABLED;
    process.env.AI_SCORE_ENABLED = "false";
    try {
      let nacked = 0;
      const channel = {
        async assertExchange() {},
        async get() {
          return { content: Buffer.from(JSON.stringify(scoreEnvelope()), "utf8") };
        },
        ack() {},
        nack() {
          nacked++;
        },
        publish() {
          throw new Error("should not publish score when disabled");
        }
      };
      const res = await replayDlqMessages(channel, {
        queues: ["dlq.ai.score"],
        limitPerQueue: 1
      });
      assert.equal(res.replayed, 0);
      assert.equal(res.skipped, 1);
      assert.equal(nacked, 1);
    } finally {
      if (prevFlag === undefined) delete process.env.AI_SCORE_ENABLED;
      else process.env.AI_SCORE_ENABLED = prevFlag;
    }
  });

  it("nacks invalid JSON without ack", async () => {
    let nacked = 0;
    let acked = 0;
    const channel = {
      async assertExchange() {},
      async get() {
        return { content: Buffer.from("not-json", "utf8") };
      },
      ack() {
        acked++;
      },
      nack(_m, _a, requeue) {
        assert.equal(requeue, true);
        nacked++;
      },
      publish() {
        return true;
      }
    };

    const res = await replayDlqMessages(channel, {
      queues: ["dlq.ai.enrich"],
      limitPerQueue: 1
    });
    assert.equal(res.skipped, 1);
    assert.equal(res.replayed, 0);
    assert.equal(nacked, 1);
    assert.equal(acked, 0);
  });
});

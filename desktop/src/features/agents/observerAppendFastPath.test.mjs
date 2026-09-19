import assert from "node:assert/strict";
import test from "node:test";
import {
  getAgentObserverSnapshot,
  getAgentTranscript,
  injectObserverEventsForE2E,
  resetAgentObserverStore,
  subscribeAgentObserverEventBatches,
} from "./observerRelayStore.ts";
import { buildTranscript } from "./ui/agentSessionTranscript.ts";

const agent = "a".repeat(64);
function event(seq, timestamp = "2026-08-01T00:00:00Z") {
  return {
    seq,
    timestamp,
    kind: "acp_read",
    agentIndex: 0,
    channelId: "channel",
    sessionId: "session",
    turnId: "turn",
    payload: {
      method: "session/update",
      params: {
        sessionId: "session",
        update: {
          sessionUpdate: "agent_message_chunk",
          content: { type: "text", text: `${seq} ` },
        },
      },
    },
  };
}

test("append, duplicate, late and trimmed journals match full transcript replay", () => {
  resetAgentObserverStore();
  const batches = [];
  const stop = subscribeAgentObserverEventBatches((batch) =>
    batches.push(batch),
  );
  const range = (first, last) =>
    Array.from({ length: last - first + 1 }, (_, i) => event(first + i));
  const stages = [
    {
      input: [event(1), event(2), event(2), event(3)],
      retained: range(1, 3),
      accepted: range(1, 3),
    },
    {
      input: [event(5), event(4), event(5)],
      retained: range(1, 5),
      accepted: range(4, 5),
    },
    {
      input: [event(0, "2026-07-31T23:59:59Z")],
      retained: [event(0, "2026-07-31T23:59:59Z"), ...range(1, 5)],
      accepted: [event(0, "2026-07-31T23:59:59Z")],
    },
    // One overflowing envelope trims to 2,700. Only retained additions publish.
    {
      input: range(6, 3005),
      retained: range(306, 3005),
      accepted: range(306, 3005),
    },
    {
      input: [event(3006), event(2999)],
      retained: range(306, 3006),
      accepted: [event(3006)],
    },
    // Replays at and below the eviction floor cannot consume the headroom.
    {
      input: [event(0, "2026-07-31T23:59:59Z"), event(305), event(306)],
      retained: range(306, 3006),
      accepted: [],
    },
    // Hysteresis permits growth back to 3,000 before the next trim.
    {
      input: range(3007, 3305),
      retained: range(306, 3305),
      accepted: range(3007, 3305),
    },
    {
      input: [event(3306)],
      retained: range(607, 3306),
      accepted: [event(3306)],
    },
    {
      input: [event(606), event(607)],
      retained: range(607, 3306),
      accepted: [],
    },
  ];
  try {
    for (const { input, retained, accepted } of stages) {
      const previousBatchCount = batches.length;
      injectObserverEventsForE2E(agent, input);
      assert.deepEqual(getAgentObserverSnapshot(agent).events, retained);
      assert.deepEqual(getAgentTranscript(agent), buildTranscript(retained));
      assert.equal(
        batches.length,
        previousBatchCount + (accepted.length ? 1 : 0),
      );
      if (accepted.length) {
        assert.deepEqual(
          batches.at(-1).map((entry) => entry.event),
          accepted,
        );
      }
    }
  } finally {
    stop();
    resetAgentObserverStore();
  }
});

test("invalid timestamps preserve legacy dedup under non-transitive ordering", () => {
  resetAgentObserverStore();
  const accepted = [];
  const stop = subscribeAgentObserverEventBatches((batch) =>
    accepted.push(...batch),
  );
  try {
    const invalid = event(2, "invalid");
    injectObserverEventsForE2E(agent, [
      invalid,
      event(2, "2026-01-01"),
      event(1, "2026-01-02"),
    ]);
    const before = getAgentObserverSnapshot(agent).events;
    injectObserverEventsForE2E(agent, [invalid]);
    assert.deepEqual(getAgentObserverSnapshot(agent).events, before);
    assert.equal(accepted.length, 3);
    assert.deepEqual(getAgentTranscript(agent), buildTranscript(before));
  } finally {
    stop();
    resetAgentObserverStore();
  }
});

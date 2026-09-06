import assert from "node:assert/strict";
import test from "node:test";
import {
  compareObserverEvents,
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
  let expected = [];
  const inputs = [
    [event(1), event(2), event(2), event(3)],
    [event(5), event(4), event(5)],
    [event(0, "2026-07-31T23:59:59Z")],
    Array.from({ length: 3000 }, (_, i) => event(i + 6)),
    [event(3006), event(2999)],
  ];
  try {
    for (const input of inputs) {
      const accepted = [];
      for (const item of input) {
        if (
          expected.some(
            (e) => e.seq === item.seq && e.timestamp === item.timestamp,
          )
        )
          continue;
        accepted.push(item);
        expected = [...expected, item].sort(compareObserverEvents).slice(-3000);
      }
      injectObserverEventsForE2E(agent, input);
      assert.deepEqual(getAgentObserverSnapshot(agent).events, expected);
      assert.deepEqual(getAgentTranscript(agent), buildTranscript(expected));
      assert.deepEqual(
        batches.at(-1).map((entry) => entry.event),
        accepted.sort(compareObserverEvents),
      );
    }
  } finally {
    stop();
    resetAgentObserverStore();
  }
});

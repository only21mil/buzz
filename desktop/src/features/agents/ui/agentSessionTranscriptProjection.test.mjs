import assert from "node:assert/strict";
import test from "node:test";

import { buildTranscriptState } from "./agentSessionTranscript.ts";
import { projectTranscriptEvents } from "./agentSessionTranscriptProjection.ts";

const baseEvent = {
  timestamp: "2026-08-30T12:00:00.000Z",
  kind: "turn_started",
  agentIndex: 0,
  channelId: "channel-1",
  sessionId: "session-1",
  turnId: "turn-1",
  payload: { triggeringEventIds: [] },
};

function lifecycleEvent(seq, kind = "turn_started") {
  return {
    ...baseEvent,
    seq,
    kind,
    timestamp: `2026-08-30T12:00:${String(seq).padStart(2, "0")}.000Z`,
  };
}

test("projectTranscriptEvents parses only an appended event suffix", () => {
  const first = lifecycleEvent(1);
  const second = lifecycleEvent(2, "turn_completed");
  const initial = projectTranscriptEvents(null, [first]);
  const firstItem = initial.state.items[0];
  const appended = projectTranscriptEvents(initial, [first, second]);

  assert.equal(
    appended.state.items[0],
    firstItem,
    "append projection preserves objects produced for the retained prefix",
  );
  assert.deepEqual(
    appended.state.items,
    buildTranscriptState([first, second]).items,
  );
});

test("projectTranscriptEvents rebuilds when archive history is prepended", () => {
  const older = lifecycleEvent(1);
  const current = lifecycleEvent(2);
  const initial = projectTranscriptEvents(null, [current]);
  const rebuilt = projectTranscriptEvents(initial, [older, current]);

  assert.notEqual(rebuilt.state.items[1], initial.state.items[0]);
  assert.deepEqual(
    rebuilt.state.items,
    buildTranscriptState([older, current]).items,
  );
});

test("projectTranscriptEvents rebuilds when an existing event object changes", () => {
  const first = lifecycleEvent(1);
  const second = lifecycleEvent(2, "turn_completed");
  const initial = projectTranscriptEvents(null, [first, second]);
  const replacement = { ...first, payload: { triggeringEventIds: ["event"] } };
  const rebuilt = projectTranscriptEvents(initial, [replacement, second]);

  assert.notEqual(rebuilt.state.items[0], initial.state.items[0]);
  assert.deepEqual(
    rebuilt.state.items,
    buildTranscriptState([replacement, second]).items,
  );
});

test("projectTranscriptEvents rebuilds when the live event window trims", () => {
  const first = lifecycleEvent(1);
  const second = lifecycleEvent(2);
  const initial = projectTranscriptEvents(null, [first, second]);
  const rebuilt = projectTranscriptEvents(initial, [second]);

  assert.notEqual(rebuilt.state.items[0], initial.state.items[1]);
  assert.deepEqual(rebuilt.state.items, buildTranscriptState([second]).items);
});

test("projectTranscriptEvents reuses a projection for the same event window", () => {
  const events = [lifecycleEvent(1)];
  const initial = projectTranscriptEvents(null, events);

  assert.equal(projectTranscriptEvents(initial, events), initial);
});

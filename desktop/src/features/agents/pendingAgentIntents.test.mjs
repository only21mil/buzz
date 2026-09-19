import assert from "node:assert/strict";
import { test } from "node:test";
import {
  requestOpenCreateAgent,
  consumePendingOpenCreateAgent,
  resetPendingOpenCreateAgent,
} from "./openCreateAgentEvent.ts";
import {
  requestOpenEditAgent,
  consumePendingOpenEditAgent,
  resetPendingOpenEditAgent,
} from "./openEditAgentEvent.ts";
import {
  requestOpenSnapshotImport,
  consumePendingSnapshotImport,
  resetPendingSnapshotImport,
} from "./openSnapshotImportFromUrlEvent.ts";

test("community reset discards pending create, edit and snapshot navigation", (t) => {
  const previous = globalThis.window;
  globalThis.window = new EventTarget();
  t.after(() => {
    globalThis.window = previous;
  });
  requestOpenCreateAgent({ channelId: "old-channel" });
  requestOpenEditAgent("old-agent", { type: "env_key", key: "MODEL" });
  requestOpenSnapshotImport({
    fileBytes: [1, 2],
    fileName: "old.json",
    snapshotKind: "agent",
  });
  resetPendingOpenCreateAgent();
  resetPendingOpenEditAgent();
  resetPendingSnapshotImport();
  assert.equal(consumePendingOpenCreateAgent(), null);
  assert.equal(consumePendingOpenEditAgent("old-agent"), false);
  assert.equal(consumePendingSnapshotImport(), null);
  requestOpenEditAgent("new-agent");
  assert.equal(consumePendingOpenEditAgent("new-agent"), true);
});

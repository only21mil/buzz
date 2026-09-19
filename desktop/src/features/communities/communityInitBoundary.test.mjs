import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const source = readFileSync(path.join(testDir, "useCommunityInit.ts"), "utf8");

function functionBody(name) {
  const start = source.indexOf(`function ${name}`);
  assert.notEqual(start, -1, `${name} must exist`);
  const nextFunction = source.indexOf("\nfunction ", start + 1);
  return source.slice(start, nextFunction === -1 ? undefined : nextFunction);
}

test("community teardown clears the process-wide timeout singleton", () => {
  assert.match(source, /import \{ clearTimeoutState \} from/);
  assert.match(functionBody("resetCommunityState"), /clearTimeoutState\(\);/);
});

test("community initialization serializes the full backend apply", () => {
  assert.match(source, /communityApplyQueue\.run\(async \(\) => \{/);
  assert.match(source, /if \(cancelled\) return;\s+await applyCommunity\(/);
});

test("community teardown clears card mint state and pending completions", () => {
  assert.match(source, /import \{ resetCardMintStore \} from/);
  assert.match(functionBody("resetCommunityState"), /resetCardMintStore\(\);/);
});

test("community teardown releases stable profile feed snapshots", () => {
  assert.match(
    functionBody("resetCommunityState"),
    /resetProfileActivityFeedScopes\(\);/,
  );
});

test("community teardown calls resetTerminalPanel", () => {
  assert.match(functionBody("resetCommunityState"), /resetTerminalPanel\(\);/);
});

test("community teardown calls resetPendingOpenCreateAgent", () => {
  assert.match(
    functionBody("resetCommunityState"),
    /resetPendingOpenCreateAgent\(\);/,
  );
});

test("community teardown calls resetPendingOpenEditAgent", () => {
  assert.match(
    functionBody("resetCommunityState"),
    /resetPendingOpenEditAgent\(\);/,
  );
});

test("community teardown calls resetPendingSnapshotImport", () => {
  assert.match(
    functionBody("resetCommunityState"),
    /resetPendingSnapshotImport\(\);/,
  );
});

test("community teardown releases reminder watermark fallbacks", () => {
  assert.match(
    functionBody("resetCommunityState"),
    /resetReminderWatermarks\(\);/,
  );
});

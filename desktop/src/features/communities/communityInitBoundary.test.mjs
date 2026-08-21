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

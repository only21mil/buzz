import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { checkCoverage } from "../../../scripts/check-web-pal-coverage.mjs";

// Enforces that every renderer-invoked Tauri command has an explicit browser
// classification (implemented / noop / capability-off). Adding a new invoke()
// call site without classifying it fails the suite.
test("web PAL coverage: every renderer command is classified", async () => {
  const manifest = JSON.parse(
    await readFile(
      new URL("../../../docs/web-pal-commands.json", import.meta.url),
      "utf8",
    ),
  );
  const coverage = JSON.parse(
    await readFile(new URL("./coverage.json", import.meta.url), "utf8"),
  );
  const result = checkCoverage(manifest, coverage);
  assert.deepEqual(result.missing, [], "unaccounted renderer commands");
  assert.deepEqual(
    result.unknown,
    [],
    "coverage claims not in renderer manifest",
  );
  assert.deepEqual(result.duplicates, [], "duplicate coverage claims");
  assert.deepEqual(result.invalid, [], "invalid coverage entries");
  assert.equal(result.ok, true);
});

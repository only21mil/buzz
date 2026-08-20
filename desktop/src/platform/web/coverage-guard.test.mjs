import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { checkCoverage } from "../../../scripts/check-web-pal-coverage.mjs";
import { createManifest } from "../../../scripts/web-pal-census.mjs";

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
  const currentManifest = await createManifest();
  assert.deepEqual(
    currentManifest.renderer.commands.map((command) => command.name),
    manifest.renderer.commands.map((command) => command.name),
    "renderer command census drift; regenerate docs/web-pal-commands.json",
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

test("web PAL coverage rejects blank and unknown pending owners", () => {
  const result = checkCoverage(
    { renderer: { commands: [{ name: "known" }] } },
    {
      implemented: [],
      noop: [],
      "capability-off": [],
      pending: { known: "   ", unknown: "lane" },
    },
  );
  assert.deepEqual(result.invalid, ["pending.known must name an owning lane"]);
  assert.deepEqual(result.unknown, ["unknown"]);
  assert.equal(result.ok, false);
});

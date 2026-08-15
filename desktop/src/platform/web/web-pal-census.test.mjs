import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  extractRendererCommandsFromSource,
  extractRustCommandsFromSource,
} from "../../../scripts/web-pal-census.mjs";

test("AST census extracts single-line, multi-line, aliased, and raw invocations", async () => {
  const fixture = await readFile(
    new URL(
      "../../../scripts/fixtures/web-pal-census-fixture.ts",
      import.meta.url,
    ),
    "utf8",
  );
  const result = extractRendererCommandsFromSource(
    fixture,
    "desktop/scripts/fixtures/web-pal-census-fixture.ts",
  );

  assert.deepEqual(
    result.commands.map((command) => command.name),
    [
      "fixture_inferred_raw",
      "fixture_multi_line",
      "fixture_raw_body",
      "fixture_single_line",
    ],
  );
  assert.equal(result.invocationCount, 5);
  assert.deepEqual(result.dynamicCalls, [
    "desktop/scripts/fixtures/web-pal-census-fixture.ts:17",
  ]);
  assert.equal(result.commands[0].payloadStyle, "raw ArrayBuffer");
  assert.equal(
    result.commands[1].callSites[0],
    "desktop/scripts/fixtures/web-pal-census-fixture.ts:10",
  );
  assert.equal(result.commands[1].payloadStyle, "json");
  assert.equal(result.commands[2].payloadStyle, "raw ArrayBuffer");
  assert.equal(
    result.commands[3].callSites[0],
    "desktop/scripts/fixtures/web-pal-census-fixture.ts:8",
  );
});

test("Rust command extraction handles module paths and cfg attributes", () => {
  const commands = extractRustCommandsFromSource(`
    tauri::Builder::default().invoke_handler(tauri::generate_handler![
      module::first_command,
      #[cfg(target_os = "macos")]
      second_command,
    ]);
  `);
  assert.deepEqual(commands, ["first_command", "second_command"]);
});

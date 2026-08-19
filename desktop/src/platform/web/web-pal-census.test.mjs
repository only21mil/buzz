import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  checkCommittedManifest,
  extractRendererCommandsFromSource,
  extractRustCommandsFromSource,
} from "../../../scripts/web-pal-census.mjs";

const execFileAsync = promisify(execFile);
const DESKTOP_DIR = fileURLToPath(new URL("../../../", import.meta.url));
const REPO_DIR = path.resolve(DESKTOP_DIR, "..");
const CENSUS_SCRIPT = fileURLToPath(
  new URL("../../../scripts/web-pal-census.mjs", import.meta.url),
);

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

test("census check is independent of the caller working directory", async () => {
  for (const cwd of [REPO_DIR, DESKTOP_DIR]) {
    const { stdout } = await execFileAsync(
      process.execPath,
      [CENSUS_SCRIPT, "--check"],
      { cwd },
    );
    assert.match(stdout, /Renderer commands: 294 distinct/);
    assert.match(stdout, /Committed manifest matches current command names/);
  }
});

test("census check rejects committed command-name drift", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "buzz-census-test-"));
  const manifestPath = path.join(directory, "web-pal-commands.json");
  try {
    const manifest = JSON.parse(
      await readFile(
        path.join(DESKTOP_DIR, "docs/web-pal-commands.json"),
        "utf8",
      ),
    );
    manifest.renderer.commands.pop();
    await writeFile(manifestPath, JSON.stringify(manifest), "utf8");
    await assert.rejects(
      checkCommittedManifest({ manifestPath }),
      /renderer command drift/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

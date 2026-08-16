import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const DESKTOP_DIR = path.resolve(SCRIPT_DIR, "..");
const MANIFEST_PATH = path.join(DESKTOP_DIR, "docs", "web-pal-commands.json");
const COVERAGE_PATH = path.join(
  DESKTOP_DIR,
  "src",
  "platform",
  "web",
  "coverage.json",
);
const COVERAGE_FIELDS = ["implemented", "noop", "capability-off"];
// `pending` maps command name -> owning lane. It marks commands whose browser
// implementation is in flight elsewhere; they count as accounted-for but a
// real class (above) always supersedes a pending entry without a duplicate.
const PENDING_FIELD = "pending";

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function rendererNamesFromManifest(manifest) {
  if (!manifest?.renderer || !Array.isArray(manifest.renderer.commands)) {
    throw new Error("Manifest is missing renderer.commands");
  }
  const names = [];
  for (const command of manifest.renderer.commands) {
    if (typeof command === "string") {
      names.push(command);
    } else if (command && typeof command.name === "string") {
      names.push(command.name);
    } else {
      throw new Error(
        "Manifest renderer.commands contains an invalid command entry",
      );
    }
  }
  return [...new Set(names)].sort(compareStrings);
}

function coverageClaimsFromFile(coverage) {
  if (!coverage || typeof coverage !== "object") {
    throw new Error("Coverage file must contain a JSON object");
  }
  const claims = new Map();
  const invalid = [];
  const duplicates = [];
  for (const field of COVERAGE_FIELDS) {
    const entries = coverage[field];
    if (!Array.isArray(entries)) {
      invalid.push(`${field} must be an array`);
      continue;
    }
    for (const name of entries) {
      if (typeof name !== "string" || name.length === 0) {
        invalid.push(
          `${field} contains a non-empty string command name requirement`,
        );
        continue;
      }
      if (claims.has(name)) duplicates.push(name);
      claims.set(name, field);
    }
  }
  const pending = new Map();
  const pendingEntries = coverage[PENDING_FIELD] ?? {};
  if (
    !pendingEntries ||
    typeof pendingEntries !== "object" ||
    Array.isArray(pendingEntries)
  ) {
    invalid.push(`${PENDING_FIELD} must be an object of name -> owner`);
  } else {
    for (const [name, owner] of Object.entries(pendingEntries)) {
      if (typeof owner !== "string" || owner.trim().length === 0) {
        invalid.push(`${PENDING_FIELD}.${name} must name an owning lane`);
        continue;
      }
      if (!claims.has(name)) pending.set(name, owner);
    }
  }
  return {
    claims,
    pending,
    invalid,
    duplicates: [...new Set(duplicates)].sort(compareStrings),
  };
}

export function checkCoverage(manifest, coverage) {
  const rendererNames = rendererNamesFromManifest(manifest);
  const { claims, pending, invalid, duplicates } =
    coverageClaimsFromFile(coverage);
  const rendererSet = new Set(rendererNames);
  const missing = rendererNames.filter(
    (name) => !claims.has(name) && !pending.has(name),
  );
  const unknown = [...claims.keys(), ...pending.keys()]
    .filter((name) => !rendererSet.has(name))
    .sort(compareStrings);
  return {
    rendererNames,
    claimedNames: [...claims.keys()].sort(compareStrings),
    pendingNames: [...pending.keys()].sort(compareStrings),
    missing,
    unknown,
    invalid,
    duplicates,
    ok:
      missing.length === 0 &&
      unknown.length === 0 &&
      invalid.length === 0 &&
      duplicates.length === 0,
  };
}

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, "utf8"));
}

function printList(label, values) {
  if (values.length > 0) console.error(`${label}: ${values.join(", ")}`);
}

async function runSelfTest() {
  const result = checkCoverage(
    {
      renderer: {
        commands: [{ name: "fixture_present" }, { name: "fixture_missing" }],
      },
    },
    { implemented: ["fixture_present"], noop: [], "capability-off": [] },
  );
  if (result.ok || !result.missing.includes("fixture_missing")) {
    throw new Error(
      "self-test expected a synthetic missing command to fail coverage",
    );
  }
  console.log(
    "check-web-pal-coverage self-test passed (synthetic missing command rejected)",
  );
}

async function run() {
  if (process.argv.includes("--self-test")) {
    await runSelfTest();
    return;
  }

  const manifest = await readJson(MANIFEST_PATH);
  const coverage = await readJson(COVERAGE_PATH);
  const result = checkCoverage(manifest, coverage);
  console.log(`Renderer commands: ${result.rendererNames.length}`);
  console.log(`Claimed coverage: ${result.claimedNames.length}`);
  if (result.pendingNames.length > 0) {
    console.log(
      `Pending (owned by in-flight lanes): ${result.pendingNames.length}`,
    );
  }
  if (result.ok) {
    console.log("Web PAL coverage: PASS");
    return;
  }
  console.error("Web PAL coverage: FAIL");
  printList("Unaccounted renderer commands", result.missing);
  printList("Unknown coverage claims", result.unknown);
  printList("Duplicate coverage claims", result.duplicates);
  printList("Invalid coverage entries", result.invalid);
  process.exitCode = 1;
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  run().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}

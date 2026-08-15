import { readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const DESKTOP_DIR = path.resolve(SCRIPT_DIR, "..");
const REPO_DIR = path.resolve(DESKTOP_DIR, "..");
const SRC_DIR = path.join(DESKTOP_DIR, "src");
const RUST_LIB = path.join(DESKTOP_DIR, "src-tauri", "src", "lib.rs");
const MANIFEST_PATH = path.join(DESKTOP_DIR, "docs", "web-pal-commands.json");
const CORE_MODULE = "@tauri-apps/api/core";
const SHARED_TAURI_PATH = path.join("src", "shared", "api", "tauri.ts");

const SOURCE_EXTENSIONS = new Map([
  [".ts", ts.ScriptKind.TS],
  [".tsx", ts.ScriptKind.TSX],
]);

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isStringLiteral(node) {
  return ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node);
}

function modulePathForImport(specifier, sourcePath) {
  if (specifier === "@/shared/api/tauri") {
    return path.join(DESKTOP_DIR, SHARED_TAURI_PATH);
  }
  if (!specifier.startsWith(".")) return null;

  const candidate = path.resolve(path.dirname(sourcePath), specifier);
  const candidates = [
    candidate,
    `${candidate}.ts`,
    `${candidate}.tsx`,
    path.join(candidate, "index.ts"),
    path.join(candidate, "index.tsx"),
  ];
  return (
    candidates.find(
      (entry) =>
        path.normalize(entry) === path.join(DESKTOP_DIR, SHARED_TAURI_PATH),
    ) ?? null
  );
}

function classifyImport(specifier, sourcePath) {
  if (specifier === CORE_MODULE) return "core";
  if (modulePathForImport(specifier, sourcePath)) return "shared-tauri";
  return null;
}

function getImportedName(element) {
  return (element.propertyName ?? element.name).text;
}

function collectInvokeBindings(sourceFile, sourcePath) {
  const bindings = new Map();
  const namespaces = new Map();

  // The shared wrapper defines invokeTauri locally, then uses it throughout
  // this file. Treat that definition as the same trusted binding as imports
  // from the wrapper module; otherwise the wrapper's command surface would be
  // invisible to the renderer census.
  const normalizedSourcePath = path
    .normalize(sourcePath)
    .split(path.sep)
    .join("/");
  if (
    normalizedSourcePath === "desktop/src/shared/api/tauri.ts" ||
    normalizedSourcePath.endsWith("/desktop/src/shared/api/tauri.ts")
  ) {
    bindings.set("invokeTauri", { kind: "shared-tauri", raw: false });
  }

  for (const statement of sourceFile.statements) {
    if (!ts.isImportDeclaration(statement)) continue;
    const moduleSpecifier = statement.moduleSpecifier;
    if (!isStringLiteral(moduleSpecifier)) continue;
    const moduleKind = classifyImport(moduleSpecifier.text, sourcePath);
    if (!moduleKind || !statement.importClause) continue;

    const namedBindings = statement.importClause.namedBindings;
    if (!namedBindings) continue;

    if (ts.isNamespaceImport(namedBindings)) {
      namespaces.set(namedBindings.name.text, moduleKind);
      continue;
    }

    for (const element of namedBindings.elements) {
      const importedName = getImportedName(element);
      const localName = element.name.text;
      if (moduleKind === "core" && importedName === "invoke") {
        bindings.set(localName, {
          kind: "core",
          raw: /raw/i.test(localName),
        });
      } else if (
        moduleKind === "shared-tauri" &&
        importedName === "invokeTauri"
      ) {
        bindings.set(localName, { kind: "shared-tauri", raw: false });
      }
    }
  }

  return { bindings, namespaces };
}

function unwrapExpression(node) {
  let current = node;
  while (
    current &&
    (ts.isAsExpression(current) ||
      ts.isTypeAssertionExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isParenthesizedExpression(current) ||
      ts.isSatisfiesExpression(current))
  ) {
    current = current.expression;
  }
  return current;
}

function typeNameLooksRaw(typeNode) {
  if (!typeNode) return false;
  return /(?:ArrayBuffer|Uint8Array|Uint8ClampedArray|DataView)/.test(
    typeNode.getText(),
  );
}

function expressionLooksRaw(node, sourceFile, rawValueNames = new Set()) {
  const expression = unwrapExpression(node);
  if (!expression) return false;

  if (ts.isNewExpression(expression)) {
    const constructorName = expression.expression.getText(sourceFile);
    return /(?:ArrayBuffer|Uint8Array|Uint8ClampedArray|DataView)$/.test(
      constructorName,
    );
  }
  if (ts.isCallExpression(expression)) {
    const callee = expression.expression;
    if (
      ts.isPropertyAccessExpression(callee) &&
      callee.name.text === "arrayBuffer"
    ) {
      return true;
    }
  }
  if (ts.isIdentifier(expression)) {
    return rawValueNames.has(expression.text);
  }
  return false;
}

function collectRawValueNames(sourceFile) {
  const declarations = [];
  function visit(node) {
    if (
      (ts.isVariableDeclaration(node) || ts.isParameter(node)) &&
      ts.isIdentifier(node.name)
    ) {
      declarations.push(node);
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);

  const rawValueNames = new Set();
  let changed = true;
  while (changed) {
    changed = false;
    for (const declaration of declarations) {
      if (!typeNameLooksRaw(declaration.type)) {
        const initializer = declaration.initializer;
        const expression = unwrapExpression(initializer);
        const syntacticallyRaw =
          expressionLooksRaw(expression, sourceFile, rawValueNames) ||
          (expression &&
            ts.isIdentifier(expression) &&
            rawValueNames.has(expression.text));
        if (!syntacticallyRaw) continue;
      }
      if (!rawValueNames.has(declaration.name.text)) {
        rawValueNames.add(declaration.name.text);
        changed = true;
      }
    }
  }
  return rawValueNames;
}

function calleeBinding(callExpression, bindings, namespaces) {
  const callee = unwrapExpression(callExpression.expression);
  if (ts.isIdentifier(callee)) return bindings.get(callee.text) ?? null;
  if (
    ts.isPropertyAccessExpression(callee) &&
    ts.isIdentifier(callee.expression)
  ) {
    const moduleKind = namespaces.get(callee.expression.text);
    if (moduleKind === "core" && callee.name.text === "invoke") {
      return { kind: "core", raw: false };
    }
    if (moduleKind === "shared-tauri" && callee.name.text === "invokeTauri") {
      return { kind: "shared-tauri", raw: false };
    }
  }
  return null;
}

function payloadStyleForCall(
  callExpression,
  binding,
  sourceFile,
  rawValueNames,
) {
  if (binding.raw) return "raw ArrayBuffer";
  const body = callExpression.arguments[1];
  if (
    binding.kind === "core" &&
    body &&
    expressionLooksRaw(body, sourceFile, rawValueNames)
  ) {
    return "raw ArrayBuffer";
  }
  return "json";
}

function addCall(callsByName, name, location, payloadStyle) {
  let command = callsByName.get(name);
  if (!command) {
    command = { locations: new Set(), styles: new Set() };
    callsByName.set(name, command);
  }
  command.locations.add(location);
  command.styles.add(payloadStyle);
}

/**
 * Extract invoke calls from one TypeScript source file.
 *
 * The import binding map is deliberately used instead of matching arbitrary
 * identifiers named `invoke`: only bindings sourced from Tauri's core API or
 * Buzz's invokeTauri wrapper are renderer command calls.
 */
export function extractRendererCommandsFromSource(
  sourceText,
  sourcePath = "fixture.ts",
) {
  const extension = path.extname(sourcePath).toLowerCase();
  const scriptKind = SOURCE_EXTENSIONS.get(extension) ?? ts.ScriptKind.TS;
  const sourceFile = ts.createSourceFile(
    sourcePath,
    sourceText,
    ts.ScriptTarget.Latest,
    true,
    scriptKind,
  );
  const { bindings, namespaces } = collectInvokeBindings(
    sourceFile,
    sourcePath,
  );
  const rawValueNames = collectRawValueNames(sourceFile);
  const callsByName = new Map();
  const dynamicCalls = [];
  let invocationCount = 0;

  function visit(node) {
    if (ts.isCallExpression(node)) {
      const binding = calleeBinding(node, bindings, namespaces);
      if (binding) {
        invocationCount += 1;
        const firstArgument = unwrapExpression(node.arguments[0]);
        if (firstArgument && isStringLiteral(firstArgument)) {
          const line =
            sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile))
              .line + 1;
          addCall(
            callsByName,
            firstArgument.text,
            `${sourcePath}:${line}`,
            payloadStyleForCall(node, binding, sourceFile, rawValueNames),
          );
        } else {
          const line =
            sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile))
              .line + 1;
          dynamicCalls.push(`${sourcePath}:${line}`);
        }
      }
    }
    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return {
    commands: [...callsByName.entries()]
      .sort(([left], [right]) => compareStrings(left, right))
      .map(([name, value]) => ({
        name,
        callSites: [...value.locations].sort(compareStrings),
        payloadStyle:
          value.styles.size === 1
            ? [...value.styles][0]
            : [...value.styles].sort(compareStrings),
      })),
    invocationCount,
    dynamicCalls: dynamicCalls.sort(compareStrings),
  };
}

async function listSourceFiles(directory) {
  const entries = (await readdir(directory, { withFileTypes: true })).sort(
    (left, right) => compareStrings(left.name, right.name),
  );
  const files = [];
  for (const entry of entries) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await listSourceFiles(fullPath)));
    } else if (SOURCE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
      files.push(fullPath);
    }
  }
  return files;
}

function relativeRepoPath(filePath) {
  return path.relative(REPO_DIR, filePath).split(path.sep).join("/");
}

export async function extractRendererCommands(sourceDirectory = SRC_DIR) {
  const files = await listSourceFiles(sourceDirectory);
  const aggregate = new Map();
  const dynamicCalls = [];
  let invocationCount = 0;
  for (const filePath of files) {
    const sourceText = await readFile(filePath, "utf8");
    const result = extractRendererCommandsFromSource(
      sourceText,
      relativeRepoPath(filePath),
    );
    invocationCount += result.invocationCount;
    dynamicCalls.push(...result.dynamicCalls);
    for (const command of result.commands) {
      let entry = aggregate.get(command.name);
      if (!entry) {
        entry = { locations: new Set(), styles: new Set() };
        aggregate.set(command.name, entry);
      }
      for (const location of command.callSites) entry.locations.add(location);
      for (const style of Array.isArray(command.payloadStyle)
        ? command.payloadStyle
        : [command.payloadStyle]) {
        entry.styles.add(style);
      }
    }
  }
  return {
    commands: [...aggregate.entries()]
      .sort(([left], [right]) => compareStrings(left, right))
      .map(([name, value]) => ({
        name,
        callSites: [...value.locations].sort(compareStrings),
        payloadStyle:
          value.styles.size === 1
            ? [...value.styles][0]
            : [...value.styles].sort(compareStrings),
      })),
    invocationCount,
    dynamicCalls: dynamicCalls.sort(compareStrings),
  };
}

function skipRustString(source, index) {
  if (source[index] === '"') {
    let cursor = index + 1;
    while (cursor < source.length) {
      if (source[cursor] === "\\") {
        cursor += 2;
      } else if (source[cursor] === '"') {
        return cursor + 1;
      } else {
        cursor += 1;
      }
    }
    return source.length;
  }
  const raw = source.slice(index).match(/^r(#+)?"/);
  if (!raw) return index;
  const hashes = raw[1] ?? "";
  const terminator = `"${hashes}`;
  const end = source.indexOf(terminator, index + raw[0].length);
  return end === -1 ? source.length : end + terminator.length;
}

function findGenerateHandlerBody(source) {
  const marker = "tauri::generate_handler![";
  const markerStart = source.indexOf(marker);
  if (markerStart === -1)
    throw new Error("Could not find tauri::generate_handler![...] in lib.rs");
  const bodyStart = markerStart + marker.length;
  let depth = 1;
  let cursor = bodyStart;
  let blockCommentDepth = 0;
  while (cursor < source.length) {
    if (blockCommentDepth > 0) {
      if (source.startsWith("/*", cursor)) {
        blockCommentDepth += 1;
        cursor += 2;
      } else if (source.startsWith("*/", cursor)) {
        blockCommentDepth -= 1;
        cursor += 2;
      } else {
        cursor += 1;
      }
      continue;
    }
    if (source.startsWith("//", cursor)) {
      const newline = source.indexOf("\n", cursor + 2);
      cursor = newline === -1 ? source.length : newline + 1;
      continue;
    }
    if (source.startsWith("/*", cursor)) {
      blockCommentDepth = 1;
      cursor += 2;
      continue;
    }
    const next = skipRustString(source, cursor);
    if (next !== cursor) {
      cursor = next;
      continue;
    }
    if (source[cursor] === "[") depth += 1;
    if (source[cursor] === "]") {
      depth -= 1;
      if (depth === 0) return source.slice(bodyStart, cursor);
    }
    cursor += 1;
  }
  throw new Error("Unterminated tauri::generate_handler![...] in lib.rs");
}

function stripRustAttributes(source) {
  let output = "";
  let cursor = 0;
  while (cursor < source.length) {
    if (source.startsWith("#[", cursor)) {
      let depth = 1;
      let end = cursor + 2;
      while (end < source.length && depth > 0) {
        const next = skipRustString(source, end);
        if (next !== end) {
          end = next;
          continue;
        }
        if (source[end] === "[") depth += 1;
        if (source[end] === "]") depth -= 1;
        end += 1;
      }
      output += " ".repeat(Math.max(1, end - cursor));
      cursor = end;
    } else {
      output += source[cursor];
      cursor += 1;
    }
  }
  return output;
}

export function extractRustCommandsFromSource(source) {
  const body = stripRustAttributes(findGenerateHandlerBody(source));
  const commands = new Set();
  for (const entry of body.split(",")) {
    const match = entry.match(
      /^\s*([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)\s*$/,
    );
    if (!match) continue;
    const pathName = match[1];
    const separator = pathName.lastIndexOf("::");
    commands.add(separator === -1 ? pathName : pathName.slice(separator + 2));
  }
  return [...commands].sort(compareStrings);
}

export async function extractRustCommands(rustPath = RUST_LIB) {
  return extractRustCommandsFromSource(await readFile(rustPath, "utf8"));
}

export function buildManifest(renderer, rustCommands) {
  const rendererNames = new Set(
    renderer.commands.map((command) => command.name),
  );
  const rustNames = new Set(rustCommands);
  return {
    schemaVersion: 1,
    renderer: {
      commandCount: renderer.commands.length,
      invocationCount: renderer.invocationCount,
      dynamicCallCount: renderer.dynamicCalls.length,
      dynamicCalls: renderer.dynamicCalls,
      commands: renderer.commands,
    },
    rust: {
      commandCount: rustCommands.length,
      commands: rustCommands,
    },
    diff: {
      rendererOnly: [...rendererNames]
        .filter((name) => !rustNames.has(name))
        .sort(compareStrings),
      rustOnly: [...rustNames]
        .filter((name) => !rendererNames.has(name))
        .sort(compareStrings),
    },
  };
}

export async function generateManifest({ outputPath = MANIFEST_PATH } = {}) {
  const [renderer, rustCommands] = await Promise.all([
    extractRendererCommands(),
    extractRustCommands(),
  ]);
  const manifest = buildManifest(renderer, rustCommands);
  await writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  return manifest;
}

function printSummary(manifest) {
  const rendererCount = manifest.renderer.commandCount;
  const rustCount = manifest.rust.commandCount;
  const rendererOnly = manifest.diff.rendererOnly.length;
  const rustOnly = manifest.diff.rustOnly.length;
  console.log("Web PAL command census");
  console.log(
    `Renderer commands: ${rendererCount} distinct (${manifest.renderer.invocationCount} literal/dynamic invoke calls scanned)`,
  );
  console.log(`Rust registered commands: ${rustCount} distinct`);
  console.log(`Diff: ${rendererOnly} renderer-only, ${rustOnly} rust-only`);
  if (manifest.renderer.dynamicCallCount > 0) {
    console.log(
      `Anomaly: ${manifest.renderer.dynamicCallCount} invoke call(s) skipped because the command argument was not a string literal`,
    );
  }
  if (rendererOnly > 0)
    console.log(`Renderer-only: ${manifest.diff.rendererOnly.join(", ")}`);
  if (rustOnly > 0)
    console.log(`Rust-only: ${manifest.diff.rustOnly.join(", ")}`);
  console.log(
    `Manifest: ${path.relative(REPO_DIR, MANIFEST_PATH).split(path.sep).join("/")}`,
  );
}

const isMain =
  process.argv[1] &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (isMain) {
  generateManifest()
    .then(printSummary)
    .catch((error) => {
      console.error(error instanceof Error ? error.message : error);
      process.exitCode = 1;
    });
}

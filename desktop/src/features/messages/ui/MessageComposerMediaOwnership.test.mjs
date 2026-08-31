import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(
  new URL("./MessageComposerMediaOwnership.tsx", import.meta.url),
  "utf8",
);

test("external media controller path does not construct an internal controller", () => {
  const ownedStart = source.indexOf("function MessageComposerWithOwnedMedia");
  const rootStart = source.indexOf("function MessageComposerRoot");
  const returnStart = source.indexOf("return React.memo", rootStart);

  assert.ok(ownedStart >= 0);
  assert.ok(rootStart > ownedStart);
  assert.ok(returnStart > rootStart);

  const ownedComponent = source.slice(ownedStart, rootStart);
  const rootComponent = source.slice(rootStart, returnStart);

  assert.equal(
    source.match(/useMediaUpload\(\{ deferUploadsUntilSend: true \}\)/g)
      ?.length,
    1,
  );
  assert.match(ownedComponent, /const mediaController = useMediaUpload/);
  assert.match(rootComponent, /if \(props\.mediaController\)/);
  assert.match(
    rootComponent,
    /<MessageComposerImpl[\s\S]*mediaController=\{props\.mediaController\}/,
  );
  assert.doesNotMatch(rootComponent, /useMediaUpload\(/);
});

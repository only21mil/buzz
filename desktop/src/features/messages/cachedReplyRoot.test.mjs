import assert from "node:assert/strict";
import test from "node:test";
import { resolveCachedReplyRootId } from "./hooks.ts";

const parent = "a".repeat(64);
const root = "b".repeat(64);
const other = "c".repeat(64);
const event = (tags) => ({ id: parent, tags });

test("cached root matches native NIP-10 root, reply fallback, and top-level order", () => {
  assert.equal(resolveCachedReplyRootId(parent, [[event([])]]), parent);
  assert.equal(
    resolveCachedReplyRootId(parent, [[], [event([["e", root, "", "root"]])]]),
    root,
  );
  assert.equal(
    resolveCachedReplyRootId(parent, [[event([["e", root, "", "reply"]])]]),
    root,
  );
  assert.equal(
    resolveCachedReplyRootId(parent, [
      [
        event([
          ["e", other, "", "root"],
          ["e", root, "", "root"],
          ["e", other, "", "reply"],
        ]),
      ],
    ]),
    root,
  );
});

test("uncached or invalid references defer to native resolution", () => {
  assert.equal(resolveCachedReplyRootId(parent, [[]]), null);
  assert.equal(
    resolveCachedReplyRootId("optimistic", [[{ id: "optimistic", tags: [] }]]),
    null,
  );
  assert.equal(
    resolveCachedReplyRootId(parent, [[event([["e", "bad", "", "root"]])]]),
    null,
  );
});

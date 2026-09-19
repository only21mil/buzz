import assert from "node:assert/strict";
import test from "node:test";

import { buildMessageEditTarget } from "./buildMessageEditTarget.ts";

const message = {
  id: "reply",
  author: "Alice",
  body: "Reply text",
  createdAt: 1,
  time: "12:00",
  depth: 1,
  parentId: "root",
};

for (const [name, tags, expected] of [
  ["thread reply", [["e", "root", "", "reply"]], true],
  [
    "broadcast reply",
    [
      ["e", "root", "", "reply"],
      ["broadcast", "1"],
    ],
    false,
  ],
  ["tagless message", undefined, false],
]) {
  test(`edit target routes ${name} to the correct composer`, () => {
    const target = buildMessageEditTarget(
      { ...message, tags },
      undefined,
      new Set(),
    );
    assert.equal(target.isThreadReply, expected);
    assert.equal(target.body, message.body);
  });
}

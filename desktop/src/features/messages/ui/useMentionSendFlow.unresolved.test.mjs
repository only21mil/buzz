import assert from "node:assert/strict";
import { test } from "node:test";
import { KEY, setup } from "./useMentionSendFlow.test-support.mjs";

test("sends a typed channel-member mention resolved by recipient extraction", async () => {
  const s = await setup();
  s.dismiss();
  s.options.mentions.memberPubkeys = new Set([KEY]);
  s.options.mentions.extractMentionPubkeys = () => [KEY];
  s.options.mentions.getDraftMentionRefs = () => [];
  s.options.mentions.getMentionDisplayName = () => "Alice";
  s.rerender();

  await s.prompt("@Alice please review");

  assert.equal(s.events("error").length, 0);
  assert.equal(s.events("SEND").length, 1);
  assert.deepEqual(s.events("SEND")[0][2], [KEY]);
});

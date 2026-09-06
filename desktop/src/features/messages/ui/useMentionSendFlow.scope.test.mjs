import assert from "node:assert/strict";
import { test } from "node:test";
import {
  setup,
  deferred,
  KEY,
  TEXT,
} from "./useMentionSendFlow.test-support.mjs";
import { initDraftStore } from "../lib/useDrafts.ts";

for (const change of [
  "author",
  "relay",
  "both",
  "away-and-back",
  "same-scope-navigation",
]) {
  test(`final recipient validation respects publication scope: ${change}`, async () => {
    const s = await setup({ lifecycle: true });
    s.dismiss();
    s.options.mentions.memberPubkeys = new Set([KEY]);
    const gate = deferred();
    s.control.publish = gate;
    s.rerender();
    let sending;
    await s.act(async () => {
      sending = s.result.current.sendMessageWithMentionFlow({
        capturedChannelId: "general",
        pendingImeta: [],
        trimmed: TEXT,
        recoveryDraftKey: "thread:a",
        sentDraftKey: "thread:a",
      });
    });
    assert.equal(s.events("publish").length, 1);
    assert.equal(s.events("SEND").length, 0);
    s.unmount();
    if (change === "author")
      initDraftStore("different-author", "wss://test.example");
    if (change === "relay")
      initDraftStore("test-author", "wss://different.example");
    if (change === "both" || change === "away-and-back")
      initDraftStore("different-author", "wss://different.example");
    if (change === "away-and-back" || change === "same-scope-navigation")
      initDraftStore("test-author", "wss://test.example");
    await s.act(async () => {
      gate.resolve();
      await sending;
    });
    const sends = s.events("SEND");
    assert.equal(sends.length, change === "same-scope-navigation" ? 1 : 0);
    if (sends.length) {
      assert.equal(sends[0][1], TEXT);
      assert.deepEqual(sends[0][2], [KEY], "exact recipient is preserved");
    }
  });
}

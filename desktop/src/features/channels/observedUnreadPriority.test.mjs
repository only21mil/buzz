import assert from "node:assert/strict";
import test from "node:test";
import { observedUnreadPriority } from "./observedUnreadPriority.ts";
import { makeObservedUnreadEvent } from "./unreadChannelCounts.ts";
import { shouldNotifyForEvent } from "../notifications/lib/shouldNotify.ts";
import { isChannelUnreadTriggerKind } from "./useLiveChannelUpdates.ts";

const self = "a".repeat(64);
const root = "b".repeat(64);
const emptyInterest = {
  participatedRootIds: new Set(),
  followedRootIds: new Set(),
  authoredRootIds: new Set(),
};
function event(tags = []) {
  return {
    id: "event",
    pubkey: "c".repeat(64),
    kind: 9,
    content: "hello",
    created_at: 100,
    tags: [["h", "room"], ...tags],
  };
}
for (const [name, tags, channelType, expected, dock] of [
  ["ordinary room", [], "stream", false, false],
  ["mention", [["p", self]], "stream", true, true],
  ["broadcast", [["broadcast", "1"]], "stream", true, true],
  [
    "relevant thread",
    [
      ["e", root, "", "root"],
      ["e", root, "", "reply"],
    ],
    "stream",
    true,
    false,
  ],
  ["DM", [], "dm", true, true],
]) {
  test(`${name}: shared live/catch-up classification preserves Dock subtotal`, () => {
    const input = event(tags);
    const classification = observedUnreadPriority(input, channelType, self);
    assert.equal(classification.isHighPriority, expected);
    const observed = makeObservedUnreadEvent({
      id: input.id,
      createdAt: input.created_at,
      rootId: classification.isThreadedReply ? root : null,
      highPriority: classification.isHighPriority,
      channelType,
      isThreadedReply: classification.isThreadedReply,
    });
    assert.equal(observed.countsTowardAppBadge, dock);
  });
}
test("unrelated or muted thread replies fail admission before priority classification", () => {
  const input = event([
    ["e", root, "", "root"],
    ["e", root, "", "reply"],
  ]);
  assert.equal(shouldNotifyForEvent(input, self, emptyInterest), false);
  assert.equal(
    shouldNotifyForEvent(input, self, {
      ...emptyInterest,
      participatedRootIds: new Set([root]),
    }),
    true,
  );
  assert.equal(
    shouldNotifyForEvent(input, self, {
      ...emptyInterest,
      participatedRootIds: new Set([root]),
      mutedRootIds: new Set([root]),
    }),
    false,
  );
});
test("agent session activity never enters message unread classification", () => {
  for (const kind of [30078, 31990, 21111])
    assert.equal(isChannelUnreadTriggerKind(kind, false), false);
});

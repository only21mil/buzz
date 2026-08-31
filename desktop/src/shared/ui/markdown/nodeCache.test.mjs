import assert from "node:assert/strict";
import test from "node:test";

import { renderToStaticMarkup } from "react-dom/server";

import {
  clearMarkdownNodeCache,
  getMarkdownNodeCacheSizeForTests,
  getMarkdownNodeCacheWeightForTests,
  getMarkdownNodeCacheWeightLimitForTests,
  getMarkdownParseCount,
  renderCachedMarkdown,
} from "./nodeCache.ts";

// The whole point of the cache is element-identity reuse across the message
// timeline's per-channel-switch remount: same parse inputs must return the
// SAME element (no re-parse), and anything that changes the parse output
// must miss.

const BASE = {
  components: {},
  content: "**bold** and `code`",
  variant: "i",
};

test("same parse inputs return the identical cached element", () => {
  clearMarkdownNodeCache();
  const first = renderCachedMarkdown({ ...BASE });
  const second = renderCachedMarkdown({ ...BASE });
  assert.equal(first, second);
  assert.match(renderToStaticMarkup(first), /<strong>bold<\/strong>/);
});

test("content changes miss the cache", () => {
  clearMarkdownNodeCache();
  const first = renderCachedMarkdown({ ...BASE });
  const second = renderCachedMarkdown({ ...BASE, content: "**bald**" });
  assert.notEqual(first, second);
});

test("customEmoji is keyed by value, not identity", () => {
  clearMarkdownNodeCache();
  const emoji = [{ shortcode: "buzz", url: "https://relay/buzz.png" }];
  const first = renderCachedMarkdown({
    ...BASE,
    content: "hi :buzz:",
    customEmoji: emoji,
  });
  // Fresh array, same values — the exact remount scenario (useMessageEmoji
  // rebuilds the array): must HIT.
  const second = renderCachedMarkdown({
    ...BASE,
    content: "hi :buzz:",
    customEmoji: [{ shortcode: "buzz", url: "https://relay/buzz.png" }],
  });
  assert.equal(first, second);
  // Same content, different emoji set (e.g. emoji added while editing —
  // custom-emoji.spec.ts Bug 2): must MISS so the new emoji renders.
  const third = renderCachedMarkdown({
    ...BASE,
    content: "hi :buzz:",
    customEmoji: [{ shortcode: "buzz", url: "https://relay/other.png" }],
  });
  assert.notEqual(first, third);
});

test("mention and channel names are part of the key", () => {
  clearMarkdownNodeCache();
  const first = renderCachedMarkdown({
    ...BASE,
    content: "ping @alice in #general",
    mentionNames: ["alice"],
    channelNames: ["general"],
  });
  const second = renderCachedMarkdown({
    ...BASE,
    content: "ping @alice in #general",
    mentionNames: ["alice", "bob"],
    channelNames: ["general"],
  });
  assert.notEqual(first, second);
});

test("render variants do not collide", () => {
  clearMarkdownNodeCache();
  const interactive = renderCachedMarkdown({ ...BASE });
  const nonInteractive = renderCachedMarkdown({ ...BASE, variant: "" });
  assert.notEqual(interactive, nonInteractive);
});

test("crafted values cannot forge key-segment boundaries", () => {
  clearMarkdownNodeCache();
  // Length-prefixed segments: a single name containing arbitrary bytes must
  // never be key-identical to two separate names, and values must not bleed
  // across the mention/channel field boundary.
  const joined = renderCachedMarkdown({
    ...BASE,
    mentionNames: ["ab"],
  });
  const split = renderCachedMarkdown({
    ...BASE,
    mentionNames: ["a", "b"],
  });
  assert.notEqual(joined, split);

  const inMentions = renderCachedMarkdown({ ...BASE, mentionNames: ["x"] });
  const inChannels = renderCachedMarkdown({ ...BASE, channelNames: ["x"] });
  assert.notEqual(inMentions, inChannels);
});

test("cache holds exactly 1000 entries and evicts the least recently used", () => {
  clearMarkdownNodeCache();
  const entries = Array.from({ length: 1000 }, (_, index) =>
    renderCachedMarkdown({ ...BASE, content: `entry-${index}` }),
  );
  assert.equal(getMarkdownNodeCacheSizeForTests(), 1000);

  // Refresh entry 0. Entry 1 is now the least recently used entry.
  assert.equal(
    renderCachedMarkdown({ ...BASE, content: "entry-0" }),
    entries[0],
  );

  renderCachedMarkdown({ ...BASE, content: "entry-1000" });
  assert.equal(getMarkdownNodeCacheSizeForTests(), 1000);
  assert.equal(
    renderCachedMarkdown({ ...BASE, content: "entry-0" }),
    entries[0],
    "a cache hit must refresh recency",
  );
  assert.notEqual(
    renderCachedMarkdown({ ...BASE, content: "entry-1" }),
    entries[1],
    "the untouched least-recently-used entry must be evicted",
  );
  assert.equal(getMarkdownNodeCacheSizeForTests(), 1000);
});

test("cache evicts large parses by retained weight before the count ceiling", () => {
  clearMarkdownNodeCache();
  const entries = Array.from({ length: 40 }, (_, index) =>
    renderCachedMarkdown({
      ...BASE,
      content: `${index}:`.padEnd(31_000, "x"),
    }),
  );

  assert.ok(
    getMarkdownNodeCacheSizeForTests() < entries.length,
    "large entries must hit the weight ceiling before the 1000-entry ceiling",
  );
  assert.ok(
    getMarkdownNodeCacheWeightForTests() <=
      getMarkdownNodeCacheWeightLimitForTests(),
    "retained weight must never exceed its configured budget",
  );

  const weightBeforeHit = getMarkdownNodeCacheWeightForTests();
  assert.equal(
    renderCachedMarkdown({
      ...BASE,
      content: "39:".padEnd(31_000, "x"),
    }),
    entries[39],
    "the newest large entry must remain cached",
  );
  assert.equal(
    getMarkdownNodeCacheWeightForTests(),
    weightBeforeHit,
    "refreshing LRU recency must not change retained-weight accounting",
  );
  assert.notEqual(
    renderCachedMarkdown({
      ...BASE,
      content: "0:".padEnd(31_000, "x"),
    }),
    entries[0],
    "the oldest large entry must be evicted by retained weight",
  );
  assert.ok(
    getMarkdownNodeCacheWeightForTests() <=
      getMarkdownNodeCacheWeightLimitForTests(),
  );

  clearMarkdownNodeCache();
  assert.equal(getMarkdownNodeCacheSizeForTests(), 0);
  assert.equal(
    getMarkdownNodeCacheWeightForTests(),
    0,
    "clearing the cache must reset retained-weight accounting exactly",
  );
});

test("oversized content and active searches parse fresh without entering the cache", () => {
  clearMarkdownNodeCache();
  const sentinel = renderCachedMarkdown({ ...BASE, content: "sentinel" });
  const sizeBefore = getMarkdownNodeCacheSizeForTests();
  const weightBefore = getMarkdownNodeCacheWeightForTests();
  const parseCountBefore = getMarkdownParseCount();

  const huge = { ...BASE, content: "a".repeat(40_000) };
  const hugeFirst = renderCachedMarkdown(huge);
  const hugeSecond = renderCachedMarkdown(huge);
  assert.notEqual(hugeFirst, hugeSecond);

  const searchFirst = renderCachedMarkdown({ ...BASE, searchQuery: "bold" });
  const searchSecond = renderCachedMarkdown({ ...BASE, searchQuery: "bold" });
  assert.notEqual(searchFirst, searchSecond);

  assert.equal(
    getMarkdownParseCount() - parseCountBefore,
    4,
    "every bypassed render must perform a fresh parse",
  );
  assert.equal(
    getMarkdownNodeCacheSizeForTests(),
    sizeBefore,
    "non-cacheable parses must not consume cache capacity",
  );
  assert.equal(
    getMarkdownNodeCacheWeightForTests(),
    weightBefore,
    "non-cacheable parses must not consume retained-weight capacity",
  );
  assert.equal(
    renderCachedMarkdown({ ...BASE, content: "sentinel" }),
    sentinel,
    "non-cacheable parses must not evict an existing cache entry",
  );
});

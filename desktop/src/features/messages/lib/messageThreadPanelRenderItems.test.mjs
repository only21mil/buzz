import assert from "node:assert/strict";
import test from "node:test";

import {
  buildLaterVisibleSiblingFlags,
  buildMessageThreadPanelRenderItems,
} from "./messageThreadPanelRenderItems.ts";

function message(id, depth, overrides = {}) {
  return {
    id,
    createdAt: Number(id.replace(/\D/g, "")) || 1,
    pubkey: "author",
    author: "Author",
    time: "12:00 PM",
    body: id,
    parentId: null,
    rootId: "root",
    depth,
    ...overrides,
  };
}

function entriesFromDepths(depths) {
  return depths.map((depth, index) => ({
    message: message(`reply-${index}`, depth),
    summary: null,
  }));
}

function referenceContinuationRails(entries, threadHead) {
  const ancestorStack = [{ index: -1, message: threadHead }];

  return entries.map((entry, index) => {
    while (
      ancestorStack.length > 0 &&
      ancestorStack.at(-1).message.depth >= entry.message.depth
    ) {
      ancestorStack.pop();
    }

    const ancestors = [...ancestorStack];
    const continuationDepths = [];
    const collapseAncestorIds = [];
    for (const ancestor of ancestors) {
      if (ancestor.message.depth === 0) continue;

      const childDepth = ancestor.message.depth + 1;
      const pathChild =
        entry.message.depth === childDepth
          ? { index, message: entry.message }
          : ancestors.find(
              (candidate) => candidate.message.depth === childDepth,
            );
      if (!pathChild) continue;

      for (
        let candidateIndex = pathChild.index + 1;
        candidateIndex < entries.length;
        candidateIndex += 1
      ) {
        const candidateDepth = entries[candidateIndex].message.depth;
        if (candidateDepth <= pathChild.message.depth) {
          if (candidateDepth === pathChild.message.depth) {
            continuationDepths.push(ancestor.message.depth);
            collapseAncestorIds.push(ancestor.message.id);
          }
          break;
        }
      }
    }

    const nextEntry = entries[index + 1];
    if (
      nextEntry &&
      nextEntry.message.depth > entry.message.depth &&
      !entry.summary
    ) {
      ancestorStack.push({ index, message: entry.message });
    }

    return { collapseAncestorIds, continuationDepths };
  });
}

test("sibling flags stop at a shallower branch", () => {
  const entries = entriesFromDepths([1, 2, 3, 2, 3, 1]);

  assert.deepEqual(buildLaterVisibleSiblingFlags(entries), [
    true,
    true,
    false,
    false,
    false,
    false,
  ]);
});

test("render items preserve nested continuation rails", () => {
  const threadHead = message("root", 0);
  const entries = entriesFromDepths([1, 2, 3, 2, 3, 1]);
  const items = buildMessageThreadPanelRenderItems({
    entries,
    isHuddleTranscript: false,
    threadHead,
  });

  assert.deepEqual(
    items.map((item) => item.continuationDepths),
    [[], [1], [1], [], [], []],
  );
  assert.deepEqual(
    items.map((item) =>
      item.collapseDepthGuideAncestors.map((ancestor) => ancestor.id),
    ),
    [[], ["reply-0"], ["reply-0"], [], [], []],
  );
});

test("a missing visible parent clears inherited rails", () => {
  const threadHead = message("root", 0);
  const entries = entriesFromDepths([1, 2, 3, 2, 3, 1]);
  entries[1].summary = {
    threadHeadId: entries[1].message.id,
    replyCount: 1,
    lastReplyAt: 3,
    participants: [],
  };

  const expected = referenceContinuationRails(entries, threadHead);
  const actual = buildMessageThreadPanelRenderItems({
    entries,
    isHuddleTranscript: false,
    threadHead,
  }).map((item) => ({
    collapseAncestorIds: item.collapseDepthGuideAncestors.map(
      (ancestor) => ancestor.id,
    ),
    continuationDepths: item.continuationDepths,
  }));

  assert.deepEqual(actual, expected);
});

test("a depth gap retains valid outer rails", () => {
  const threadHead = message("root", 0);
  const entries = entriesFromDepths([1, 2, 4, 2, 1]);
  const expected = referenceContinuationRails(entries, threadHead);
  const actual = buildMessageThreadPanelRenderItems({
    entries,
    isHuddleTranscript: false,
    threadHead,
  }).map((item) => ({
    collapseAncestorIds: item.collapseDepthGuideAncestors.map(
      (ancestor) => ancestor.id,
    ),
    continuationDepths: item.continuationDepths,
  }));

  assert.deepEqual(actual, expected);
  assert.deepEqual(actual[2].continuationDepths, [1]);
});

test("optimized rail builder matches the former scan across varied trees", () => {
  const threadHead = message("root", 0);
  let seed = 0x5eed1234;

  for (let run = 0; run < 120; run += 1) {
    const depths = [1];
    for (let index = 1; index < 80; index += 1) {
      seed = (Math.imul(seed, 1_664_525) + 1_013_904_223) >>> 0;
      const previousDepth = depths.at(-1);
      const nextDepth = 1 + (seed % (previousDepth + 1));
      depths.push(nextDepth);
    }

    const entries = entriesFromDepths(depths);
    const expected = referenceContinuationRails(entries, threadHead);
    const actual = buildMessageThreadPanelRenderItems({
      entries,
      isHuddleTranscript: false,
      threadHead,
    }).map((item) => ({
      collapseAncestorIds: item.collapseDepthGuideAncestors.map(
        (ancestor) => ancestor.id,
      ),
      continuationDepths: item.continuationDepths,
    }));

    assert.deepEqual(actual, expected, `depth sequence ${depths.join(",")}`);
  }
});

test("deep threads read depth a linear number of times", () => {
  const rowCount = 4_000;
  let depthReads = 0;
  const entries = Array.from({ length: rowCount }, (_, index) => {
    const row = message(`reply-${index}`, index + 1);
    Object.defineProperty(row, "depth", {
      configurable: true,
      get() {
        depthReads += 1;
        return index + 1;
      },
    });
    return { message: row, summary: null };
  });

  const items = buildMessageThreadPanelRenderItems({
    entries,
    isHuddleTranscript: false,
    threadHead: message("root", 0),
  });

  assert.equal(items.length, rowCount);
  assert.equal(
    items.every((item) => item.continuationDepths.length === 0),
    true,
  );
  assert.ok(
    depthReads <= rowCount * 12,
    `expected at most ${rowCount * 12} depth reads, received ${depthReads}`,
  );
});

test("wide threads compute sibling flags with one depth read per row", () => {
  const rowCount = 20_000;
  let depthReads = 0;
  const entries = Array.from({ length: rowCount }, (_, index) => {
    const row = message(`reply-${index}`, 1);
    Object.defineProperty(row, "depth", {
      configurable: true,
      get() {
        depthReads += 1;
        return 1;
      },
    });
    return { message: row, summary: null };
  });

  const flags = buildLaterVisibleSiblingFlags(entries);

  assert.equal(depthReads, rowCount);
  assert.equal(flags.at(-1), false);
  assert.equal(flags.slice(0, -1).every(Boolean), true);
});

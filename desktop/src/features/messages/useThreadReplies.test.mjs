import assert from "node:assert/strict";
import test from "node:test";

import { collectThreadAuxMessageIds } from "./useThreadReplies.ts";

const ROOT_ID = "1".repeat(64);
const REPLY_ID = "2".repeat(64);

function reply(id = REPLY_ID) {
  return {
    id,
    pubkey: "a".repeat(64),
    kind: 9,
    created_at: 1_700_000_000,
    content: "reply",
    tags: [["e", ROOT_ID]],
    sig: "sig",
  };
}

test("thread aux hydration includes the root when there are no replies", () => {
  assert.deepEqual(collectThreadAuxMessageIds(ROOT_ID, []), [ROOT_ID]);
});

test("thread aux hydration includes and deduplicates root and reply ids", () => {
  assert.deepEqual(
    collectThreadAuxMessageIds(ROOT_ID, [reply(), reply(ROOT_ID)]),
    [ROOT_ID, REPLY_ID],
  );
});

const { QueryClient } = await import("@tanstack/react-query");
const { loadThreadReplies } = await import("./useThreadReplies.ts");
const { relayClient } = await import("@/shared/api/relayClient.ts");
const { threadRepliesKey } = await import("./lib/messageQueryKeys.ts");

for (const scenario of [
  { name: "new relay", flags: [true, true], auxReads: 0 },
  {
    name: "old relay without header",
    flags: [undefined, undefined],
    auxReads: 2,
  },
  { name: "mixed pages", flags: [true, false], auxReads: 2 },
  { name: "empty new thread", flags: [true], auxReads: 0, empty: true },
  { name: "empty old thread", flags: [undefined], auxReads: 2, empty: true },
]) {
  test(`thread loading preserves auxiliary data and fallback for ${scenario.name}`, async (t) => {
    const previousWindow = globalThis.window;
    const previousFetch = relayClient.fetchAuxEventsByReference;
    const client = new QueryClient();
    const key = threadRepliesKey("channel", ROOT_ID);
    const stale = { ...reply("3".repeat(64)), content: "stale" };
    const live = { ...reply("4".repeat(64)), content: "live" };
    const aux = {
      ...reply("5".repeat(64)),
      kind: 7,
      tags: [["e", ROOT_ID]],
      content: "+",
    };
    client.setQueryData(key, [stale]);
    const commands = [];
    const backfills = [];
    relayClient.fetchAuxEventsByReference = async (_channel, ids) => {
      backfills.push(ids);
      return [];
    };
    globalThis.window = {
      __TAURI_INTERNALS__: {
        invoke: async (command, args) => {
          assert.equal(command, "get_thread_replies");
          const index = commands.length;
          commands.push(args);
          const last = index === scenario.flags.length - 1;
          if (last) client.setQueryData(key, [stale, live]);
          return {
            events: scenario.empty
              ? [aux]
              : index === 0
                ? [reply(), aux]
                : [{ ...reply("6".repeat(64)), created_at: 1_700_000_001 }],
            aux_included: scenario.flags[index],
            next_cursor: last
              ? null
              : { created_at: 1_700_000_000, event_id: REPLY_ID },
          };
        },
      },
    };
    try {
      const events = await loadThreadReplies(client, "channel", ROOT_ID);
      assert.equal(commands.length, scenario.flags.length);
      assert.equal(backfills.length, scenario.auxReads);
      t.diagnostic(
        JSON.stringify({
          scenario: scenario.name,
          threadReads: commands.length,
          auxiliaryReads: backfills.length,
        }),
      );
      assert.ok(events.some((event) => event.id === aux.id));
      assert.ok(events.some((event) => event.id === live.id));
      assert.ok(!events.some((event) => event.id === stale.id));
      if (commands.length > 1)
        assert.deepEqual(commands[1].cursor, {
          created_at: 1_700_000_000,
          event_id: REPLY_ID,
        });
      if (backfills.length)
        assert.ok(backfills.every((ids) => ids.includes(ROOT_ID)));
    } finally {
      relayClient.fetchAuxEventsByReference = previousFetch;
      globalThis.window = previousWindow;
      client.clear();
    }
  });
}

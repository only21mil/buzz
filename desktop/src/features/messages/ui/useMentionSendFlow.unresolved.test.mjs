import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import { test } from "node:test";
import ts from "typescript";
import { extractMentionPubkeys } from "../lib/extractMentionPubkeys.ts";
import { snapshotDraftMentionRefs } from "../lib/draftMentionRefs.ts";
import { normalizePubkey } from "../../../shared/lib/pubkey.ts";
import { KEY, setup } from "./useMentionSendFlow.test-support.mjs";

// Execute the production callbacks with real matching and synthetic picker state.
// Only React's memoization is replaced; no recipient or label result is stubbed.
function currentMentionCallbacks(selectedMentions, memberCandidates) {
  const source = fs.readFileSync(
    new URL("../lib/useMentions.ts", import.meta.url),
    "utf8",
  );
  const callbacks = [
    ["getMentionDisplayName", "isAgentPubkey"],
    ["extractMentionPubkeysForCurrentMentions", "getSelectedAgentPubkeys"],
  ].map(([name, next]) =>
    source.slice(
      source.indexOf(`  const ${name} =`),
      source.indexOf(`  const ${next} =`),
    ),
  );
  return vm.runInNewContext(
    ts.transpileModule(
      `${callbacks.join("\n")}
      ({ getMentionDisplayName, extractMentionPubkeys: extractMentionPubkeysForCurrentMentions });`,
      { compilerOptions: { target: ts.ScriptTarget.ES2022 } },
    ).outputText,
    {
      React: { useCallback: (callback) => callback },
      normalizePubkey,
      extractMentionPubkeys,
      mentionMapRef: { current: selectedMentions },
      personaMentionMapRef: { current: new Map() },
      mentionCandidates: memberCandidates,
    },
  );
}

async function setupMemberMentions(selectedMentions, memberCandidates) {
  const s = await setup();
  s.dismiss();
  Object.assign(
    s.options.mentions,
    currentMentionCallbacks(selectedMentions, memberCandidates),
    {
      memberPubkeys: new Set(memberCandidates.map((member) => member.pubkey)),
      getDraftMentionRefs: (text) =>
        snapshotDraftMentionRefs(text, selectedMentions, [], memberCandidates),
    },
  );
  s.rerender();
  return s;
}

test("sends a typed channel-member mention resolved by recipient extraction", async () => {
  const s = await setupMemberMentions(new Map(), [
    { pubkey: KEY, displayName: "Alice", isMember: true },
  ]);

  await s.prompt("@Alice please review");

  assert.equal(s.events("error").length, 0);
  assert.equal(s.events("SEND").length, 1);
  assert.deepEqual(s.events("SEND")[0][2], [KEY]);
});

for (const text of [
  "@Alicia please review",
  "@Alice and @Alicia please review",
  "**@ALICIA** please review",
]) {
  test(`sends renamed member with a retained old label: ${text}`, async () => {
    const s = await setupMemberMentions(new Map([["Alice", KEY]]), [
      { pubkey: KEY, displayName: "Alicia", isMember: true },
    ]);
    assert.equal(s.options.mentions.getMentionDisplayName(KEY), "Alice");

    await s.prompt(text);

    assert.equal(s.events("error").length, 0);
    assert.equal(s.events("SEND").length, 1);
    assert.deepEqual(s.events("SEND")[0][2], [KEY]);
  });
}

test("still blocks an unknown mention beside a resolved renamed member", async () => {
  const s = await setupMemberMentions(new Map([["Alice", KEY]]), [
    { pubkey: KEY, displayName: "Alicia", isMember: true },
  ]);

  await s.prompt("@Alicia and ||@missing|| please review");

  assert.equal(s.events("SEND").length, 0);
  assert.match(s.events("error")[0][1], /not linked to a member/);
});

test("still rejects ambiguous typed current member names", async () => {
  const s = await setupMemberMentions(new Map([["Alice", KEY]]), [
    { pubkey: KEY, displayName: "Alicia", isMember: true },
    { pubkey: "c".repeat(64), displayName: "Alicia", isMember: true },
  ]);

  await s.prompt("@Alicia please review");

  assert.equal(s.events("SEND").length, 0);
  assert.match(s.events("error")[0][1], /ambiguous/);
});

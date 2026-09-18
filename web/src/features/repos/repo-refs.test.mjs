import assert from "node:assert/strict";
import test from "node:test";

import {
  parseRefs,
  refsFilter,
  REPO_STATE_KIND,
  selectTrustedRefsEvents,
} from "./repo-refs.ts";

const RELAY = "a".repeat(64);
const SPOOFER = "b".repeat(64);

function refsEvent(pubkey, tags, created_at = 100) {
  return { id: "e".repeat(64), pubkey, kind: 30618, created_at, tags };
}

const RELAY_TAGS = [
  ["d", "buzz"],
  ["refs/heads/main", "c".repeat(40)],
  ["HEAD", "ref: refs/heads/main"],
];

test("refsFilter constrains authors to the relay pubkey", () => {
  assert.deepEqual(refsFilter("buzz", RELAY), {
    kinds: [REPO_STATE_KIND],
    "#d": ["buzz"],
    authors: [RELAY],
  });
});

test("refsFilter omits authors when the relay pubkey is unknown", () => {
  assert.deepEqual(refsFilter("buzz", null), {
    kinds: [REPO_STATE_KIND],
    "#d": ["buzz"],
  });
});

test("selectTrustedRefsEvents drops events from other authors", () => {
  const events = [
    refsEvent(RELAY, RELAY_TAGS),
    refsEvent(SPOOFER, [
      ["d", "buzz"],
      ["refs/heads/main", "d".repeat(40)],
    ]),
  ];
  assert.deepEqual(selectTrustedRefsEvents(events, RELAY), [events[0]]);
});

test("selectTrustedRefsEvents passes everything through without a relay key", () => {
  const events = [refsEvent(SPOOFER, RELAY_TAGS)];
  assert.deepEqual(selectTrustedRefsEvents(events, null), events);
});

test("trust filtering before parse keeps the relay-signed HEAD", () => {
  const trusted = selectTrustedRefsEvents(
    [
      refsEvent(SPOOFER, [
        ["d", "buzz"],
        ["refs/heads/main", "d".repeat(40)],
        ["HEAD", "ref: refs/heads/main"],
      ]),
      refsEvent(RELAY, RELAY_TAGS),
    ],
    RELAY,
  );
  assert.deepEqual(parseRefs(trusted), {
    branches: ["main"],
    tags: [],
    head: { ref: "main", sha: "c".repeat(40) },
  });
});

test("a spoofed-only feed parses to nothing after trust filtering", () => {
  const trusted = selectTrustedRefsEvents(
    [refsEvent(SPOOFER, RELAY_TAGS)],
    RELAY,
  );
  assert.deepEqual(parseRefs(trusted), {
    branches: [],
    tags: [],
    head: null,
  });
});

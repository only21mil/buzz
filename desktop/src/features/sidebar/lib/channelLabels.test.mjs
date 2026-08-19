import assert from "node:assert/strict";
import test from "node:test";

import { npubEncode } from "nostr-tools/nip19";

import { resolveChannelDisplayLabel } from "./channelLabels.ts";

const SELF = "a".repeat(64);
const PEER = "b".repeat(64);

function makeDm(name, participantLabel = PEER) {
  return {
    archivedAt: null,
    channelType: "dm",
    description: "",
    id: "dm-1",
    isMember: true,
    lastMessageAt: null,
    memberCount: 2,
    memberPubkeys: [SELF, PEER],
    name,
    participantPubkeys: [SELF, PEER],
    participants: [SELF, participantLabel],
    purpose: null,
    topic: null,
    ttlDeadline: null,
    ttlSeconds: null,
    visibility: "private",
  };
}

test("known DM peer profile replaces a raw hex channel name", () => {
  const label = resolveChannelDisplayLabel(makeDm(PEER), SELF, {
    [PEER]: {
      avatarUrl: null,
      displayName: "Ada Display",
      isAgent: false,
      name: null,
      nip05Handle: null,
      ownerPubkey: null,
    },
  });

  assert.equal(label, "Ada Display");
});

test("known DM peer kind-0 name replaces a raw npub channel name", () => {
  const label = resolveChannelDisplayLabel(makeDm(npubEncode(PEER)), SELF, {
    [PEER]: {
      avatarUrl: null,
      displayName: null,
      isAgent: false,
      name: "Grace Name",
      nip05Handle: null,
      ownerPubkey: null,
    },
  });

  assert.equal(label, "Grace Name");
});

test("missing DM peer profile uses the bounded canonical identifier", () => {
  assert.equal(
    resolveChannelDisplayLabel(makeDm("DM"), SELF, undefined),
    "bbbbbbbb…bbbb",
  );
});

test("explicit human DM names remain authoritative", () => {
  const label = resolveChannelDisplayLabel(makeDm("Ada and Victor"), SELF, {
    [PEER]: {
      avatarUrl: null,
      displayName: "Ada Display",
      isAgent: false,
      name: null,
      nip05Handle: null,
      ownerPubkey: null,
    },
  });

  assert.equal(label, "Ada and Victor");
});

import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { finalizeEvent, getPublicKey } from "nostr-tools/pure";

// Disposable deterministic test keys. No identity or relay is loaded.
export const testKey = (byte) => new Uint8Array(32).fill(byte);
export const viewerKey = testKey(1);
export const viewerPubkey = getPublicKey(viewerKey);

export function signedEvent(
  key,
  kind,
  content = {},
  tags = [],
  timestamp = 100,
) {
  return finalizeEvent(
    { kind, content: JSON.stringify(content), tags, created_at: timestamp },
    key,
  );
}

export function ownedProfile(
  key,
  owner = viewerKey,
  conditions = "",
  timestamp = 100,
) {
  const signature = bytesToHex(
    schnorr.sign(
      sha256(
        new TextEncoder().encode(
          `nostr:agent-auth:${getPublicKey(key)}:${conditions}`,
        ),
      ),
      owner,
    ),
  );
  return signedEvent(
    key,
    0,
    {},
    [["auth", getPublicKey(owner), conditions, signature]],
    timestamp,
  );
}

export function directoryFixture() {
  const ownedKey = testKey(2);
  const foreignKey = testKey(3);
  const forgedKey = testKey(4);
  const owner = getPublicKey(viewerKey);
  const owned = getPublicKey(ownedKey);
  const foreign = getPublicKey(foreignKey);
  const forged = getPublicKey(forgedKey);
  const events = [
    signedEvent(ownedKey, 10100, { name: "Owned Scout" }),
    signedEvent(foreignKey, 10100, {
      name: "Foreign Scout",
      owner_pubkey: owner,
    }),
    signedEvent(forgedKey, 10100, {
      name: "Forged Scout",
      owner_pubkey: owner,
    }),
    ownedProfile(ownedKey),
    ownedProfile(foreignKey, testKey(5)),
    // A valid owner attestation is insufficient when the profile was tampered.
    { ...ownedProfile(forgedKey), content: '{"name":"tampered"}' },
  ];
  const queries = [];
  return {
    owner,
    owned,
    foreign,
    forged,
    events,
    queries,
    client: {
      async fetchEvents(filter) {
        queries.push(filter);
        return events.filter(
          (event) =>
            filter.kinds.includes(event.kind) &&
            (!filter.authors || filter.authors.includes(event.pubkey)),
        );
      },
    },
  };
}

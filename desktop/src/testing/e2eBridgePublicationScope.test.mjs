import assert from "node:assert/strict";
import test from "node:test";
import { MockPublicationAuthority } from "./e2eBridgePublicationScope.ts";

test("mock native snapshots keep their epoch across repeat reads and canonical relay spellings", () => {
  const authority = new MockPublicationAuthority();
  const original = authority.update("alice", "wss://relay.example/Team");
  assert.equal(
    authority.update("alice", "wss://relay.example/Team/").nativeEpoch,
    original.nativeEpoch,
  );
  authority.validate(original);
});

for (const change of [
  { pubkey: "bob", relayUrl: "wss://relay.example/Team" },
  { pubkey: "alice", relayUrl: "wss://relay.example/team" },
]) {
  test(`mock native scope rejects stale publication after ABA: ${JSON.stringify(change)}`, () => {
    const authority = new MockPublicationAuthority();
    const original = authority.update("alice", "wss://relay.example/Team");
    authority.update(change.pubkey, change.relayUrl);
    const restored = authority.update(original.pubkey, original.relayUrl);
    assert.equal(restored.nativeEpoch, original.nativeEpoch + 2);
    assert.throws(
      () => authority.validate(original),
      /identity or community changed/,
    );
    authority.validate(restored);
  });
}

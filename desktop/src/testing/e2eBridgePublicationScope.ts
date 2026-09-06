type MockPublicationScope = {
  pubkey: string;
  relayUrl: string;
  nativeEpoch: number;
};

const canonicalRelay = (value: string) =>
  new URL(value.trim().replace(/\/+$/, "")).toString().replace(/\/+$/, "");

/** Independent authority for mocked native publication, including ABA changes. */
export class MockPublicationAuthority {
  private current: MockPublicationScope | undefined;

  update(pubkey: string, relayUrl: string): MockPublicationScope {
    const previous = this.current;
    const changed =
      previous &&
      (previous.pubkey !== pubkey ||
        canonicalRelay(previous.relayUrl) !== canonicalRelay(relayUrl));
    this.current = {
      pubkey,
      relayUrl,
      nativeEpoch: (previous?.nativeEpoch ?? 0) + (changed ? 1 : 0),
    };
    return { ...this.current };
  }

  validate(expected: Partial<MockPublicationScope> | undefined): void {
    if (!expected) return;
    const current = this.current;
    if (
      !current ||
      expected.pubkey !== current.pubkey ||
      !expected.relayUrl ||
      canonicalRelay(expected.relayUrl) !== canonicalRelay(current.relayUrl) ||
      (expected.nativeEpoch !== undefined &&
        expected.nativeEpoch !== current.nativeEpoch)
    ) {
      throw new Error(
        "Message cancelled because the identity or community changed.",
      );
    }
  }
}

const ENCRYPTED_KEY_BACKUP_PREFIX = "ncryptsec1";
const ENCRYPTED_KEY_BACKUP_PREFIX_UPPER =
  ENCRYPTED_KEY_BACKUP_PREFIX.toUpperCase();
const PLAINTEXT_KEY_PREFIX = "nsec1";
const PLAINTEXT_KEY_PREFIX_UPPER = PLAINTEXT_KEY_PREFIX.toUpperCase();
const RAW_SECRET_BYTES = 32;
const RAW_SECRET_HEX_LENGTH = RAW_SECRET_BYTES * 2;
const MAX_REGISTERED_SECRETS = 2;
const registeredSecrets: Uint8Array[] = [];

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.length === right.length && left.every((byte, i) => byte === right[i])
  );
}

function hexNibble(code: number): number {
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 65 && code <= 70) return code - 55;
  if (code >= 97 && code <= 102) return code - 87;
  return -1;
}

function matchesRawSecretAt(
  value: string,
  offset: number,
  secret: Uint8Array,
): boolean {
  for (let i = 0; i < RAW_SECRET_BYTES; i += 1) {
    const high = hexNibble(value.charCodeAt(offset + i * 2));
    const low = hexNibble(value.charCodeAt(offset + i * 2 + 1));
    if (high < 0 || low < 0 || ((high << 4) | low) !== secret[i]) return false;
  }
  return true;
}

function containsRegisteredRawSecret(value: string): boolean {
  if (value.length < RAW_SECRET_HEX_LENGTH) return false;
  for (const secret of registeredSecrets) {
    for (
      let offset = 0;
      offset <= value.length - RAW_SECRET_HEX_LENGTH;
      offset += 1
    ) {
      if (matchesRawSecretAt(value, offset, secret)) return true;
    }
  }
  return false;
}

/** Keep the current and immediately prior browser identity in the egress guard. */
export function registerIdentitySecretForEgressGuard(secret: Uint8Array): void {
  if (secret.length !== RAW_SECRET_BYTES) {
    throw new TypeError("Identity egress guard requires a 32-byte secret key");
  }
  const existing = registeredSecrets.findIndex((candidate) =>
    sameBytes(candidate, secret),
  );
  if (existing >= 0) {
    const [registered] = registeredSecrets.splice(existing, 1);
    registeredSecrets.unshift(registered);
    return;
  }
  registeredSecrets.unshift(Uint8Array.from(secret));
  while (registeredSecrets.length > MAX_REGISTERED_SECRETS) {
    registeredSecrets.pop()?.fill(0);
  }
}

/** Zero and forget retained identity secrets after explicit sign-out. */
export function clearIdentitySecretsForEgressGuard(): void {
  for (const secret of registeredSecrets) secret.fill(0);
  registeredSecrets.length = 0;
}

/** Reject identity secrets in browser WebSocket and HTTP request fields. */
export function assertNoIdentityKeyEgress(
  value: string,
  context: string,
): void {
  if (
    value.includes(ENCRYPTED_KEY_BACKUP_PREFIX) ||
    value.includes(ENCRYPTED_KEY_BACKUP_PREFIX_UPPER)
  ) {
    throw new Error(
      `blocked ${context}: payload contains NIP-49 key-backup material ` +
        "(ncryptsec); the local key backup must never be transmitted to a relay",
    );
  }
  if (
    value.includes(PLAINTEXT_KEY_PREFIX) ||
    value.includes(PLAINTEXT_KEY_PREFIX_UPPER)
  ) {
    throw new Error(
      `blocked ${context}: payload contains plaintext identity key material ` +
        "(nsec); the local identity secret must never be transmitted to a relay",
    );
  }
  if (containsRegisteredRawSecret(value)) {
    throw new Error(
      `blocked ${context}: payload contains plaintext identity key material ` +
        "(raw 64-hex secret); the local identity secret must never be transmitted to a relay",
    );
  }
}

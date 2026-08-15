const ENCRYPTED_KEY_BACKUP_PREFIX = "ncryptsec1";
const ENCRYPTED_KEY_BACKUP_PREFIX_UPPER =
  ENCRYPTED_KEY_BACKUP_PREFIX.toUpperCase();

/** Reject encrypted backups in browser WebSocket and HTTP request fields. */
export function assertNoEncryptedKeyBackupEgress(
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
}

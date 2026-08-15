import {
  finalizeEvent,
  generateSecretKey,
  getPublicKey,
} from "nostr-tools/pure";
import { decode, npubEncode, nsecEncode } from "nostr-tools/nip19";
import { decrypt, encrypt } from "nostr-tools/nip49";
import { truncatePubkey } from "@/shared/lib/pubkey";

export const NIP49_LOG_N = 18;
const NIP49_SECURITY_BYTE = 0x02;
const HEX_SECRET_RE = /^[0-9a-f]{64}$/i;
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

export type EventRequest = {
  kind: number;
  content: string;
  createdAt?: number;
  tags: string[][];
};

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

export function hexToBytes(hex: string): Uint8Array {
  if (!HEX_SECRET_RE.test(hex)) {
    throw new Error("Secret key must be exactly 64 hexadecimal characters");
  }
  return Uint8Array.from({ length: 32 }, (_, index) =>
    Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16),
  );
}

export function validateSecretKey(secret: Uint8Array): Uint8Array {
  if (secret.length !== 32) {
    secret.fill(0);
    throw new Error("Secret key must be exactly 32 bytes");
  }
  // getPublicKey also rejects zero and out-of-range secp256k1 scalars.
  getPublicKey(secret);
  return secret;
}

export function parsePlainSecret(input: string): Uint8Array {
  const value = input.trim();
  if (HEX_SECRET_RE.test(value)) {
    return validateSecretKey(hexToBytes(value));
  }
  if (value.toLowerCase().startsWith("nsec1")) {
    const decoded = decode(value);
    if (decoded.type !== "nsec") {
      throw new Error("Expected an nsec secret key");
    }
    return validateSecretKey(Uint8Array.from(decoded.data));
  }
  throw new Error("Identity must be an nsec, ncryptsec, or 64-hex secret key");
}

function convertFiveBitWords(words: number[], byteLimit: number): Uint8Array {
  let accumulator = 0;
  let bits = 0;
  const output: number[] = [];
  for (const word of words) {
    accumulator = (accumulator << 5) | word;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      output.push((accumulator >> bits) & 0xff);
      if (output.length >= byteLimit) return Uint8Array.from(output);
    }
  }
  return Uint8Array.from(output);
}

/** Read the NIP-49 work factor before invoking scrypt. */
export function readNcryptsecLogN(value: string): number {
  const normalized = value.trim().toLowerCase();
  const separator = normalized.lastIndexOf("1");
  if (normalized.slice(0, separator) !== "ncryptsec" || separator < 1) {
    throw new Error("Invalid ncryptsec prefix");
  }
  // Exclude the six checksum words. The full checksum is still verified by
  // nostr-tools before decryption; this bounded decode exists only to reject a
  // hostile scrypt work factor before expensive allocation begins.
  const payload = normalized.slice(separator + 1, -6);
  const words = Array.from(payload, (character) => {
    const word = BECH32_CHARSET.indexOf(character);
    if (word < 0) throw new Error("Invalid ncryptsec encoding");
    return word;
  });
  const header = convertFiveBitWords(words, 2);
  if (header.length < 2 || header[0] !== 2) {
    throw new Error("Unsupported ncryptsec version");
  }
  return header[1];
}

export function decryptNcryptsec(value: string, password: string): Uint8Array {
  if (!password) throw new Error("Password is required for ncryptsec import");
  const logN = readNcryptsecLogN(value);
  if (logN > NIP49_LOG_N) {
    throw new Error(
      `ncryptsec work factor ${logN} exceeds the supported limit`,
    );
  }
  return validateSecretKey(decrypt(value.trim(), password.normalize("NFKC")));
}

export function encryptNcryptsec(
  secret: Uint8Array,
  password: string,
  logN = NIP49_LOG_N,
): string {
  if (logN > NIP49_LOG_N) {
    throw new Error(
      `ncryptsec work factor ${logN} exceeds the supported limit`,
    );
  }
  return encrypt(
    validateSecretKey(Uint8Array.from(secret)),
    password.normalize("NFKC"),
    logN,
    NIP49_SECURITY_BYTE,
  );
}

export function displayNameForPubkey(pubkey: string): string {
  return truncatePubkey(npubEncode(pubkey));
}

export function signEvent(secret: Uint8Array, request: EventRequest): string {
  if (
    !Number.isInteger(request.kind) ||
    request.kind < 0 ||
    request.kind > 65535
  ) {
    throw new TypeError("kind must be an integer from 0 through 65535");
  }
  if (typeof request.content !== "string") {
    throw new TypeError("content must be a string");
  }
  if (
    request.createdAt !== undefined &&
    (!Number.isSafeInteger(request.createdAt) || request.createdAt < 0)
  ) {
    throw new TypeError("createdAt must be a non-negative safe integer");
  }
  if (
    !Array.isArray(request.tags) ||
    request.tags.some(
      (tag) =>
        !Array.isArray(tag) ||
        tag.length === 0 ||
        tag.some((value) => typeof value !== "string"),
    )
  ) {
    throw new TypeError("tags must be non-empty arrays of strings");
  }
  const event = finalizeEvent(
    {
      kind: request.kind,
      content: request.content,
      created_at: request.createdAt ?? Math.floor(Date.now() / 1000),
      tags: request.tags.map((tag) => [...tag]),
    },
    secret,
  );
  return JSON.stringify(event);
}

export { generateSecretKey, getPublicKey, nsecEncode };

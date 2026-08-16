import { register, type InvokeBody } from "./registry";
import {
  clearIdentitySecretsForEgressGuard,
  registerIdentitySecretForEgressGuard,
} from "@/shared/lib/keyBackupEgress";
import {
  displayNameForPubkey,
  generateSecretKey,
  getPublicKey,
  nsecEncode,
  parsePlainSecret,
  signEvent,
  type EventRequest,
} from "./identityCrypto";
import {
  IndexedDbIdentityStore,
  type IdentityStore,
  type StoredIdentity,
} from "./identityStore";
import { purgeRepoSnapshotCache } from "./desktopOnly/repoSnapshot";
import { WorkerNip49Codec, type Nip49Codec } from "./nip49Client";
import { v2 as nip44 } from "nostr-tools/nip44";

const DEVICE_PASSWORD_CONTEXT = new TextEncoder().encode(
  "buzz-browser-identity:nip49:v1",
);

export type RawIdentity = {
  pubkey: string;
  display_name: string;
  storage: "indexed-db" | "ephemeral";
  lost: boolean;
  locked: false;
  reset_failed: false;
};

function objectBody(body: InvokeBody): Record<string, unknown> {
  if (
    !body ||
    Array.isArray(body) ||
    body instanceof ArrayBuffer ||
    body instanceof Uint8Array
  ) {
    throw new TypeError("Command requires an object body");
  }
  return body;
}

function stringField(
  body: Record<string, unknown>,
  field: string,
  required = true,
): string | undefined {
  const value = body[field];
  if (value === undefined || value === null) {
    if (required) throw new TypeError(`${field} must be a string`);
    return undefined;
  }
  if (typeof value !== "string")
    throw new TypeError(`${field} must be a string`);
  return value;
}

function eventRequest(body: InvokeBody): EventRequest {
  const record = objectBody(body);
  return {
    kind: record.kind as number,
    content: record.content as string,
    createdAt: record.createdAt as number | undefined,
    tags: record.tags as string[][],
  };
}

async function generateDeviceKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"],
  );
}

async function devicePassword(deviceKey: CryptoKey): Promise<string> {
  const signature = await crypto.subtle.sign(
    "HMAC",
    deviceKey,
    DEVICE_PASSWORD_CONTEXT,
  );
  return Array.from(new Uint8Array(signature), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

export class BrowserIdentityManager {
  private readonly store: IdentityStore;
  private readonly codec: Nip49Codec;
  private secret: Uint8Array;
  private deviceKey: CryptoKey | null;
  private durable: boolean;
  private recovery: boolean;
  private repoSnapshotGeneration = 0;

  private constructor(
    store: IdentityStore,
    codec: Nip49Codec,
    secret: Uint8Array,
    deviceKey: CryptoKey | null,
    durable: boolean,
    recovery: boolean,
  ) {
    this.store = store;
    this.codec = codec;
    this.secret = secret;
    this.deviceKey = deviceKey;
    this.durable = durable;
    this.recovery = recovery;
    registerIdentitySecretForEgressGuard(secret);
  }

  static async create(
    store: IdentityStore = new IndexedDbIdentityStore(),
    codec: Nip49Codec = new WorkerNip49Codec(),
  ): Promise<BrowserIdentityManager> {
    try {
      const stored = await store.load();
      if (stored) {
        const secret = await codec.decrypt(
          stored.ncryptsec,
          await devicePassword(stored.deviceKey),
        );
        if (getPublicKey(secret) !== stored.pubkey) {
          secret.fill(0);
          throw new Error(
            "Stored identity public key does not match ciphertext",
          );
        }
        return new BrowserIdentityManager(
          store,
          codec,
          secret,
          stored.deviceKey,
          true,
          false,
        );
      }

      const secret = generateSecretKey();
      const key = await generateDeviceKey();
      const ncryptsec = await codec.encrypt(secret, await devicePassword(key));
      const identity = {
        version: 1 as const,
        pubkey: getPublicKey(secret),
        ncryptsec,
      };
      await store.save(identity, key);
      return new BrowserIdentityManager(store, codec, secret, key, true, false);
    } catch (error) {
      console.error("[web PAL] browser identity recovery mode:", error);
      return new BrowserIdentityManager(
        store,
        codec,
        generateSecretKey(),
        null,
        false,
        true,
      );
    }
  }

  identity(): RawIdentity {
    const pubkey = getPublicKey(this.secret);
    return {
      pubkey,
      display_name: displayNameForPubkey(pubkey),
      storage: this.durable ? "indexed-db" : "ephemeral",
      lost: this.recovery,
      locked: false,
      reset_failed: false,
    };
  }

  pubkey(): string {
    return getPublicKey(this.secret);
  }

  repoSnapshotScope(): string {
    return `${this.repoSnapshotGeneration}:${this.pubkey()}`;
  }

  sign(request: EventRequest): string {
    if (this.recovery) {
      throw new Error(
        "Identity storage is unavailable; import your identity to sign",
      );
    }
    return signEvent(this.secret, request);
  }

  nip44EncryptToSelf(plaintext: string): string {
    const key = nip44.utils.getConversationKey(this.secret, this.pubkey());
    return nip44.encrypt(plaintext, key);
  }

  nip44DecryptFromSelf(ciphertext: string): string {
    const key = nip44.utils.getConversationKey(this.secret, this.pubkey());
    return nip44.decrypt(ciphertext, key);
  }

  getNsec(): string {
    if (this.recovery) {
      throw new Error(
        "Identity storage is unavailable; import your identity first",
      );
    }
    return nsecEncode(this.secret);
  }

  async importIdentity(input: string, password?: string): Promise<RawIdentity> {
    const trimmed = input.trim();
    const imported = trimmed.toLowerCase().startsWith("ncryptsec1")
      ? await this.codec.decrypt(trimmed, password ?? "")
      : parsePlainSecret(trimmed);
    try {
      const key = this.deviceKey ?? (await generateDeviceKey());
      const identity: Omit<StoredIdentity, "deviceKey"> = {
        version: 1,
        pubkey: getPublicKey(imported),
        ncryptsec: await this.codec.encrypt(
          imported,
          await devicePassword(key),
        ),
      };
      // Persistence must succeed before the active signer changes.
      await this.store.save(identity, key);
      this.repoSnapshotGeneration += 1;
      this.secret.fill(0);
      this.secret = Uint8Array.from(imported);
      registerIdentitySecretForEgressGuard(this.secret);
      this.deviceKey = key;
      this.durable = true;
      this.recovery = false;
      return this.identity();
    } finally {
      imported.fill(0);
    }
  }

  async persistCurrentIdentity(): Promise<RawIdentity> {
    if (this.durable) {
      throw new Error("identity is not in a lost state");
    }
    const key = await generateDeviceKey();
    const identity: Omit<StoredIdentity, "deviceKey"> = {
      version: 1,
      pubkey: this.pubkey(),
      ncryptsec: await this.codec.encrypt(
        this.secret,
        await devicePassword(key),
      ),
    };
    await this.store.save(identity, key);
    registerIdentitySecretForEgressGuard(this.secret);
    this.deviceKey = key;
    this.durable = true;
    this.recovery = false;
    return this.identity();
  }

  async signOut(): Promise<void> {
    const outgoingPubkey = this.pubkey();
    this.repoSnapshotGeneration += 1;
    await this.store.clear();
    await purgeRepoSnapshotCache(outgoingPubkey);
    this.secret.fill(0);
    this.secret = generateSecretKey();
    this.deviceKey = null;
    this.durable = false;
    this.recovery = true;
    clearIdentitySecretsForEgressGuard();
  }

  async createBackup(password: string): Promise<string> {
    if (this.recovery) {
      throw new Error(
        "Identity storage is unavailable; import your identity first",
      );
    }
    return this.codec.encrypt(this.secret, password);
  }

  async verifyBackup(ncryptsec: string, password: string) {
    const secret = await this.codec.decrypt(ncryptsec, password);
    try {
      const pubkey = getPublicKey(secret);
      return {
        pubkey,
        npub: (await import("nostr-tools/nip19")).npubEncode(pubkey),
        matchesCurrentIdentity: pubkey === this.pubkey(),
      };
    } finally {
      secret.fill(0);
    }
  }
}

export function registerIdentityCommands(
  manager: BrowserIdentityManager,
  reload: () => void = () => window.location.reload(),
): void {
  register("get_identity", () => manager.identity());
  register("get_nsec", () => manager.getNsec());
  register("persist_current_identity", () => manager.persistCurrentIdentity());
  register("sign_out", async () => {
    await manager.signOut();
    globalThis.setTimeout(reload, 0);
  });
  register("import_identity", async (body) => {
    const record = objectBody(body);
    return manager.importIdentity(
      stringField(record, "nsec") as string,
      stringField(record, "password", false),
    );
  });
  register("sign_event", (body) => manager.sign(eventRequest(body)));
  register("nip44_encrypt_to_self", (body) =>
    manager.nip44EncryptToSelf(
      stringField(objectBody(body), "plaintext") as string,
    ),
  );
  register("nip44_decrypt_from_self", (body) =>
    manager.nip44DecryptFromSelf(
      stringField(objectBody(body), "ciphertext") as string,
    ),
  );
  register("create_auth_event", (body) => {
    const record = objectBody(body);
    return manager.sign({
      kind: 22242,
      content: "",
      tags: [
        ["relay", stringField(record, "relayUrl") as string],
        ["challenge", stringField(record, "challenge") as string],
      ],
    });
  });
  register("create_ncryptsec_backup", (body) =>
    manager.createBackup(stringField(objectBody(body), "password") as string),
  );
  register("verify_ncryptsec_backup", (body) => {
    const record = objectBody(body);
    return manager.verifyBackup(
      stringField(record, "ncryptsec") as string,
      stringField(record, "password") as string,
    );
  });
  register("generate_backup_passphrase", (body) => {
    const record = body === undefined ? {} : objectBody(body);
    const requestedWords = record.words;
    const words =
      typeof requestedWords === "number"
        ? Math.min(10, Math.max(3, Math.trunc(requestedWords)))
        : 6;
    const separator =
      typeof record.separator === "string" ? record.separator : " ";
    const random = crypto.getRandomValues(new Uint8Array(words * 4));
    return Array.from({ length: words }, (_, index) =>
      Array.from(random.slice(index * 4, index * 4 + 4), (byte) =>
        byte.toString(16).padStart(2, "0"),
      ).join(""),
    ).join(separator);
  });
  register("save_ncryptsec_copy", (body) => {
    const ncryptsec = stringField(objectBody(body), "ncryptsec") as string;
    const url = URL.createObjectURL(
      new Blob([`${ncryptsec}\n`], { type: "text/plain;charset=utf-8" }),
    );
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `buzz-identity-${manager.pubkey().slice(0, 8)}.ncryptsec`;
    anchor.click();
    queueMicrotask(() => URL.revokeObjectURL(url));
    return anchor.download;
  });
}

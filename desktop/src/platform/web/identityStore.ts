export type StoredIdentity = {
  version: 1;
  pubkey: string;
  ncryptsec: string;
  deviceKey: CryptoKey;
};

export type IdentityStore = {
  load(): Promise<StoredIdentity | null>;
  save(
    identity: Omit<StoredIdentity, "deviceKey">,
    deviceKey: CryptoKey,
  ): Promise<void>;
};

const DB_NAME = "buzz-browser-identity";
const STORE_NAME = "records";
const IDENTITY_KEY = "identity";
const DEVICE_KEY = "device-key";

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(request.error ?? new Error("IndexedDB request failed"));
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () =>
      reject(transaction.error ?? new Error("IndexedDB transaction aborted"));
    transaction.onerror = () =>
      reject(transaction.error ?? new Error("IndexedDB transaction failed"));
  });
}

export class IndexedDbIdentityStore implements IdentityStore {
  private readonly database: Promise<IDBDatabase>;

  constructor(factory: IDBFactory = indexedDB) {
    this.database = new Promise((resolve, reject) => {
      const request = factory.open(DB_NAME, 1);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(STORE_NAME)) {
          request.result.createObjectStore(STORE_NAME);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(request.error ?? new Error("Unable to open identity database"));
      request.onblocked = () =>
        reject(new Error("Identity database upgrade is blocked"));
    });
  }

  async load(): Promise<StoredIdentity | null> {
    const database = await this.database;
    const transaction = database.transaction(STORE_NAME, "readonly");
    const store = transaction.objectStore(STORE_NAME);
    const [identity, deviceKey] = await Promise.all([
      requestResult<Omit<StoredIdentity, "deviceKey"> | undefined>(
        store.get(IDENTITY_KEY),
      ),
      requestResult<CryptoKey | undefined>(store.get(DEVICE_KEY)),
    ]);
    await transactionDone(transaction);
    if (!identity && !deviceKey) return null;
    if (!identity || !deviceKey || identity.version !== 1) {
      throw new Error("Browser identity storage is incomplete or unsupported");
    }
    return { ...identity, deviceKey };
  }

  async save(
    identity: Omit<StoredIdentity, "deviceKey">,
    deviceKey: CryptoKey,
  ): Promise<void> {
    const database = await this.database;
    const transaction = database.transaction(STORE_NAME, "readwrite");
    const store = transaction.objectStore(STORE_NAME);
    store.put(identity, IDENTITY_KEY);
    store.put(deviceKey, DEVICE_KEY);
    await transactionDone(transaction);
  }
}

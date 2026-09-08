export interface QueryCacheStorage {
  read(key: string): Promise<string | null>;
  write(key: string, value: string): Promise<void>;
  clear(): Promise<void>;
}

/** Cache data is separate from the browser identity database and contains no keys. */
export class IndexedDbQueryCacheStorage implements QueryCacheStorage {
  private database: Promise<IDBDatabase> | undefined;
  private epoch: string | undefined;

  private open(): Promise<IDBDatabase> {
    this.database ??= new Promise((resolve, reject) => {
      const request = indexedDB.open("buzz-query-cache", 1);
      request.onupgradeneeded = () =>
        request.result.createObjectStore("scopes");
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
      request.onblocked = () => reject(new Error("Query cache is blocked"));
    });
    return this.database;
  }

  async read(key: string): Promise<string | null> {
    if (typeof indexedDB === "undefined") return null;
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("scopes");
      const store = tx.objectStore("scopes");
      const epoch = store.get("epoch");
      const request = store.get(key);
      tx.oncomplete = () => {
        const current = String(epoch.result ?? "0");
        // Capture the generation before exposing data, even if this tab has
        // never saved. A delayed first save must not adopt a later logout.
        this.epoch ??= current;
        resolve(
          this.epoch === current && typeof request.result === "string"
            ? request.result
            : null,
        );
      };
      tx.onabort = () => reject(tx.error);
      tx.onerror = () => reject(tx.error);
    });
  }

  private async mutate(write: (store: IDBObjectStore) => void): Promise<void> {
    if (typeof indexedDB === "undefined") return;
    const db = await this.open();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction("scopes", "readwrite");
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(tx.error);
      tx.onerror = () => reject(tx.error);
      write(tx.objectStore("scopes"));
    });
  }

  write(key: string, value: string): Promise<void> {
    return this.mutate((store) => {
      const epoch = store.get("epoch");
      epoch.onsuccess = () => {
        const current = String(epoch.result ?? "0");
        // A logout in another tab invalidates this writer atomically with its clear.
        if (this.epoch === current) store.put(value, key);
      };
    });
  }

  async clear(): Promise<void> {
    const epoch = crypto.randomUUID();
    await this.mutate((store) => {
      store.clear();
      store.put(epoch, "epoch");
    });
    this.epoch = epoch;
  }
}

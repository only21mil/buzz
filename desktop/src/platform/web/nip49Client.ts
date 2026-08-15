import { decryptNcryptsec, encryptNcryptsec } from "./identityCrypto";

export type Nip49Codec = {
  encrypt(secret: Uint8Array, password: string): Promise<string>;
  decrypt(ncryptsec: string, password: string): Promise<Uint8Array>;
};

type WorkerResponse =
  | { id: number; ok: true; ncryptsec: string }
  | { id: number; ok: true; secret: ArrayBuffer }
  | { id: number; ok: false; error: string };

type Pending = {
  resolve(value: string | Uint8Array): void;
  reject(error: Error): void;
};

export class WorkerNip49Codec implements Nip49Codec {
  private readonly worker: Worker;
  private readonly pending = new Map<number, Pending>();
  private nextId = 1;

  constructor() {
    this.worker = new Worker(new URL("./identity.worker.ts", import.meta.url), {
      type: "module",
    });
    this.worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
      const response = event.data;
      const pending = this.pending.get(response.id);
      if (!pending) return;
      this.pending.delete(response.id);
      if (!response.ok) {
        pending.reject(new Error(response.error));
      } else if ("ncryptsec" in response) {
        pending.resolve(response.ncryptsec);
      } else {
        pending.resolve(new Uint8Array(response.secret));
      }
    };
    this.worker.onerror = (event) => {
      const error = new Error(event.message || "NIP-49 worker failed");
      for (const pending of this.pending.values()) pending.reject(error);
      this.pending.clear();
    };
  }

  encrypt(secret: Uint8Array, password: string): Promise<string> {
    const copy = Uint8Array.from(secret);
    const id = this.nextId++;
    return new Promise<string>((resolve, reject) => {
      this.pending.set(id, {
        resolve: (value) => resolve(value as string),
        reject,
      });
      this.worker.postMessage(
        { id, operation: "encrypt", secret: copy.buffer, password },
        [copy.buffer],
      );
    });
  }

  decrypt(ncryptsec: string, password: string): Promise<Uint8Array> {
    const id = this.nextId++;
    return new Promise<Uint8Array>((resolve, reject) => {
      this.pending.set(id, {
        resolve: (value) => resolve(value as Uint8Array),
        reject,
      });
      this.worker.postMessage({
        id,
        operation: "decrypt",
        ncryptsec,
        password,
      });
    });
  }
}

/** Deterministic, worker-free codec for unit tests only. */
export class DirectNip49Codec implements Nip49Codec {
  private readonly logN: number;

  constructor(logN = 10) {
    this.logN = logN;
  }

  async encrypt(secret: Uint8Array, password: string): Promise<string> {
    return encryptNcryptsec(secret, password, this.logN);
  }

  async decrypt(ncryptsec: string, password: string): Promise<Uint8Array> {
    return decryptNcryptsec(ncryptsec, password);
  }
}

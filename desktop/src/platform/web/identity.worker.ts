/// <reference lib="webworker" />

import { decryptNcryptsec, encryptNcryptsec } from "./identityCrypto";

type Request =
  | { id: number; operation: "encrypt"; secret: ArrayBuffer; password: string }
  | { id: number; operation: "decrypt"; ncryptsec: string; password: string };

type Response =
  | { id: number; ok: true; ncryptsec: string }
  | { id: number; ok: true; secret: ArrayBuffer }
  | { id: number; ok: false; error: string };

self.onmessage = (event: MessageEvent<Request>) => {
  const request = event.data;
  try {
    if (request.operation === "encrypt") {
      const secret = new Uint8Array(request.secret);
      try {
        const response: Response = {
          id: request.id,
          ok: true,
          ncryptsec: encryptNcryptsec(secret, request.password),
        };
        self.postMessage(response);
      } finally {
        secret.fill(0);
      }
      return;
    }

    const secret = decryptNcryptsec(request.ncryptsec, request.password);
    const response: Response = {
      id: request.id,
      ok: true,
      secret: secret.buffer as ArrayBuffer,
    };
    self.postMessage(response, { transfer: [response.secret] });
  } catch (error) {
    const response: Response = {
      id: request.id,
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    };
    self.postMessage(response);
  }
};

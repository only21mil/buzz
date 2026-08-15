import { assertNoEncryptedKeyBackupEgress } from "@/shared/lib/keyBackupEgress";

import { register, type InvokeBody } from "./registry";

const CONNECT_TIMEOUT_MS = 10_000;

type WebSocketCallbackMessage =
  | { type: "Text"; data: string }
  | { type: "Binary"; data: number[] }
  | { type: "Close"; data: { code: number; reason: string } | null }
  | { type: "Error"; data: string };

type WebSocketHandler = (message: WebSocketCallbackMessage) => void;

type Connection = {
  id: number;
  socket: WebSocket;
  handler: WebSocketHandler;
  terminal: boolean;
  locallyClosed: boolean;
};

type PendingConnection = {
  socket: WebSocket;
  cancel: () => void;
};

type WebSocketCommandBody = Record<string, unknown>;

const connections = new Map<number, Connection>();
const pendingConnections = new Set<PendingConnection>();
let nextConnectionId = 1;

function commandBody(body: InvokeBody, command: string): WebSocketCommandBody {
  if (
    body === undefined ||
    Array.isArray(body) ||
    body instanceof ArrayBuffer ||
    body instanceof Uint8Array
  ) {
    throw new TypeError(`${command} requires an object body`);
  }
  return body;
}

function resolveHandler(value: unknown): WebSocketHandler {
  if (typeof value === "function") {
    return value as WebSocketHandler;
  }
  if (
    typeof value === "object" &&
    value !== null &&
    "onmessage" in value &&
    typeof value.onmessage === "function"
  ) {
    return value.onmessage as WebSocketHandler;
  }
  throw new TypeError("Invalid websocket message handler");
}

function allocateConnectionId(): number {
  for (let attempts = 0; attempts < 0xffff_ffff; attempts += 1) {
    const candidate = nextConnectionId;
    nextConnectionId =
      nextConnectionId === 0xffff_ffff ? 1 : nextConnectionId + 1;
    if (!connections.has(candidate)) return candidate;
  }
  throw new Error("WebSocket connection id space exhausted");
}

function connectionFor(id: unknown): Connection {
  if (typeof id !== "number" || !Number.isInteger(id) || id < 0) {
    throw new TypeError("WebSocket connection id must be an integer");
  }
  const connection = connections.get(id);
  if (!connection) {
    throw new Error(`WebSocket connection ${id} not found`);
  }
  return connection;
}

function terminateRemote(
  connection: Connection,
  message: WebSocketCallbackMessage,
): void {
  if (connection.terminal || connection.locallyClosed) return;
  connection.terminal = true;
  connections.delete(connection.id);
  connection.handler(message);
}

async function connect(body: InvokeBody): Promise<number> {
  const payload = commandBody(body, "plugin:websocket|connect");
  if (typeof payload.url !== "string" || payload.url.length === 0) {
    throw new TypeError("plugin:websocket|connect requires a url");
  }
  assertNoEncryptedKeyBackupEgress(payload.url, "websocket URL");
  const handler = resolveHandler(payload.onMessage);
  const socket = new WebSocket(payload.url);
  socket.binaryType = "arraybuffer";

  return new Promise<number>((resolve, reject) => {
    let settled = false;
    let connection: Connection | null = null;

    const finishPending = () => {
      globalThis.clearTimeout(timeout);
      pendingConnections.delete(pending);
    };

    const rejectPending = (message: string, closeSocket: boolean) => {
      if (settled) return;
      settled = true;
      finishPending();
      if (closeSocket) socket.close();
      reject(new Error(message));
    };

    const pending: PendingConnection = {
      socket,
      cancel: () => rejectPending("WebSocket connection cancelled", true),
    };
    pendingConnections.add(pending);

    const timeout = globalThis.setTimeout(() => {
      rejectPending("WebSocket connection timed out", true);
    }, CONNECT_TIMEOUT_MS);

    socket.addEventListener("open", () => {
      if (settled) return;
      settled = true;
      finishPending();
      const id = allocateConnectionId();
      connection = {
        id,
        socket,
        handler,
        terminal: false,
        locallyClosed: false,
      };
      connections.set(id, connection);
      resolve(id);
    });

    socket.addEventListener("message", (event) => {
      if (!connection || connection.terminal || connection.locallyClosed)
        return;
      if (typeof event.data === "string") {
        connection.handler({ type: "Text", data: event.data });
        return;
      }
      if (event.data instanceof ArrayBuffer) {
        connection.handler({
          type: "Binary",
          data: Array.from(new Uint8Array(event.data)),
        });
      }
    });

    socket.addEventListener("error", () => {
      if (!settled) {
        rejectPending("WebSocket connection failed", true);
        return;
      }
      if (connection) {
        terminateRemote(connection, {
          type: "Error",
          data: "WebSocket connection errored",
        });
      }
    });

    socket.addEventListener("close", (event) => {
      if (!settled) {
        rejectPending("WebSocket connection closed before opening", false);
        return;
      }
      if (!connection) return;
      const data =
        event.code === 1005 && event.reason === ""
          ? null
          : { code: event.code, reason: event.reason };
      terminateRemote(connection, { type: "Close", data });
    });
  });
}

function send(body: InvokeBody): void {
  const payload = commandBody(body, "plugin:websocket|send");
  const message = payload.message;
  if (typeof message !== "object" || message === null || !("type" in message)) {
    throw new TypeError("plugin:websocket|send requires a message");
  }

  const type = message.type;
  const data = "data" in message ? message.data : undefined;

  if (type === "Text") {
    if (typeof data !== "string") {
      throw new TypeError("WebSocket Text data must be a string");
    }
    assertNoEncryptedKeyBackupEgress(data, "websocket text frame");
    const connection = connectionFor(payload.id);
    if (connection.socket.readyState !== WebSocket.OPEN) {
      throw new Error("WebSocket connection closed");
    }
    connection.socket.send(data);
    return;
  }

  if (type === "Binary") {
    if (
      !Array.isArray(data) ||
      data.some(
        (value) =>
          typeof value !== "number" ||
          !Number.isInteger(value) ||
          value < 0 ||
          value > 255,
      )
    ) {
      throw new TypeError("WebSocket Binary data must be a byte array");
    }
    const bytes = Uint8Array.from(data);
    assertNoEncryptedKeyBackupEgress(
      new TextDecoder().decode(bytes),
      "websocket binary frame",
    );
    const connection = connectionFor(payload.id);
    if (connection.socket.readyState !== WebSocket.OPEN) {
      throw new Error("WebSocket connection closed");
    }
    connection.socket.send(bytes);
    return;
  }

  if (type === "Close") {
    const connection = connectionFor(payload.id);
    if (data === undefined || data === null) {
      connection.locallyClosed = true;
      connection.terminal = true;
      connections.delete(connection.id);
      connection.socket.close();
      return;
    }
    if (
      typeof data !== "object" ||
      !("code" in data) ||
      typeof data.code !== "number" ||
      !("reason" in data) ||
      typeof data.reason !== "string"
    ) {
      throw new TypeError("WebSocket Close data must contain code and reason");
    }
    assertNoEncryptedKeyBackupEgress(data.reason, "websocket close reason");
    connection.locallyClosed = true;
    connection.terminal = true;
    connections.delete(connection.id);
    connection.socket.close(data.code, data.reason);
    return;
  }

  connectionFor(payload.id);
  if (type === "Ping" || type === "Pong") {
    throw new Error(`Browser WebSocket does not support ${type} frames`);
  }
  throw new TypeError(`Unsupported WebSocket message type: ${String(type)}`);
}

function disconnect(body: InvokeBody): void {
  const payload = commandBody(body, "plugin:websocket|disconnect");
  if (typeof payload.id !== "number") return;
  const connection = connections.get(payload.id);
  if (!connection) return;
  connection.locallyClosed = true;
  connection.terminal = true;
  connections.delete(connection.id);
  connection.socket.close(1000, "disconnect");
}

function disconnectAll(): void {
  for (const pending of [...pendingConnections]) pending.cancel();
  for (const connection of connections.values()) {
    connection.locallyClosed = true;
    connection.terminal = true;
    connection.socket.close(1000, "disconnect");
  }
  connections.clear();
}

export function registerWebSocketCommands(): void {
  register("plugin:websocket|connect", connect);
  register("plugin:websocket|send", send);
  register("plugin:websocket|disconnect", disconnect);
  register("plugin:websocket|disconnect_all", disconnectAll);
}

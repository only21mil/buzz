import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { Channel } from "./shims/core.ts";
import { dispatch, resetRegistryForTests } from "./registry.ts";
import { registerWebSocketCommands } from "./websocket.ts";

const originalWebSocket = globalThis.WebSocket;

class FakeWebSocket {
  static OPEN = 1;
  static instances = [];

  readyState = 0;
  binaryType = "blob";
  sent = [];
  closeCalls = [];
  listeners = new Map();

  constructor(url) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }

  addEventListener(type, listener) {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  emit(type, event = {}) {
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }

  open() {
    this.readyState = FakeWebSocket.OPEN;
    this.emit("open");
  }

  send(value) {
    if (this.readyState !== FakeWebSocket.OPEN) {
      throw new Error("socket is not open");
    }
    this.sent.push(value);
  }

  close(code = 1005, reason = "") {
    this.readyState = 3;
    this.closeCalls.push({ code, reason });
    this.emit("close", { code, reason });
  }
}

async function install() {
  globalThis.WebSocket = FakeWebSocket;
  registerWebSocketCommands();
}

afterEach(async () => {
  try {
    await dispatch("plugin:websocket|disconnect_all");
  } catch {}
  resetRegistryForTests();
  FakeWebSocket.instances.length = 0;
  globalThis.WebSocket = originalWebSocket;
});

test("browser websocket preserves connect, text, send, and local teardown contracts", async () => {
  await install();
  const received = [];
  const channel = new Channel((message) => received.push(message));
  let resolved = false;
  const connect = dispatch("plugin:websocket|connect", {
    url: "wss://relay.example.test",
    onMessage: channel,
    config: {},
  }).then((id) => {
    resolved = true;
    return id;
  });

  const socket = FakeWebSocket.instances[0];
  assert.equal(socket.url, "wss://relay.example.test");
  assert.equal(socket.binaryType, "arraybuffer");
  await Promise.resolve();
  assert.equal(resolved, false);

  socket.open();
  const id = await connect;
  socket.emit("message", { data: '["AUTH","challenge"]' });
  assert.deepEqual(received, [{ type: "Text", data: '["AUTH","challenge"]' }]);

  await dispatch("plugin:websocket|send", {
    id,
    message: { type: "Text", data: '["REQ","sub",{}]' },
  });
  assert.deepEqual(socket.sent, ['["REQ","sub",{}]']);

  await dispatch("plugin:websocket|disconnect", { id });
  assert.deepEqual(socket.closeCalls, [{ code: 1000, reason: "disconnect" }]);
  assert.equal(
    received.length,
    1,
    "local teardown must suppress Close callbacks",
  );
  await dispatch("plugin:websocket|disconnect", { id });
});

test("failed connects reject without exposing a socket id", async () => {
  await install();
  const connect = dispatch("plugin:websocket|connect", {
    url: "wss://relay.example.test",
    onMessage: new Channel(),
  });
  const socket = FakeWebSocket.instances[0];
  socket.emit("error");
  await assert.rejects(connect, /WebSocket connection failed/);
  assert.deepEqual(socket.closeCalls, [{ code: 1005, reason: "" }]);
});

test("connect blocks encrypted key backups in the URL", async () => {
  await install();
  await assert.rejects(
    dispatch("plugin:websocket|connect", {
      url: `wss://relay.example.test/${["ncr", "yptsec1secret"].join("")}`,
      onMessage: new Channel(),
    }),
    /local key backup must never be transmitted/,
  );
  assert.equal(FakeWebSocket.instances.length, 0);
});

test("remote terminal events preserve native payloads and remove ownership", async () => {
  await install();
  const received = [];
  const connect = dispatch("plugin:websocket|connect", {
    url: "wss://relay.example.test",
    onMessage: new Channel((message) => received.push(message)),
  });
  const socket = FakeWebSocket.instances[0];
  socket.open();
  const id = await connect;

  socket.emit("close", { code: 1012, reason: "relay restarting" });
  assert.deepEqual(received, [
    {
      type: "Close",
      data: { code: 1012, reason: "relay restarting" },
    },
  ]);
  await assert.rejects(
    dispatch("plugin:websocket|send", {
      id,
      message: { type: "Text", data: "hello" },
    }),
    /WebSocket connection .* not found/,
  );

  socket.emit("error");
  assert.equal(
    received.length,
    1,
    "one transport failure emits one terminal callback",
  );
});

test("text and binary sends block encrypted backups before socket lookup", async () => {
  await install();
  await assert.rejects(
    dispatch("plugin:websocket|send", {
      id: 999,
      message: {
        type: "Text",
        data: ["content:ncr", "yptsec1secret"].join(""),
      },
    }),
    /local key backup must never be transmitted/,
  );
  await assert.rejects(
    dispatch("plugin:websocket|send", {
      id: 999,
      message: {
        type: "Binary",
        data: Array.from(
          new TextEncoder().encode(["NCR", "YPTSEC1SECRET"].join("")),
        ),
      },
    }),
    /local key backup must never be transmitted/,
  );
});

test("close blocks encrypted key backups in the reason before teardown", async () => {
  await install();
  const connect = dispatch("plugin:websocket|connect", {
    url: "wss://relay.example.test",
    onMessage: new Channel(),
  });
  const socket = FakeWebSocket.instances[0];
  socket.open();
  const id = await connect;

  await assert.rejects(
    dispatch("plugin:websocket|send", {
      id,
      message: {
        type: "Close",
        data: {
          code: 1000,
          reason: ["NCR", "YPTSEC1SECRET"].join(""),
        },
      },
    }),
    /local key backup must never be transmitted/,
  );
  assert.deepEqual(socket.closeCalls, []);

  await dispatch("plugin:websocket|send", {
    id,
    message: { type: "Close", data: { code: 1000, reason: "done" } },
  });
  assert.deepEqual(socket.closeCalls, [{ code: 1000, reason: "done" }]);
});

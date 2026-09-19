import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import { after, test } from "node:test";

// Only signing is stubbed. Exercise the production query state machine with
// a controllable socket and clock, without an extension or live relay.
const hooks = registerHooks({
  resolve(specifier, context, nextResolve) {
    const source = {
      "nostr-tools/nip42": "export const makeAuthEvent = () => ({});",
      "@/shared/lib/nostr-signer":
        'export const signNostrEvent = async () => ({ id: "auth-id" });',
    }[specifier];
    return source
      ? {
          url: `data:text/javascript,${encodeURIComponent(source)}`,
          shortCircuit: true,
        }
      : nextResolve(specifier, context);
  },
});
const { queryEvents } = await import("./nostr-client.ts");
hooks.deregister();
const originalSocket = globalThis.WebSocket;
after(() => {
  globalThis.WebSocket = originalSocket;
});

class FakeSocket extends EventTarget {
  static latest;
  sent = [];
  closed = false;
  constructor() {
    super();
    FakeSocket.latest = this;
  }
  send(data) {
    assert.equal(this.closed, false, "must not send after closing");
    this.sent.push(JSON.parse(data));
  }
  close() {
    this.closed = true;
  }
  emit(type, data) {
    this.dispatchEvent(
      type === "message"
        ? new MessageEvent(type, { data: JSON.stringify(data) })
        : new Event(type),
    );
  }
}

function start(t) {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  globalThis.WebSocket = FakeSocket;
  const result = queryEvents("wss://relay.example", {
    kinds: [30617],
    limit: 500,
  });
  return { result, socket: FakeSocket.latest };
}

test("retains NOTICE when the relay closes before EOSE", async (t) => {
  const { result, socket } = start(t);
  const rejected = assert.rejects(
    result,
    /before completing the query: rate-limited: retry later/,
  );
  socket.emit("message", ["NOTICE", "rate-limited: retry later"]);
  socket.emit("close");
  await rejected;
});

test("informational NOTICE does not reject a complete query", async (t) => {
  const { result, socket } = start(t);
  socket.emit("open");
  t.mock.timers.tick(100);
  const subId = socket.sent[0][1];
  const event = { id: "event", kind: 30617 };
  socket.emit("message", ["NOTICE", "Welcome"]);
  socket.emit("message", ["EVENT", subId, event]);
  socket.emit("message", ["EOSE", subId]);
  assert.deepEqual(await result, [event]);
  assert.equal(socket.closed, true);
});

test("timeout cancels a fallback REQ scheduled just before the deadline", async (t) => {
  const { result, socket } = start(t);
  const rejected = assert.rejects(
    result,
    /timed out after 10000ms: restricted: query denied/,
  );
  t.mock.timers.tick(9_950);
  socket.emit("open");
  socket.emit("message", ["NOTICE", "restricted: query denied"]);
  t.mock.timers.tick(50);
  await rejected;
  t.mock.timers.tick(100);
  socket.emit("open");
  socket.emit("message", ["OK", null, true]);
  t.mock.timers.tick(100);
  assert.deepEqual(socket.sent, []);
});

test("CLOSED rejects only the matching subscription and preserves the reason", async (t) => {
  const { result, socket } = start(t);
  const rejected = assert.rejects(result, /restricted: membership required/);
  socket.emit("open");
  t.mock.timers.tick(100);
  socket.emit("message", ["CLOSED", "unrelated", "ignore"]);
  assert.equal(socket.closed, false);
  socket.emit("message", [
    "CLOSED",
    socket.sent[0][1],
    "restricted: membership required",
  ]);
  await rejected;
});

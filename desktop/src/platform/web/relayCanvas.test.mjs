import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { registerRelayCanvasCommands } from "./relayCanvas.ts";
import { dispatch, resetRegistryForTests } from "./registry.ts";

const CHANNEL_ID = "94a444a4-c0a3-5966-ab05-530c6ddc2301";
const PUBKEY = "a".repeat(64);

function identityWithCapture(requests) {
  return {
    sign(request) {
      requests.push(request);
      return JSON.stringify({
        ...request,
        id: "signed-canvas-event",
        pubkey: PUBKEY,
        created_at: 100,
        sig: "f".repeat(128),
      });
    },
  };
}

afterEach(() => resetRegistryForTests());

test("get_canvas queries kind 40100 by h tag and preserves the Rust wire shape", async () => {
  const filters = [];
  const client = {
    async fetchFirstEvent(filter) {
      filters.push(filter);
      return {
        id: "canvas-event",
        pubkey: PUBKEY,
        created_at: 1_721_234_567,
        kind: 40100,
        tags: [["h", CHANNEL_ID]],
        content: "# Current canvas",
        sig: "f".repeat(128),
      };
    },
  };
  registerRelayCanvasCommands(identityWithCapture([]), client);

  assert.deepEqual(await dispatch("get_canvas", { channelId: CHANNEL_ID }), {
    content: "# Current canvas",
    event_id: "canvas-event",
    updated_at: 1_721_234_567,
    author: PUBKEY,
  });
  assert.deepEqual(filters, [{ kinds: [40100], "#h": [CHANNEL_ID], limit: 1 }]);
});

test("get_canvas returns explicit null metadata when no canvas exists", async () => {
  const client = {
    async fetchFirstEvent() {
      return null;
    },
  };
  registerRelayCanvasCommands(identityWithCapture([]), client);

  assert.deepEqual(await dispatch("get_canvas", { channelId: CHANNEL_ID }), {
    content: "",
    event_id: null,
    updated_at: null,
    author: null,
  });
});

test("set_canvas signs and publishes the canonical kind-40100 event", async () => {
  const requests = [];
  const publications = [];
  const client = {
    async fetchFirstEvent() {
      return null;
    },
    async publishEvent(event, timeoutMessage, sendErrorMessage) {
      publications.push({ event, timeoutMessage, sendErrorMessage });
      return event;
    },
  };
  registerRelayCanvasCommands(identityWithCapture(requests), client);

  assert.deepEqual(
    await dispatch("set_canvas", {
      channelId: CHANNEL_ID.toUpperCase(),
      content: "# Plan\n\nShip it.",
    }),
    { ok: true, event_id: "signed-canvas-event" },
  );
  assert.deepEqual(requests, [
    {
      kind: 40100,
      content: "# Plan\n\nShip it.",
      tags: [["h", CHANNEL_ID]],
    },
  ]);
  assert.deepEqual(publications, [
    {
      event: {
        kind: 40100,
        content: "# Plan\n\nShip it.",
        tags: [["h", CHANNEL_ID]],
        id: "signed-canvas-event",
        pubkey: PUBKEY,
        created_at: 100,
        sig: "f".repeat(128),
      },
      timeoutMessage: "Timed out while setting the canvas.",
      sendErrorMessage: "Failed while setting the canvas.",
    },
  ]);
});

test("set_canvas mirrors UUID and UTF-8 content validation", async () => {
  const requests = [];
  const client = {
    async fetchFirstEvent() {
      return null;
    },
    async publishEvent(event) {
      return event;
    },
  };
  registerRelayCanvasCommands(identityWithCapture(requests), client);

  await assert.rejects(
    dispatch("set_canvas", { channelId: "not-a-uuid", content: "text" }),
    /invalid channel UUID: not-a-uuid/,
  );
  await assert.rejects(
    dispatch("set_canvas", {
      channelId: CHANNEL_ID,
      content: "🟧".repeat(16_385),
    }),
    /content exceeds maximum size of 65536 bytes \(got 65540\)/,
  );
  assert.deepEqual(requests, []);
});

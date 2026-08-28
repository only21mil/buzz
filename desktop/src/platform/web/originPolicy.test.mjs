import assert from "node:assert/strict";
import test from "node:test";

import {
  normalizeBrowserRelayUrl,
  relayHttpUrlFromBrowserRelay,
} from "./originPolicy.ts";

const HTTPS_APP = {
  href: "https://buzz.example/app/",
  origin: "https://buzz.example",
  protocol: "https:",
};

test("browser relay policy accepts only the matching secure origin", () => {
  assert.equal(
    normalizeBrowserRelayUrl("wss://buzz.example/", HTTPS_APP),
    "wss://buzz.example",
  );
  assert.equal(
    relayHttpUrlFromBrowserRelay("wss://buzz.example"),
    "https://buzz.example",
  );
});

test("browser relay policy rejects cross-origin and downgrade sockets", () => {
  for (const value of [
    "wss://other.example",
    "ws://buzz.example",
    "wss://buzz.example:444",
  ]) {
    assert.throws(
      () => normalizeBrowserRelayUrl(value, HTTPS_APP),
      /must match the application origin/,
    );
  }
});

test("browser relay policy rejects credentials and non-origin URLs", () => {
  for (const value of [
    "https://buzz.example",
    "wss://user:secret@buzz.example",
    "wss://buzz.example/socket",
    "wss://buzz.example/?token=secret",
    "wss://buzz.example/#fragment",
  ]) {
    assert.throws(() => normalizeBrowserRelayUrl(value, HTTPS_APP));
  }
});

import assert from "node:assert/strict";
import { test } from "node:test";

import { finalizeEvent, generateSecretKey } from "nostr-tools/pure";

import {
  blossomAuthorizationWithSigner,
  buildMediaGetAuthTemplate,
  mediaHashFromUrl,
} from "./mediaAuthProtocol.ts";

const HASH = "a".repeat(64);
const previousWindow = globalThis.window;

globalThis.window = { location: { origin: "https://relay.example" } };

test("media auth is same-origin, blob-scoped, and time-bounded", () => {
  assert.equal(
    mediaHashFromUrl(`https://relay.example/media/${HASH}.png?x=1`),
    HASH,
  );
  assert.equal(
    mediaHashFromUrl(`https://evil.example/media/${HASH}.png`),
    null,
  );
  assert.deepEqual(
    buildMediaGetAuthTemplate(`https://relay.example/media/${HASH}.png`, 1_000),
    {
      kind: 24242,
      content: "Get buzz-media",
      createdAt: 1_000,
      tags: [
        ["t", "get"],
        ["x", HASH],
        ["expiration", "1600"],
        ["server", "relay.example"],
      ],
    },
  );
});

test("authorization verifies the exact signed template and uses unpadded base64url", async () => {
  const secret = generateSecretKey();
  const template = buildMediaGetAuthTemplate(
    `https://relay.example/media/${HASH}.png`,
    1_000,
  );
  const authorization = await blossomAuthorizationWithSigner(
    template,
    async (template) => {
      return JSON.stringify(
        finalizeEvent(
          {
            kind: template.kind,
            content: template.content,
            created_at: template.createdAt,
            tags: template.tags,
          },
          secret,
        ),
      );
    },
  );
  assert.match(authorization, /^Nostr [A-Za-z0-9_-]+$/);
  assert.equal(authorization.includes("="), false);
});

test("authorization rejects a signer that mutates the requested event", async () => {
  const secret = generateSecretKey();
  await assert.rejects(
    blossomAuthorizationWithSigner(
      buildMediaGetAuthTemplate(
        `https://relay.example/media/${HASH}.png`,
        1_000,
      ),
      async (body) =>
        JSON.stringify(
          finalizeEvent(
            {
              kind: body.kind,
              content: `${body.content} changed`,
              created_at: body.createdAt,
              tags: body.tags,
            },
            secret,
          ),
        ),
    ),
    /changed the template/,
  );
});

test.after(() => {
  globalThis.window = previousWindow;
});

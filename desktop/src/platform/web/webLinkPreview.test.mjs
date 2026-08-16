import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { dispatch, resetRegistryForTests } from "./registry.ts";
import {
  fetchBrowserLinkPreviewMetadata,
  registerLinkPreviewCommands,
} from "./webLinkPreview.ts";

afterEach(() => {
  resetRegistryForTests();
});

test("link preview command degrades to null without fetching arbitrary URLs", async () => {
  registerLinkPreviewCommands();

  for (const href of [
    "https://example.com/article",
    "https://127.0.0.1/private",
    "https://user:secret@example.com/",
    "https://example.com:8443/",
  ]) {
    assert.equal(await dispatch("fetch_link_preview_metadata", { href }), null);
  }
  assert.equal(fetchBrowserLinkPreviewMetadata(), null);
});

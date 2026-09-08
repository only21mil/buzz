import assert from "node:assert/strict";
import test from "node:test";

import {
  assertManagedAgentPromptPersisted,
  assertPersonaPromptPersisted,
} from "@/shared/api/agentPromptPersistence";

test("managed-agent save rejects a response that discarded the prompt", () => {
  assert.throws(
    () =>
      assertManagedAgentPromptPersisted(
        { pubkey: "a".repeat(64), systemPrompt: "Updated prompt" },
        { systemPrompt: "Old prompt" },
      ),
    /System prompt was not saved/,
  );
});

test("managed-agent save accepts the returned prompt and ignores unrelated updates", () => {
  assert.doesNotThrow(() =>
    assertManagedAgentPromptPersisted(
      { pubkey: "a".repeat(64), systemPrompt: "Updated prompt" },
      { systemPrompt: "Updated prompt" },
    ),
  );
  assert.doesNotThrow(() =>
    assertManagedAgentPromptPersisted(
      { pubkey: "a".repeat(64), name: "Renamed" },
      { systemPrompt: "Old prompt" },
    ),
  );
});

test("definition save rejects a response that discarded the prompt", () => {
  assert.throws(
    () =>
      assertPersonaPromptPersisted(
        {
          id: "persona-1",
          displayName: "Qwen",
          systemPrompt: "Updated prompt",
        },
        { systemPrompt: "Old prompt" },
      ),
    /System prompt was not saved/,
  );
});

test("definition save accepts the returned prompt", () => {
  assert.doesNotThrow(() =>
    assertPersonaPromptPersisted(
      {
        id: "persona-1",
        displayName: "Qwen",
        systemPrompt: "Updated prompt",
      },
      { systemPrompt: "Updated prompt" },
    ),
  );
});

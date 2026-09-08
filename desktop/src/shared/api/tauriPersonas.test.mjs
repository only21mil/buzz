import assert from "node:assert/strict";
import test from "node:test";

import { agentManagementReviewContent } from "../../features/agents/agentManagementReview.ts";
import { fromRawPersona, updatePersona } from "./tauriPersonas.ts";

function rawPersona(overrides = {}) {
  return {
    id: "persona-1",
    display_name: "Team Analyst",
    avatar_url: null,
    system_prompt: "You are Team Analyst.",
    runtime: null,
    model: null,
    provider: null,
    name_pool: [],
    is_builtin: false,
    is_active: true,
    source_team: null,
    env_vars: {},
    created_at: "2026-01-01T00:00:00.000Z",
    updated_at: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

test("fromRawPersona maps source_team to sourceTeam", () => {
  const persona = fromRawPersona(rawPersona({ source_team: "team-research" }));

  assert.equal(persona.sourceTeam, "team-research");
});

test("owner review revision reaches the native update command unchanged", async () => {
  const previousWindow = globalThis.window;
  const calls = [];
  globalThis.window = {
    __TAURI_INTERNALS__: {
      invoke: async (command, args) => {
        calls.push({ command, args });
        return rawPersona();
      },
    },
  };
  try {
    const input = {
      id: "persona-1",
      displayName: "Reviewed",
      systemPrompt: "Prompt",
    };
    const expectedContent = agentManagementReviewContent(
      fromRawPersona(rawPersona()),
    );
    await updatePersona({
      ...input,
      expectedUpdatedAt: "revision-1",
      expectedContent,
      expectedShared: false,
    });
    await updatePersona(input);
    assert.equal(calls[0].command, "update_persona");
    assert.equal(calls[0].args.input.expectedUpdatedAt, "revision-1");
    assert.equal(calls[0].args.input.expectedShared, false);
    assert.deepEqual(
      JSON.parse(JSON.stringify(calls[0].args.input.expectedContent)),
      expectedContent,
    );
    assert.equal(calls[1].args.input.expectedUpdatedAt, undefined);
    assert.equal(calls[1].args.input.expectedShared, undefined);
    assert.equal(calls[1].args.input.expectedContent, undefined);
  } finally {
    if (previousWindow === undefined) delete globalThis.window;
    else globalThis.window = previousWindow;
  }
});

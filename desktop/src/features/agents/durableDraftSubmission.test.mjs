import assert from "node:assert/strict";
import test from "node:test";
import { submitDurableDraft } from "./durableDraftSubmission.ts";
import { agentManagementReviewContent } from "./agentManagementReview.ts";
import { draftPersonaForInstance } from "./durableDraftReview.ts";
import {
  agentDraftConfirm,
  agentDraftPrepare,
  agentDraftApply,
} from "@/shared/api/tauriAgentDrafts";

const scope = { owner: "a".repeat(64), relayUrl: "wss://community.example" };
const create = {
  type: "agent_management_request",
  action: "create",
  requestId: "request-uuid",
  request: {
    channelId: "channel",
    displayName: "Draft",
    systemPrompt: "Agent suggestion",
  },
};
const input = {
  displayName: "Owner edit",
  systemPrompt: "Exact reviewed prompt",
  runtime: "buzz-agent",
  model: "model",
  envVars: { SETTING: "reviewed" },
};
const runtime = {
  id: "buzz-agent",
  command: "buzz-agent",
  availability: "available",
};
const rawPersona = {
  id: "stable-persona",
  display_name: "Owner edit",
  system_prompt: "Exact reviewed prompt",
  avatar_url: null,
  is_builtin: false,
  created_at: "now",
  updated_at: "now",
};
const operation = {
  requestEventId: "signed-request-id",
  targetId: "stable-persona",
  action: "save",
  state: "prepared",
  claimEvent: {},
  persona: rawPersona,
  input,
  instanceInput: null,
  publishShared: false,
};
function harness(overrides = {}) {
  const calls = [];
  const previous = globalThis.window;
  globalThis.window = {
    __TAURI_INTERNALS__: {
      invoke: async (command, args) => {
        calls.push({ command, args: structuredClone(args) });
        return overrides.invoke
          ? overrides.invoke(command, args)
          : {
              ...operation,
              state: command === "agent_draft_prepare" ? "prepared" : "applied",
            };
      },
    },
  };
  const args = {
    scope,
    requestEventId: "signed-request-id",
    request: create,
    action: "save",
    input: structuredClone(input),
    reviewed: null,
    backend: null,
    currentPersona: () => undefined,
    availableRuntimes: async () => [runtime],
    assertAvailable: () => {},
    assertCurrent: () => {},
    ...overrides,
  };
  return {
    calls,
    args,
    restore: () => {
      if (previous === undefined) delete globalThis.window;
      else globalThis.window = previous;
    },
  };
}

test("explicit Save uses prepare/apply adapters with exact edited input and no instance authority", async () => {
  const f = harness();
  try {
    const result = await submitDurableDraft(f.args);
    assert.deepEqual(
      f.calls.map(({ command }) => command),
      ["agent_draft_prepare", "agent_draft_apply"],
    );
    assert.deepEqual(f.calls[0].args, {
      ...scope,
      requestEventId: "signed-request-id",
      action: "save",
      input,
      expectedContent: null,
      instanceInput: null,
      publishShared: false,
    });
    assert.deepEqual(f.calls[1].args, {
      ...scope,
      requestEventId: "signed-request-id",
    });
    assert.equal(result.persona.displayName, "Owner edit");
  } finally {
    f.restore();
  }
});

test("Create and Start pin runtime/backend and exact input before asynchronous preparation", async () => {
  for (const action of ["create", "start"]) {
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const f = harness({
      action,
      availableRuntimes: async () => {
        await gate;
        return [runtime];
      },
      backend: {
        type: "provider",
        id: "reviewed-provider",
        config: { region: "one" },
      },
    });
    try {
      const work = submitDurableDraft(f.args);
      f.args.input.systemPrompt = "Later unreviewed edit";
      f.args.backend.config.region = "two";
      release();
      await work;
      const prepared = f.calls[0].args;
      assert.equal(prepared.input.systemPrompt, input.systemPrompt);
      assert.equal(prepared.instanceInput.backend.config.region, "one");
      assert.equal(prepared.instanceInput.spawnAfterCreate, action === "start");
      assert.equal(prepared.instanceInput.startOnAppLaunch, false);
      assert.equal(prepared.instanceInput.personaId, create.requestId);
      assert.equal(prepared.action, action);
    } finally {
      f.restore();
    }
  }
});

test("shared update binds canonical content/revision and explicit publication", async () => {
  const reviewed = {
    ...draftPersonaForInstance(input, "target"),
    updatedAt: "same-second",
    shared: true,
  };
  const update = {
    ...create,
    action: "update",
    request: {
      channelId: "channel",
      agentName: reviewed.displayName,
      systemPrompt: "Agent suggestion",
    },
  };
  const f = harness({
    request: update,
    input: { ...input, id: "target" },
    reviewed,
    currentPersona: () => reviewed,
  });
  try {
    await submitDurableDraft(f.args);
    assert.equal(f.calls[0].args.input.expectedUpdatedAt, "same-second");
    assert.equal(f.calls[0].args.input.expectedShared, true);
    assert.deepEqual(
      f.calls[0].args.expectedContent,
      agentManagementReviewContent(reviewed),
    );
    assert.deepEqual(
      f.calls[0].args.input.expectedContent,
      agentManagementReviewContent(reviewed),
    );
    assert.equal(f.calls[0].args.publishShared, true);
  } finally {
    f.restore();
  }
});

test("same-second content changes, target replacement and revoked membership fail before prepare", async () => {
  const reviewed = {
    ...draftPersonaForInstance(input, "target"),
    updatedAt: "same-second",
  };
  for (const current of [
    { ...reviewed, systemPrompt: "Inbound replacement" },
    { ...reviewed, id: "other" },
    { ...reviewed, sourceTeam: "team" },
  ]) {
    const f = harness({
      request: { ...create, action: "update" },
      input: { ...input, id: "target" },
      reviewed,
      currentPersona: () => current,
    });
    try {
      await assert.rejects(submitDurableDraft(f.args), /changed since/);
      assert.equal(f.calls.length, 0);
    } finally {
      f.restore();
    }
  }
  let checks = 0;
  const f = harness({
    action: "start",
    assertAvailable: () => {
      if (++checks === 2) throw new Error("membership revoked");
    },
  });
  try {
    await assert.rejects(submitDurableDraft(f.args), /membership revoked/);
    assert.equal(f.calls.length, 0);
  } finally {
    f.restore();
  }
});

test("identity switch during native prepare retains the approval without calling apply", async () => {
  const f = harness({
    assertCurrent: () => {
      throw new Error("identity switched");
    },
  });
  try {
    await assert.rejects(submitDurableDraft(f.args), /identity switched/);
    assert.deepEqual(
      f.calls.map(({ command }) => command),
      ["agent_draft_prepare"],
    );
  } finally {
    f.restore();
  }
});

test("explicit Reject has no persona or instance input; confirm retries native retained bytes only", async () => {
  const f = harness();
  try {
    await agentDraftPrepare({
      ...scope,
      requestEventId: "signed-request-id",
      action: "reject",
      input: null,
      expectedContent: null,
      instanceInput: null,
      publishShared: false,
    });
    await agentDraftApply(scope, "signed-request-id");
    await agentDraftConfirm(scope, "signed-request-id");
    assert.equal(f.calls[0].args.input, null);
    assert.equal(f.calls[0].args.instanceInput, null);
    assert.equal(f.calls[0].args.action, "reject");
    assert.deepEqual(f.calls[2], {
      command: "agent_draft_confirm",
      args: { ...scope, requestEventId: "signed-request-id" },
    });
  } finally {
    f.restore();
  }
});

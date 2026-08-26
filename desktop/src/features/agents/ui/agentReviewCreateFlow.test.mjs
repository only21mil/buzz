import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { AgentDefinitionDialogFooter } from "./AgentDefinitionDialogFooter.tsx";

const noop = () => {};

test("owner-review footer makes Create agent the default and Start now explicit", () => {
  const footer = AgentDefinitionDialogFooter({
    canSubmit: true,
    isAvatarUploadPending: false,
    isPending: false,
    onCancel: noop,
    onSecondarySubmit: noop,
    publishesCatalogUpdates: false,
    secondarySubmitLabel: "Start now",
    submitBlockReason: null,
    submitLabel: "Create agent",
  });
  const actions = footer.props.children[1].props.children;

  assert.equal(actions.length, 3);
  assert.equal(actions[0].props.children, "Cancel");
  assert.equal(actions[1].props.children, "Start now");
  assert.equal(actions[1].props.type, "button");
  assert.equal(actions[1].props.form, undefined);
  assert.equal(actions[2].props.children, "Create agent");
  assert.equal(actions[2].props.type, "submit");
  assert.equal(actions[2].props.form, "persona-dialog-form");
});

test("stopped identity option is scoped to owned-agent review dialogs", async () => {
  const [managementDialogs, requestedDialogs] = await Promise.all([
    readFile(new URL("./AgentManagementDialogs.tsx", import.meta.url), "utf8"),
    readFile(
      new URL("./RequestedAgentCreateDialogs.tsx", import.meta.url),
      "utf8",
    ),
  ]);

  assert.match(managementDialogs, /offerStoppedCreate/);
  assert.match(
    managementDialogs,
    /key=\{management\.request\.requestId\}/,
    "each queued request remounts with fresh dialog state",
  );
  assert.doesNotMatch(requestedDialogs, /offerStoppedCreate/);
});

test("successful create advances the review queue only through dialog close", async () => {
  const managementHook = await readFile(
    new URL("../useAgentManagement.ts", import.meta.url),
    "utf8",
  );
  const createStart = managementHook.indexOf("async function submitCreate(");
  const updateStart = managementHook.indexOf("async function submitUpdate(");
  assert.ok(createStart >= 0 && updateStart > createStart);

  const createBody = managementHook.slice(createStart, updateStart);
  assert.doesNotMatch(
    createBody,
    /\bdismiss\(\)/,
    "the router close owns the single queue advance after create",
  );
});

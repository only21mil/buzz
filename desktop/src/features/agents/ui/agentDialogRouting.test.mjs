import assert from "node:assert/strict";
import test from "node:test";
import * as React from "react";
import { renderToString } from "react-dom/server";
import {
  Capability,
  setCapabilityAvailable,
} from "../../../platform/web/capabilities.ts";

import { AgentDialog } from "./AgentDialog.tsx";
import { AgentDefinitionDialog } from "./AgentDefinitionDialog.tsx";
import { AgentInstanceEditDialog } from "./AgentInstanceEditDialog.tsx";
import { AgentRunLocationProvider } from "./AgentRunLocationContext.tsx";

// Render the router inside React so its capability subscription is valid,
// while inspecting the selected form before any form hooks or effects mount.
function routeAgentDialog(props) {
  let element;
  function Capture() {
    element = AgentDialog(props);
    return null;
  }
  renderToString(React.createElement(Capture));
  return element;
}

const noop = () => {};

test("definition-edit routes to AgentDefinitionDialog with exact pass-through", () => {
  const props = {
    description: "Edit the agent definition.",
    error: null,
    initialValues: { displayName: "Brain" },
    isPending: false,
    onOpenChange: noop,
    onSubmit: async () => {},
    open: true,
    runtimes: [],
    runtimesLoading: false,
    submitLabel: "Save",
    title: "Edit agent",
  };

  const element = routeAgentDialog({ mode: "definition-edit", ...props });

  assert.equal(element.type, AgentDefinitionDialog);
  assert.deepEqual(element.props, props, "props must pass through unchanged");
  assert.equal(
    "mode" in element.props,
    false,
    "the mode discriminant must not leak into AgentDefinitionDialog",
  );
});

test("instance-edit routes to AgentInstanceEditDialog with its contract props", () => {
  const agent = { pubkey: "abc", name: "test-agent" };
  const onOpenChange = noop;
  const onUpdated = noop;

  const element = routeAgentDialog({
    mode: "instance-edit",
    agent,
    onOpenChange,
    onUpdated,
    open: true,
  });

  // The arm wraps the form in the run-location provider so the respond-to
  // warning can name the machine without the value being threaded as a prop
  // through AgentInstanceEditDialog (see AgentRunLocationContext for why).
  assert.equal(element.type, AgentRunLocationProvider);
  const form = element.props.children;
  assert.equal(form.type, AgentInstanceEditDialog);
  assert.deepEqual(form.props, {
    agent,
    onEditLinkedPersona: undefined,
    onOpenChange,
    onUpdated,
    open: true,
    initialFocus: undefined,
  });
});

test("instance-edit publishes the run location resolved from the agent backend", () => {
  const routeWithBackend = (backend) =>
    routeAgentDialog({
      mode: "instance-edit",
      agent: { pubkey: "abc", name: "test-agent", backend },
      onOpenChange: noop,
      onUpdated: noop,
      open: true,
    }).props.runLocation;

  assert.equal(routeWithBackend({ type: "local" }), "local");
  assert.equal(
    routeWithBackend({ type: "provider", id: "blox", config: {} }),
    "remote",
  );
  // An agent with no backend record has an unknown location — never a guess.
  assert.equal(routeWithBackend(undefined), null);
});

test("create mode routes to the internal create router, not a form directly", () => {
  const element = routeAgentDialog({
    mode: "definition",
    definitionError: null,
    isDefinitionPending: false,
    onOpenChange: noop,
    onSubmitDefinition: async () => true,
    runtimes: [],
    runtimesLoading: false,
  });

  assert.notEqual(element.type, AgentDefinitionDialog);
  assert.notEqual(element.type, AgentInstanceEditDialog);
  assert.equal(
    typeof element.type,
    "function",
    "definition must route through the internal create router",
  );
  assert.equal(element.type.name, "AgentCreateDialogRouter");
});

test("unavailable agent create and instance edit show a dismissible desktop notice", () => {
  setCapabilityAvailable(Capability.ManagedAgents, false);
  try {
    const element = routeAgentDialog({
      mode: "definition",
      onOpenChange: noop,
    });
    assert.equal(element.props.open, true);
    assert.equal(element.props.onOpenChange, noop);
    assert.equal(
      routeAgentDialog({ mode: "instance-edit", open: false }),
      null,
    );
    const edit = routeAgentDialog({
      mode: "definition-edit",
      open: true,
      onOpenChange: noop,
    });
    assert.equal(
      edit.type,
      AgentDefinitionDialog,
      "relay-backed definition editing stays reachable",
    );
  } finally {
    setCapabilityAvailable(Capability.ManagedAgents, true);
  }
});

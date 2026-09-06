import assert from "node:assert/strict";
import test from "node:test";
import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { JSDOM } from "jsdom";
import { useEffortDraft } from "./useEffortDraft.ts";
import {
  fromRawManagedAgent,
  fromRawAcpRuntimeCatalogEntry,
} from "../../../shared/api/tauri.ts";
import { effortPickerState } from "./effortPicker.ts";

test("effort draft survives polling, cancels locally and saves an explicit clear", async () => {
  const dom = new JSDOM("<div id='root'></div>");
  const previous = {
    window: globalThis.window,
    document: globalThis.document,
    act: globalThis.IS_REACT_ACT_ENVIRONMENT,
  };
  globalThis.window = dom.window;
  globalThis.document = dom.window.document;
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  const root = createRoot(document.getElementById("root"));
  let draft;
  function Form({ open, saved }) {
    draft = useEffortDraft(open, "agent", saved);
    return null;
  }
  const render = async (open, saved) =>
    act(async () => root.render(React.createElement(Form, { open, saved })));
  const writes = [];
  try {
    await render(true, "low");
    assert.equal(draft.patch, undefined);
    await act(async () => draft.onChange("high"));
    await render(true, "medium");
    assert.equal(draft.value, "high", "polling must preserve the draft");
    await render(false, "low");
    assert.equal(
      writes.length,
      0,
      "Cancel never invokes a persistence operation",
    );
    await render(true, "low");
    assert.equal(draft.value, "low");
    assert.equal(draft.patch, undefined);
    await act(async () => draft.onChange(null));
    writes.push({ effortLevel: draft.patch });
    assert.deepEqual(writes, [{ effortLevel: null }]);
  } finally {
    await act(async () => root.unmount());
    dom.window.close();
    globalThis.window = previous.window;
    globalThis.document = previous.document;
    globalThis.IS_REACT_ACT_ENVIRONMENT = previous.act;
  }
});

test("effort picker requires observed local capability", () => {
  const input = {
    backend: { type: "local" },
    currentEffort: "high",
    effortOptions: [{ value: "high" }],
  };
  assert.equal(
    effortPickerState({ ...input, currentEffort: null }).visible,
    false,
  );
  assert.equal(
    effortPickerState(input).visible,
    true,
    "saved effort can be cleared without a live session",
  );
  assert.equal(
    effortPickerState({ ...input, effortConfigId: "model-reasoning" }).visible,
    true,
  );
  assert.equal(
    effortPickerState({
      ...input,
      backend: { type: "provider", providerId: "remote" },
      effortConfigId: "model-reasoning",
    }).visible,
    false,
  );
});

test("native effort wire fields reach the draft and provider compatibility options", () => {
  assert.equal(
    fromRawManagedAgent({ effort_level: "high" }).effortLevel,
    "high",
  );
  assert.equal(fromRawManagedAgent({}).effortLevel, null);
  assert.deepEqual(
    fromRawAcpRuntimeCatalogEntry({ effort_canonical_values: ["off", "high"] })
      .effortCanonicalValues,
    ["off", "high"],
  );
});

test("an unavailable saved effort stays visible and can be cleared", () => {
  const state = effortPickerState({
    backend: { type: "local" },
    effortConfigId: "reasoning",
    effortOptions: [{ value: "high" }],
    currentEffort: "old",
  });
  assert.equal(state.selectValue, "old");
  assert.equal(
    state.options.find((option) => option.value === "old").disabled,
    true,
  );
});

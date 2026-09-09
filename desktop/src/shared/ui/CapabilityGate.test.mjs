import assert from "node:assert/strict";
import { after, afterEach, before, test } from "node:test";
import * as React from "react";
import { JSDOM } from "jsdom";
import {
  Capability,
  initializeBrowserCapabilities,
  setCapabilityAvailable,
} from "../../platform/web/capabilities.ts";
import { CapabilityGate } from "./CapabilityGate.tsx";

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "http://localhost",
  pretendToBeVisual: true,
});
let render, cleanup, fireEvent, act;
let nativeCalls = [];
before(async () => {
  Object.assign(globalThis, {
    window: dom.window,
    document: dom.window.document,
    HTMLElement: dom.window.HTMLElement,
    IS_REACT_ACT_ENVIRONMENT: true,
  });
  dom.window.matchMedia = () => ({
    matches: true,
    addEventListener() {},
    removeEventListener() {},
    addListener() {},
    removeListener() {},
  });
  dom.window.__TAURI_INTERNALS__ = {
    invoke(command) {
      nativeCalls.push(command);
      throw new Error(`Unexpected native call: ${command}`);
    },
  };
  ({ render, cleanup, fireEvent, act } = await import(
    "@testing-library/react"
  ));
});
afterEach(() => {
  cleanup();
  initializeBrowserCapabilities();
  nativeCalls = [];
});
after(() => dom.window.close());

test("capability changes mount and unmount the feature, including its effects", async () => {
  initializeBrowserCapabilities();
  let mounted = 0;
  let actions = 0;
  function Feature() {
    React.useEffect(() => {
      mounted++;
      return () => {
        mounted--;
      };
    }, []);
    return React.createElement(
      "button",
      { type: "button", onClick: () => actions++ },
      "Run",
    );
  }
  const view = render(
    React.createElement(
      CapabilityGate,
      { capability: Capability.ManagedAgents },
      React.createElement(Feature),
    ),
  );
  assert.equal(mounted, 0);
  assert.equal(view.queryByRole("button"), null);
  await act(() => setCapabilityAvailable(Capability.ManagedAgents, true));
  fireEvent.click(view.getByRole("button", { name: "Run" }));
  assert.equal(mounted, 1);
  assert.equal(actions, 1);
  await act(() => setCapabilityAvailable(Capability.ManagedAgents, false));
  assert.equal(mounted, 0);
  assert.equal(view.queryByRole("button"), null);
});

test("hosted onboarding displays a usable Back action without mounting sign-in", async () => {
  initializeBrowserCapabilities();
  const { HostedCommunityOnboarding } = await import(
    "../../features/communities/ui/HostedCommunityOnboarding.tsx"
  );
  let backs = 0;
  const view = render(
    React.createElement(HostedCommunityOnboarding, {
      onBack: () => backs++,
      stageHidden: true,
    }),
  );
  assert.match(
    view.getByRole("status").textContent,
    /Open Buzz desktop.*existing community/,
  );
  assert.equal(view.queryByRole("button", { name: /sign in/i }), null);
  fireEvent.click(view.getByRole("button", { name: "Back" }));
  assert.equal(backs, 1);
  assert.deepEqual(nativeCalls, []);
});

test("hosted create and recovery pairing never mount unsupported native flows", async () => {
  initializeBrowserCapabilities();
  const { HostedCommunityCreateFlow } = await import(
    "../../features/communities/ui/HostedCommunityCreateFlow.tsx"
  );
  const { IdentityRecoveryPairing } = await import(
    "../../features/onboarding/ui/IdentityRecoveryPairing.tsx"
  );
  render(
    React.createElement(
      React.Fragment,
      null,
      React.createElement(HostedCommunityCreateFlow, { onComplete() {} }),
      React.createElement(IdentityRecoveryPairing, { async onRecovered() {} }),
    ),
  );
  assert.match(document.body.textContent, /recovery key/);
  assert.equal(document.querySelectorAll("input, button").length, 0);
  assert.deepEqual(nativeCalls, []);
});

test("native settings show capability notices before their hooks or controls mount", async () => {
  initializeBrowserCapabilities();
  const { renderSettingsSection } = await import(
    "../../features/settings/ui/SettingsPanels.tsx"
  );
  // Module-level media URL discovery is a browser-supported read. The feature
  // components below must not start any native settings operations.
  nativeCalls = [];
  for (const section of [
    "voice",
    "agents",
    "compute",
    "hosted-communities",
    "local-archive",
    "mobile",
  ]) {
    const view = render(
      renderSettingsSection(section, { currentPubkey: "a".repeat(64) }),
    );
    assert.match(view.getByRole("status").textContent, /Open Buzz desktop/);
    assert.equal(view.queryByRole("button"), null);
    cleanup();
  }
  assert.deepEqual(nativeCalls, []);
});

test("persona controls disable native Start while keeping definition Edit available", async () => {
  initializeBrowserCapabilities();
  const { ProfilePersonaPrimaryActions } = await import(
    "../../features/profile/ui/UserProfilePrimaryActions.tsx"
  );
  const { TooltipProvider } = await import("./tooltip.tsx");
  let starts = 0;
  let edits = 0;
  const view = render(
    React.createElement(
      TooltipProvider,
      null,
      React.createElement(ProfilePersonaPrimaryActions, {
        canEditAgent: true,
        disabled: false,
        onStartAgent: () => starts++,
        onEditAgent: () => edits++,
      }),
    ),
  );
  const start = view.getByRole("button", { name: "Start Agent" });
  assert.equal(start.disabled, true);
  fireEvent.click(start);
  fireEvent.click(view.getByRole("button", { name: "Edit" }));
  assert.equal(starts, 0);
  assert.equal(edits, 1);
  await act(() => setCapabilityAvailable(Capability.ManagedAgents, true));
  fireEvent.click(start);
  assert.equal(starts, 1);
});

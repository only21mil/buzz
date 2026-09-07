import assert from "node:assert/strict";
import { after, afterEach, test } from "node:test";
import { JSDOM } from "jsdom";

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "http://localhost",
});
Object.assign(globalThis, {
  window: dom.window,
  document: dom.window.document,
  localStorage: dom.window.localStorage,
  HTMLElement: dom.window.HTMLElement,
  MutationObserver: dom.window.MutationObserver,
  IS_REACT_ACT_ENVIRONMENT: true,
  ResizeObserver: class {
    observe() {}
    disconnect() {}
  },
});
Object.defineProperty(globalThis, "navigator", {
  configurable: true,
  value: dom.window.navigator,
});
dom.window.matchMedia = () => ({
  matches: false,
  addEventListener() {},
  removeEventListener() {},
  addListener() {},
  removeListener() {},
});
for (const key of [
  "Node",
  "NodeFilter",
  "HTMLInputElement",
  "HTMLButtonElement",
  "SVGElement",
  "CustomEvent",
  "Event",
  "EventTarget",
  "getComputedStyle",
])
  globalThis[key] = dom.window[key];
globalThis.requestAnimationFrame = (callback) => setTimeout(callback, 0);
globalThis.cancelAnimationFrame = clearTimeout;
const probes = [];
class ControlledImage {
  addEventListener() {}
  removeEventListener() {}
  set src(value) {
    this.currentSrc = value;
    if (value.includes("buzz_avatar_probe")) probes.push(this);
  }
}
globalThis.Image = dom.window.Image = ControlledImage;
let readProfile;
let finishProfileWrite;
let profile;
const writes = [];
dom.window.__TAURI_INTERNALS__ = {
  invoke: async (command, payload) => {
    if (command === "get_profile") return readProfile();
    if (command === "list_personas") return [];
    if (command === "get_identity") return { pubkey: profile.pubkey };
    if (command === "update_profile" || command === "update_profile_at_relay") {
      writes.push({ command, payload });
      if (payload.avatarUrl !== undefined)
        profile.avatar_url = payload.avatarUrl;
      if (payload.displayName !== undefined)
        profile.display_name = payload.displayName;
      if (finishProfileWrite) await finishProfileWrite;
      return { ...profile };
    }
    throw new Error(`Unexpected command: ${command}`);
  },
};
const React = await import("react");
const { act, cleanup, fireEvent, render } = await import(
  "@testing-library/react"
);
const { QueryClient, QueryClientProvider } = await import(
  "@tanstack/react-query"
);
const { CommunityOnboardingProvider, useCommunityOnboarding } = await import(
  "../communityOnboarding.tsx"
);
const { CommunityOnboardingFlow } = await import(
  "./CommunityOnboardingFlow.tsx"
);
const {
  beginAvatarPresentation,
  getAvatarPresentation,
  resetAvatarPresentations,
} = await import("../../profile/avatarPresentationStore.ts");
const { resetAvatarProfileSync } = await import(
  "../../profile/avatarProfileSync.ts"
);
const { ThemeProvider } = await import(
  "../../../shared/theme/ThemeProvider.tsx"
);
const avatarUrl = "https://example.test/confirmed.png";
let queryClient;
let onboarding;
function FlowController() {
  onboarding = useCommunityOnboarding();
  return React.createElement(CommunityOnboardingFlow, {
    onCancel() {},
    onConnect() {},
  });
}

function mount() {
  profile = {
    pubkey: "1".repeat(64),
    display_name: null,
    avatar_url: avatarUrl,
    about: null,
    nip05_handle: null,
    owner_pubkey: null,
    has_profile_event: false,
  };
  readProfile = async () => ({ ...profile });
  finishProfileWrite = null;
  writes.length = 0;
  probes.length = 0;
  localStorage.setItem(
    "buzz-community-onboarding-transaction.v1",
    JSON.stringify({
      id: "profile-test",
      source: "first-community",
      stage: "profile",
      relayUrl: "wss://example.test",
      communityName: "Example",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }),
  );
  queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return () =>
    render(
      React.createElement(
        QueryClientProvider,
        { client: queryClient },
        React.createElement(
          CommunityOnboardingProvider,
          null,
          React.createElement(
            ThemeProvider,
            null,
            React.createElement(FlowController),
          ),
        ),
      ),
    );
}

async function saveName(view) {
  await act(async () => {
    fireEvent.change(view.getByTestId("community-profile-name-key"), {
      target: { value: "Updated name" },
    });
  });
  await act(async () => {
    fireEvent.click(view.getByTestId("community-profile-next"));
  });
}

afterEach(() => {
  cleanup();
  resetAvatarPresentations();
  resetAvatarProfileSync();
  queryClient?.clear();
  localStorage.clear();
});
after(() => dom.window.close());

test("hydrated ready avatar is omitted from a name-only save", async () => {
  const renderFlow = mount();
  beginAvatarPresentation(avatarUrl, new Blob(["image"]));
  let view;
  await act(async () => {
    view = renderFlow();
  });
  assert.equal(
    view.getByTestId("community-avatar-open").getAttribute("aria-label"),
    "Change your avatar",
  );
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.equal(probes.length, 1);
    probes[0].onload();
  });
  assert.equal(getAvatarPresentation(avatarUrl)?.state, "ready");
  await saveName(view);
  assert.deepEqual(
    writes.map(({ payload }) => payload.avatarUrl),
    [undefined],
  );
  assert.equal(profile.avatar_url, avatarUrl);
});

test("hydrated pending avatar does not register deferred propagation", async () => {
  const renderFlow = mount();
  beginAvatarPresentation(avatarUrl, new Blob(["image"]));
  let view;
  await act(async () => {
    view = renderFlow();
  });
  assert.equal(getAvatarPresentation(avatarUrl)?.state, "pending");
  await saveName(view);
  assert.deepEqual(
    writes.map(({ payload }) => payload.avatarUrl),
    [undefined],
  );
  // Complete the actual image verifier. A wrongly registered deferred save
  // would now issue update_profile_at_relay with the unchanged URL.
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.equal(probes.length, 1);
    probes[0].onload();
  });
  assert.equal(getAvatarPresentation(avatarUrl)?.state, "ready");
  assert.deepEqual(
    writes.map(({ payload }) => payload.avatarUrl),
    [undefined],
  );
  assert.equal(profile.avatar_url, avatarUrl);
});

test("name-only save before hydration still omits the saved avatar", async () => {
  const renderFlow = mount();
  const pendingReads = [];
  readProfile = () => new Promise((resolve) => pendingReads.push(resolve));
  let view;
  await act(async () => {
    view = renderFlow();
  });
  assert.equal(pendingReads.length, 2);
  await saveName(view);
  await act(async () => {
    for (const resolve of pendingReads) resolve({ ...profile });
  });
  assert.deepEqual(
    writes.map(({ payload }) => payload.avatarUrl),
    [undefined],
  );
  assert.equal(profile.avatar_url, avatarUrl);
});

test("late hydration preserves a user-cleared name", async () => {
  const renderFlow = mount();
  const pendingReads = [];
  readProfile = () => new Promise((resolve) => pendingReads.push(resolve));
  let view;
  await act(async () => {
    view = renderFlow();
  });
  const name = view.getByTestId("community-profile-name-key");
  fireEvent.change(name, { target: { value: "Draft" } });
  fireEvent.change(name, { target: { value: "" } });
  await act(async () => {
    for (const resolve of pendingReads)
      resolve({ ...profile, display_name: "Saved name" });
  });
  assert.equal(name.value, "");
});

test("new transactions discard previous drafts and late hydration", async () => {
  const renderFlow = mount();
  const previousReads = [];
  readProfile = () => new Promise((resolve) => previousReads.push(resolve));
  let view;
  await act(async () => {
    view = renderFlow();
  });
  fireEvent.change(view.getByTestId("community-profile-name-key"), {
    target: { value: "Old draft" },
  });
  await act(async () => {
    onboarding.clear();
  });
  readProfile = async () => ({ ...profile, avatar_url: null });
  await act(async () => {
    onboarding.start({
      source: "first-community",
      relayUrl: "wss://other.test",
    });
  });
  await act(async () => {
    onboarding.update({ stage: "profile" });
  });
  await act(async () => {
    for (const resolve of previousReads)
      resolve({ ...profile, display_name: "Old saved name" });
  });
  assert.equal(view.getByTestId("community-profile-name-key").value, "");
  assert.equal(
    view.getByTestId("community-avatar-open").getAttribute("aria-label"),
    "Add an avatar",
  );
});

test("late hydration preserves a ready user avatar replacement", async () => {
  const renderFlow = mount();
  const pendingReads = [];
  readProfile = () => new Promise((resolve) => pendingReads.push(resolve));
  let view;
  await act(async () => {
    view = renderFlow();
  });
  fireEvent.click(view.getByTestId("community-avatar-open"));
  const replacement = "https://example.test/replacement.png";
  fireEvent.change(view.getByTestId("community-avatar-url"), {
    target: { value: replacement },
  });
  await act(async () => {
    for (const resolve of pendingReads) resolve({ ...profile });
  });
  assert.equal(view.getByTestId("community-avatar-url").value, replacement);
  fireEvent.click(view.getByTestId("community-avatar-done"));
  await saveName(view);
  assert.deepEqual(
    writes.map(({ payload }) => payload.avatarUrl),
    [replacement],
  );
  assert.equal(profile.avatar_url, replacement);
});

test("selecting the saved avatar again omits the unchanged value", async () => {
  const renderFlow = mount();
  let view;
  await act(async () => {
    view = renderFlow();
  });
  fireEvent.click(view.getByTestId("community-avatar-open"));
  const input = view.getByTestId("community-avatar-url");
  fireEvent.change(input, {
    target: { value: "https://example.test/draft.png" },
  });
  fireEvent.change(input, { target: { value: avatarUrl } });
  fireEvent.click(view.getByTestId("community-avatar-done"));
  await saveName(view);
  assert.deepEqual(
    writes.map(({ payload }) => payload.avatarUrl),
    [undefined],
  );
  assert.equal(profile.avatar_url, avatarUrl);
});

test("an old profile save cannot advance a replacement transaction", async () => {
  const renderFlow = mount();
  let view;
  await act(async () => {
    view = renderFlow();
  });
  let releaseWrite;
  finishProfileWrite = new Promise((resolve) => {
    releaseWrite = resolve;
  });
  await saveName(view);
  assert.equal(writes.length, 1);
  await act(async () => {
    onboarding.clear();
  });
  await act(async () => {
    onboarding.start({
      source: "first-community",
      relayUrl: "wss://replacement.test",
    });
  });
  await act(async () => {
    onboarding.update({ stage: "profile" });
  });
  await act(async () => {
    releaseWrite();
  });
  assert.equal(onboarding.transaction.relayUrl, "wss://replacement.test");
  assert.equal(onboarding.transaction.stage, "profile");
});

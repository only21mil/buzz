import assert from "node:assert/strict";
import { after, afterEach, before, test } from "node:test";
import { JSDOM } from "jsdom";
import * as React from "react";
import { ChannelNavigationProvider } from "@/shared/context/ChannelNavigationContext.tsx";
import { useChannelLinks } from "./useChannelLinks.ts";

const dom = new JSDOM("<!doctype html><html><body></body></html>");
before(() =>
  Object.assign(globalThis, {
    document: dom.window.document,
    window: dom.window,
    HTMLElement: dom.window.HTMLElement,
    IS_REACT_ACT_ENVIRONMENT: true,
  }),
);
afterEach(async () => (await import("@testing-library/react")).cleanup());
after(() => dom.window.close());
const channels = [
  { id: "general", name: "general", channelType: "stream" },
  { id: "engineering", name: "engineering", channelType: "stream" },
];

async function setup(t) {
  const { act, renderHook } = await import("@testing-library/react");
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const hook = renderHook(useChannelLinks, {
    wrapper: ({ children }) =>
      React.createElement(ChannelNavigationProvider, { channels }, children),
  });
  act(() => hook.result.current.updateChannelQuery("Welcome to #general", 19));
  act(() => t.mock.timers.tick(120));
  assert.equal(hook.result.current.isChannelOpen, true);
  return { act, hook };
}

for (const [label, text] of [
  ["replacement body", "Edited, not deleted"],
  ["empty edit", ""],
  ["different channel query", "#eng"],
]) {
  test(`an old channel suggestion cannot consume Enter after ${label}`, async (t) => {
    const { act, hook } = await setup(t);
    let prevented = false;
    let result;
    act(() => {
      // Input and its immediately following Enter may run before React commits.
      const current = hook.result.current;
      current.updateChannelQuery(text, text.length);
      result = current.handleChannelKeyDown({
        key: "Enter",
        preventDefault: () => {
          prevented = true;
        },
      });
    });
    assert.equal(result.handled, false);
    assert.equal(prevented, false);
    assert.equal(hook.result.current.isChannelOpen, false);
    act(() => t.mock.timers.tick(120));
    assert.equal(hook.result.current.isChannelOpen, text === "#eng");
  });
}

test("an unchanged live query still accepts its selected channel", async (t) => {
  const { hook } = await setup(t);
  const result = hook.result.current.handleChannelKeyDown({
    key: "Enter",
    preventDefault() {},
  });
  assert.equal(result.handled, true);
  assert.equal(result.suggestion.id, "general");
});

test("cancelling revokes the visible query before the next render", async (t) => {
  const { act, hook } = await setup(t);
  let result;
  act(() => {
    const current = hook.result.current;
    current.clearChannels();
    result = current.handleChannelKeyDown({
      key: "Enter",
      preventDefault() {},
    });
  });
  assert.equal(result.handled, false);
  act(() => t.mock.timers.tick(120));
  assert.equal(hook.result.current.isChannelOpen, false);
});

test("settling a new query cannot grant a retained handler the old suggestion", async (t) => {
  const { act, hook } = await setup(t);
  let result;
  act(() => {
    const previous = hook.result.current;
    previous.updateChannelQuery("#eng", 4);
    t.mock.timers.tick(120);
    result = previous.handleChannelKeyDown({
      key: "Enter",
      preventDefault() {},
    });
  });
  assert.equal(result.handled, false);
  const next = hook.result.current.handleChannelKeyDown({
    key: "Enter",
    preventDefault() {},
  });
  assert.equal(next.handled, true);
  assert.equal(next.suggestion.id, "engineering");
});

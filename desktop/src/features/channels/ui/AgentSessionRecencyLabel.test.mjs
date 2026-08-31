import assert from "node:assert/strict";
import { after, afterEach, before, mock, test } from "node:test";

import { JSDOM } from "jsdom";

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "http://localhost",
});

let React;
let act;
let cleanup;
let render;
let screen;
let AgentSessionRecencyLabel;

before(async () => {
  Object.assign(globalThis, {
    document: dom.window.document,
    HTMLElement: dom.window.HTMLElement,
    IS_REACT_ACT_ENVIRONMENT: true,
    window: dom.window,
  });
  React = await import("react");
  ({ act, cleanup, render, screen } = await import("@testing-library/react"));
  ({ AgentSessionRecencyLabel } = await import(
    "./AgentSessionRecencyLabel.tsx"
  ));
});

afterEach(() => {
  cleanup();
  mock.timers.reset();
});

after(() => dom.window.close());

test("recency ticks commit only the isolated label", () => {
  const epoch = Date.parse("2026-08-30T12:00:00.000Z");
  mock.timers.enable({ apis: ["setInterval", "Date"], now: epoch });
  let bodyRenders = 0;
  let labelCommits = 0;

  function ExpensiveActivityBody() {
    bodyRenders += 1;
    return React.createElement("div", null, "activity body");
  }

  render(
    React.createElement(
      React.Fragment,
      null,
      React.createElement(
        React.Profiler,
        {
          id: "recency",
          onRender: () => {
            labelCommits += 1;
          },
        },
        React.createElement(AgentSessionRecencyLabel, {
          latestActivityAt: epoch - 61_000,
        }),
      ),
      React.createElement(ExpensiveActivityBody),
    ),
  );

  assert.equal(
    screen.getByTestId("agent-session-recency-label").textContent,
    "Last updated 1m ago",
  );
  assert.equal(bodyRenders, 1);
  assert.equal(labelCommits, 1);

  act(() => mock.timers.tick(60_000));

  assert.equal(
    screen.getByTestId("agent-session-recency-label").textContent,
    "Last updated 2m ago",
  );
  assert.equal(
    bodyRenders,
    1,
    "the activity body must not render on clock ticks",
  );
  assert.equal(
    labelCommits,
    2,
    "the recency label should own the timer commit",
  );
});

test("an empty recency label does not start a timer", () => {
  const originalSetInterval = globalThis.setInterval;
  let intervalCount = 0;
  globalThis.setInterval = (...args) => {
    intervalCount += 1;
    return originalSetInterval(...args);
  };

  try {
    render(
      React.createElement(AgentSessionRecencyLabel, {
        latestActivityAt: null,
      }),
    );
  } finally {
    globalThis.setInterval = originalSetInterval;
  }

  assert.equal(
    screen.getByTestId("agent-session-recency-label").textContent,
    "No updates yet",
  );
  assert.equal(intervalCount, 0);
});

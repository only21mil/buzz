import assert from "node:assert/strict";
import { after, afterEach, before, test } from "node:test";

import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { JSDOM } from "jsdom";

import { describeRawEvent } from "./agentSessionTranscriptHelpers.ts";
import { RawEventRail } from "./RawEventRail.tsx";

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "http://localhost",
});

before(() => {
  Object.assign(globalThis, {
    document: dom.window.document,
    HTMLElement: dom.window.HTMLElement,
    IS_REACT_ACT_ENVIRONMENT: true,
    window: dom.window,
  });
});

afterEach(async () => {
  const { cleanup } = await import("@testing-library/react");
  cleanup();
});

after(() => dom.window.close());

function rawEvent(overrides = {}) {
  return {
    seq: 1,
    kind: "acp",
    sessionId: "sess-1",
    channelId: "channel-1",
    timestamp: "2026-07-13T00:00:00.000Z",
    payload: {},
    ...overrides,
  };
}

test("describeRawEvent surfaces the session/update sessionUpdate label", () => {
  const event = rawEvent({
    payload: {
      method: "session/update",
      params: { update: { sessionUpdate: "agent_message_chunk" } },
    },
  });
  assert.equal(describeRawEvent(event), "agent_message_chunk");
});

test("describeRawEvent falls back to the method when session/update lacks an update label", () => {
  const event = rawEvent({
    payload: { method: "session/update", params: {} },
  });
  assert.equal(describeRawEvent(event), "session/update");
});

test("describeRawEvent uses the method for non-session/update payloads", () => {
  const event = rawEvent({ payload: { method: "session/prompt" } });
  assert.equal(describeRawEvent(event), "session/prompt");
});

test("describeRawEvent falls back to the event kind when no method is present", () => {
  const event = rawEvent({ kind: "acp_parse_error", payload: {} });
  assert.equal(describeRawEvent(event), "acp_parse_error");
});

test("RawEventRail render: each row exposes data-message-id keyed on (seq, timestamp) for scroll anchoring", () => {
  const events = [rawEvent({ seq: 1 }), rawEvent({ seq: 2 })];
  const html = renderToStaticMarkup(
    React.createElement(RawEventRail, { events }),
  );
  assert.ok(
    html.includes('data-message-id="1:2026-07-13T00:00:00.000Z"'),
    "row for seq 1 should carry data-message-id",
  );
  assert.ok(
    html.includes('data-message-id="2:2026-07-13T00:00:00.000Z"'),
    "row for seq 2 should carry data-message-id",
  );
});

test("RawEventRail render: rows sharing seq across an agent restart get distinct ids", () => {
  // seq is process-local and resets to 1 on every agent restart, so two
  // rows can share seq while their timestamps differ. Both must render a
  // distinct data-message-id or the scroll anchor (and prop-id delta
  // classification) collapses the two rows into one identity.
  const events = [
    rawEvent({ seq: 1, timestamp: "2026-07-13T00:00:00.000Z" }),
    rawEvent({ seq: 1, timestamp: "2026-07-13T01:00:00.000Z" }),
  ];
  const html = renderToStaticMarkup(
    React.createElement(RawEventRail, { events }),
  );
  assert.ok(
    html.includes('data-message-id="1:2026-07-13T00:00:00.000Z"'),
    "pre-restart row should carry the pre-restart id",
  );
  assert.ok(
    html.includes('data-message-id="1:2026-07-13T01:00:00.000Z"'),
    "post-restart row should carry a distinct post-restart id",
  );
});

test("RawEventRail serializes payloads only while their row is open", async () => {
  let serializationCount = 0;
  const payload = {
    toJSON() {
      serializationCount += 1;
      return { private: "expanded payload" };
    },
  };
  const events = [rawEvent({ payload })];
  const { fireEvent, render, screen } = await import("@testing-library/react");
  const view = render(React.createElement(RawEventRail, { events }));
  const details = view.container.querySelector("details");
  const summary = view.container.querySelector("summary");

  assert.ok(details);
  assert.ok(summary);
  assert.equal(
    serializationCount,
    0,
    "closed rows must not stringify payloads",
  );
  assert.equal(view.container.querySelector("pre"), null);

  details.open = true;
  fireEvent(details, new dom.window.Event("toggle", { bubbles: true }));

  assert.equal(details.open, true);
  assert.ok(view.container.querySelector("pre"));
  assert.equal(serializationCount, 1);
  assert.match(
    screen.getByText(/expanded payload/).textContent,
    /expanded payload/,
  );

  details.open = false;
  fireEvent(details, new dom.window.Event("toggle", { bubbles: true }));

  assert.equal(details.open, false);
  assert.equal(view.container.querySelector("pre"), null);
  view.rerender(React.createElement(RawEventRail, { events }));

  assert.equal(
    serializationCount,
    1,
    "closing and rerendering must not stringify again",
  );
  assert.equal(view.container.querySelector("pre"), null);
});

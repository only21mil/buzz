import assert from "node:assert/strict";
import { after, test } from "node:test";
import { JSDOM } from "jsdom";
import React from "react";

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "https://buzz.example",
});
Object.assign(globalThis, {
  window: dom.window,
  document: dom.window.document,
  HTMLElement: dom.window.HTMLElement,
  IS_REACT_ACT_ENVIRONMENT: true,
});
after(() => dom.window.close());

test("browser Projects create control cannot invoke any write action", async () => {
  const { render, fireEvent, cleanup } = await import("@testing-library/react");
  const { ProjectsCreateMenu } = await import("./ProjectsCreateMenu.tsx");
  let writes = 0;
  const write = () => {
    writes += 1;
  };
  try {
    const view = render(
      React.createElement(ProjectsCreateMenu, {
        onCreateIssue: write,
        onCreateProject: write,
        onCreatePullRequest: write,
      }),
    );
    const button = view.getByRole("button", { name: "Create" });
    assert.equal(button.disabled, true);
    assert.match(button.title, /desktop app/);
    fireEvent.click(button);
    fireEvent.mouseEnter(button);
    assert.equal(writes, 0);
    assert.equal(view.queryByRole("menu"), null);
  } finally {
    cleanup();
  }
});

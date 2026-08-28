import assert from "node:assert/strict";
import test from "node:test";

import {
  focusMainContentAfterRouteChange,
  routeAnnouncement,
} from "./AppRouteAccessibility.tsx";

test("route announcements use stable human-readable destinations", () => {
  assert.equal(routeAnnouncement("/"), "Home view");
  assert.equal(routeAnnouncement("/channels/channel-id"), "Channel view");
  assert.equal(routeAnnouncement("/workflows/run-id"), "Workflows view");
  assert.equal(routeAnnouncement("/settings"), "Settings view");
});
function withDocument(fakeDocument, run) {
  const original = Object.getOwnPropertyDescriptor(globalThis, "document");
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: fakeDocument,
  });
  try {
    run();
  } finally {
    if (original) {
      Object.defineProperty(globalThis, "document", original);
    } else {
      delete globalThis.document;
    }
  }
}

test("route focus preserves new descendant autofocus inside main", () => {
  const activeAtRouteChange = { id: "previous-navigation" };
  const recipientSearch = { id: "new-dm-search" };
  let focusCalls = 0;
  const main = {
    contains(node) {
      return node === recipientSearch;
    },
    focus() {
      focusCalls += 1;
    },
  };

  withDocument(
    {
      activeElement: recipientSearch,
      getElementById(id) {
        return id === "main-content" ? main : null;
      },
    },
    () => focusMainContentAfterRouteChange(activeAtRouteChange),
  );

  assert.equal(focusCalls, 0);
});

test("route focus falls back to main when no descendant claimed focus", () => {
  const activeAtRouteChange = { id: "navigation" };
  const focusOptions = [];
  const main = {
    contains() {
      return false;
    },
    focus(options) {
      focusOptions.push(options);
    },
  };

  withDocument(
    {
      activeElement: activeAtRouteChange,
      getElementById(id) {
        return id === "main-content" ? main : null;
      },
    },
    () => focusMainContentAfterRouteChange(activeAtRouteChange),
  );

  assert.deepEqual(focusOptions, [{ preventScroll: true }]);
});

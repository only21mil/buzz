import assert from "node:assert/strict";
import test from "node:test";

import { routeAnnouncement } from "./AppRouteAccessibility.tsx";

test("route announcements use stable human-readable destinations", () => {
  assert.equal(routeAnnouncement("/"), "Home view");
  assert.equal(routeAnnouncement("/channels/channel-id"), "Channel view");
  assert.equal(routeAnnouncement("/workflows/run-id"), "Workflows view");
  assert.equal(routeAnnouncement("/settings"), "Settings view");
});

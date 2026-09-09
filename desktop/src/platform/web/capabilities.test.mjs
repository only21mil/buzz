import assert from "node:assert/strict";
import { test } from "node:test";
import {
  Capability,
  initializeBrowserCapabilities,
  isCapabilityAvailable,
  setCapabilityAvailable,
} from "./capabilities.ts";
import {
  getTerminalPanelSnapshotForTests,
  resetTerminalPanelForTests,
  setTerminalPanelMode,
  toggleTerminalPanel,
} from "../../features/terminal/terminalPanelStore.ts";

test("desktop defaults preserve capabilities; browser installation resets only implemented features on", () => {
  for (const capability of Object.values(Capability))
    assert.equal(isCapabilityAvailable(capability), true);
  initializeBrowserCapabilities();
  const available = Object.values(Capability).filter(isCapabilityAvailable);
  assert.deepEqual(available, [
    Capability.LinkPreview,
    Capability.AddCommunity,
  ]);
  setCapabilityAvailable(Capability.Terminal, true);
  initializeBrowserCapabilities();
  assert.equal(isCapabilityAvailable(Capability.Terminal), false);
});

test("terminal shortcut and programmatic open cannot activate an unavailable terminal", () => {
  initializeBrowserCapabilities();
  resetTerminalPanelForTests();
  toggleTerminalPanel();
  setTerminalPanelMode("maximized");
  assert.equal(getTerminalPanelSnapshotForTests().mode, "closed");
  setCapabilityAvailable(Capability.Terminal, true);
  toggleTerminalPanel();
  assert.equal(getTerminalPanelSnapshotForTests().mode, "docked");
  setCapabilityAvailable(Capability.Terminal, false);
  setTerminalPanelMode("closed");
  assert.equal(getTerminalPanelSnapshotForTests().mode, "closed");
});

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  HUDDLE_METER_UPDATE_INTERVAL_MS,
  reconcileHuddleActiveSpeakers,
  reconcileHuddleMeterLevel,
  reconcileHuddleSpeakerLevels,
} from "./useHuddleSpeakerActivity.ts";

const FIVE_SECONDS_MS = 5_000;

test("five seconds of unchanged silence cause no React meter state replacements", () => {
  let micLevel = 0;
  let speakerLevels = {};
  let activeSpeakers = [];
  let updates = 0;

  for (
    let elapsed = 0;
    elapsed < FIVE_SECONDS_MS;
    elapsed += HUDDLE_METER_UPDATE_INTERVAL_MS
  ) {
    const nextMicLevel = reconcileHuddleMeterLevel(micLevel, 0);
    const nextSpeakerLevels = reconcileHuddleSpeakerLevels(speakerLevels, {});
    const nextActiveSpeakers = reconcileHuddleActiveSpeakers(
      activeSpeakers,
      [],
    );
    updates += Number(nextMicLevel !== micLevel);
    updates += Number(nextSpeakerLevels !== speakerLevels);
    updates += Number(nextActiveSpeakers !== activeSpeakers);
    micLevel = nextMicLevel;
    speakerLevels = nextSpeakerLevels;
    activeSpeakers = nextActiveSpeakers;
  }

  assert.equal(updates, 0);
});

test("five seconds of speech stay bounded by cadence and meter buckets", () => {
  const ticks = FIVE_SECONDS_MS / HUDDLE_METER_UPDATE_INTERVAL_MS;
  let micLevel = 0;
  let speakerLevels = {};
  let micUpdates = 0;
  let speakerUpdates = 0;

  for (let tick = 0; tick < ticks; tick += 1) {
    // A smooth ramp exercises every meter bucket while providing many more
    // samples than the UI should publish as distinct values.
    const sample = 0.2 + (tick / (ticks - 1)) * 0.8;
    const nextMicLevel = reconcileHuddleMeterLevel(micLevel, sample);
    const nextSpeakerLevels = reconcileHuddleSpeakerLevels(speakerLevels, {
      speaker: sample,
    });
    micUpdates += Number(nextMicLevel !== micLevel);
    speakerUpdates += Number(nextSpeakerLevels !== speakerLevels);
    micLevel = nextMicLevel;
    speakerLevels = nextSpeakerLevels;
  }

  assert.ok(micUpdates > 0);
  assert.ok(speakerUpdates > 0);
  assert.ok(micUpdates <= 17, `mic updates: ${micUpdates}`);
  assert.ok(speakerUpdates <= 17, `speaker updates: ${speakerUpdates}`);
  assert.ok(micUpdates <= ticks);
  assert.ok(speakerUpdates <= ticks);
});

test("semantically unchanged speaker payloads preserve React state identity", () => {
  const levels = { alice: 0.5, bob: 0.75 };
  const speakers = ["alice", "bob"];

  assert.equal(
    reconcileHuddleSpeakerLevels(levels, { bob: 0.76, alice: 0.51 }),
    levels,
  );
  assert.equal(
    reconcileHuddleActiveSpeakers(speakers, ["BOB", "ALICE", "alice"]),
    speakers,
  );
});

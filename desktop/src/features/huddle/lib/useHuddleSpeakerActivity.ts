import { listen } from "@tauri-apps/api/event";
import * as React from "react";

type TtsSpeakerActivity = { pubkey: string; level: number };

export const HUDDLE_METER_UPDATE_INTERVAL_MS = 100;
const HUDDLE_METER_STEPS = 20;

export function quantizeHuddleMeterLevel(level: number): number {
  if (!Number.isFinite(level)) return 0;
  return (
    Math.round(Math.min(1, Math.max(0, level)) * HUDDLE_METER_STEPS) /
    HUDDLE_METER_STEPS
  );
}

export function reconcileHuddleMeterLevel(
  previous: number,
  level: number,
): number {
  const next = quantizeHuddleMeterLevel(level);
  return previous === next ? previous : next;
}

export function reconcileHuddleSpeakerLevels(
  previous: Record<string, number>,
  payload: Record<string, number>,
): Record<string, number> {
  const next: Record<string, number> = {};
  for (const [pubkey, level] of Object.entries(payload)) {
    const quantized = quantizeHuddleMeterLevel(level);
    if (pubkey && quantized > 0) next[pubkey] = quantized;
  }

  const previousKeys = Object.keys(previous);
  const nextKeys = Object.keys(next);
  if (
    previousKeys.length === nextKeys.length &&
    nextKeys.every((pubkey) => previous[pubkey] === next[pubkey])
  ) {
    return previous;
  }
  return next;
}

export function reconcileHuddleActiveSpeakers(
  previous: string[],
  payload: string[],
): string[] {
  const byNormalizedPubkey = new Map<string, string>();
  for (const pubkey of payload) {
    if (pubkey) byNormalizedPubkey.set(pubkey.toLowerCase(), pubkey);
  }
  const next = [...byNormalizedPubkey.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([, pubkey]) => pubkey);
  if (
    previous.length === next.length &&
    next.every(
      (pubkey, index) =>
        previous[index]?.toLowerCase() === pubkey.toLowerCase(),
    )
  ) {
    return previous;
  }
  return next;
}

export function useHuddleSpeakerActivity() {
  const [remoteActiveSpeakers, setRemoteActiveSpeakers] = React.useState<
    string[]
  >([]);
  const [remoteSpeakerLevels, setRemoteSpeakerLevels] = React.useState<
    Record<string, number>
  >({});
  const [ttsSpeakerActivity, setTtsSpeakerActivity] =
    React.useState<TtsSpeakerActivity | null>(null);

  const activeSpeakers = React.useMemo(() => {
    if (!ttsSpeakerActivity) return remoteActiveSpeakers;
    const normalizedTtsPubkey = ttsSpeakerActivity.pubkey.toLowerCase();
    if (
      remoteActiveSpeakers.some(
        (pubkey) => pubkey.toLowerCase() === normalizedTtsPubkey,
      )
    ) {
      return remoteActiveSpeakers;
    }
    return [...remoteActiveSpeakers, ttsSpeakerActivity.pubkey];
  }, [remoteActiveSpeakers, ttsSpeakerActivity]);

  const speakerLevels = React.useMemo(() => {
    if (!ttsSpeakerActivity) return remoteSpeakerLevels;
    return {
      ...remoteSpeakerLevels,
      [ttsSpeakerActivity.pubkey]: Math.max(
        remoteSpeakerLevels[ttsSpeakerActivity.pubkey] ?? 0,
        ttsSpeakerActivity.level,
      ),
    };
  }, [remoteSpeakerLevels, ttsSpeakerActivity]);

  React.useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | null = null;
    listen<Record<string, number>>("huddle-speaker-levels", (event) => {
      if (!cancelled) {
        setRemoteSpeakerLevels((previous) =>
          reconcileHuddleSpeakerLevels(previous, event.payload),
        );
      }
    }).then((cleanup) => {
      if (cancelled) cleanup();
      else unlisten = cleanup;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  React.useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | null = null;
    listen<{ pubkey: string | null; level: number }>(
      "huddle-tts-speaker-level",
      (event) => {
        if (cancelled) return;
        const { pubkey, level } = event.payload;
        const quantizedLevel = quantizeHuddleMeterLevel(level);
        setTtsSpeakerActivity((previous) => {
          if (!pubkey || quantizedLevel === 0)
            return previous ? null : previous;
          if (
            previous?.pubkey.toLowerCase() === pubkey.toLowerCase() &&
            previous.level === quantizedLevel
          ) {
            return previous;
          }
          return { pubkey, level: quantizedLevel };
        });
      },
    ).then((cleanup) => {
      if (cancelled) cleanup();
      else unlisten = cleanup;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  React.useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | null = null;
    listen<string[]>("huddle-active-speakers", (event) => {
      if (!cancelled) {
        setRemoteActiveSpeakers((previous) =>
          reconcileHuddleActiveSpeakers(previous, event.payload),
        );
      }
    }).then((cleanup) => {
      if (cancelled) cleanup();
      else unlisten = cleanup;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  const resetSpeakerActivity = React.useCallback(() => {
    setRemoteActiveSpeakers((previous) =>
      previous.length === 0 ? previous : [],
    );
    setRemoteSpeakerLevels((previous) =>
      Object.keys(previous).length === 0 ? previous : {},
    );
    setTtsSpeakerActivity(null);
  }, []);

  return { activeSpeakers, resetSpeakerActivity, speakerLevels };
}

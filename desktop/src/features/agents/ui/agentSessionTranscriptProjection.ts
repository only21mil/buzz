import type { ObserverEvent } from "./agentSessionTypes";
import {
  buildTranscriptState,
  processTranscriptEvent,
  type TranscriptState,
} from "./agentSessionTranscript";

export type TranscriptProjection = Readonly<{
  events: readonly ObserverEvent[];
  state: TranscriptState;
}>;

/**
 * Project a sorted observer-event window into transcript state.
 *
 * Live frames normally extend the existing window. In that common case only
 * the appended suffix needs parsing. Archive paging prepends history, while a
 * late frame or live-window trim can change the existing prefix; those cases
 * deliberately rebuild so stateful ACP relationships remain correct.
 *
 * Prefix identity is intentionally strict. Observer store arrays are
 * immutable and retain event objects between snapshots, so reference equality
 * gives us a cheap, unambiguous append-only proof without deep-comparing large
 * payloads. Any cloned or replaced event takes the conservative rebuild path.
 */
export function projectTranscriptEvents(
  previous: TranscriptProjection | null,
  events: readonly ObserverEvent[],
): TranscriptProjection {
  if (previous?.events === events) {
    return previous;
  }

  if (!previous || !hasIdenticalPrefix(previous.events, events)) {
    return { events, state: buildTranscriptState(events) };
  }

  let state = previous.state;
  for (let index = previous.events.length; index < events.length; index += 1) {
    state = processTranscriptEvent(state, events[index]);
  }
  return { events, state };
}

function hasIdenticalPrefix(
  previous: readonly ObserverEvent[],
  events: readonly ObserverEvent[],
): boolean {
  if (previous.length > events.length) {
    return false;
  }
  for (let index = 0; index < previous.length; index += 1) {
    if (previous[index] !== events[index]) {
      return false;
    }
  }
  return true;
}

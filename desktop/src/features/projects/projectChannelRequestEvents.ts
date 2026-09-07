import {
  parseProjectChannelRequest,
  type ProjectChannelRequest,
} from "./projectChannelRequest";

const listeners = new Set<
  (agentPubkey: string, request: ProjectChannelRequest) => void
>();
/** Called only after the observer store verifies and decrypts its source frame. */
export function dispatchProjectChannelRequest(
  agentPubkey: string,
  payload: unknown,
): boolean {
  const request = parseProjectChannelRequest(payload);
  if (!request) return false;
  for (const listener of listeners) listener(agentPubkey, request);
  return true;
}
export function subscribeProjectChannelRequests(
  listener: (agentPubkey: string, request: ProjectChannelRequest) => void,
) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}
export function resetProjectChannelRequests() {
  listeners.clear();
}

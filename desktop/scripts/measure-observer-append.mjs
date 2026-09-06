// Deterministic work counter, not a CPU benchmark. Run with the desktop test loader.
const store = await import(
  process.env.OBSERVER_STORE_MODULE ??
    "../src/features/agents/observerRelayStore.ts"
);
const agent = "a".repeat(64);
const events = Array.from({ length: 1000 }, (_, seq) => ({
  seq,
  timestamp: "2026-08-01T00:00:00Z",
  kind: "turn_liveness",
  agentIndex: 0,
  channelId: "channel",
  sessionId: "session",
  turnId: "turn",
  payload: null,
}));
for (let trial = 1; trial <= 3; trial++) {
  store.resetAgentObserverStore();
  const parse = Date.parse;
  let dateParses = 0;
  Date.parse = (...args) => {
    dateParses++;
    return parse(...args);
  };
  try {
    store.injectObserverEventsForE2E(agent, events);
  } finally {
    Date.parse = parse;
  }
  console.log(
    JSON.stringify({
      trial,
      accepted: store.getAgentObserverSnapshot(agent).events.length,
      dateParses,
    }),
  );
}
store.resetAgentObserverStore();

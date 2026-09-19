import assert from "node:assert/strict";
import test from "node:test";
import { QueryClient, QueryObserver } from "@tanstack/react-query";
import { projectCollectionQueryOptions } from "./projectCollectionQuery.ts";
import { isRelayDependentQuery } from "@/shared/api/relayQueryInvalidation.ts";
import { buildProjectsFromFetcher } from "./projectEnumeration.ts";
import { markProjectDataAuthoritative } from "./projectSnapshot.ts";
const scope = { relayOrigin: "https://relay.example", pubkey: "a".repeat(64) };
function optionsFor(client, fetcher) {
  return projectCollectionQueryOptions(client, async (_, signal) => {
    const projects = await buildProjectsFromFetcher(
      async (...args) => {
        signal.throwIfAborted();
        const rows = await fetcher(...args);
        signal.throwIfAborted();
        return rows;
      },
      { relayOrigin: scope.relayOrigin, viewerPubkey: scope.pubkey },
    );
    return projects.map((project) =>
      markProjectDataAuthoritative(project, "relay"),
    );
  });
}
const repo = {
  id: "1".repeat(64),
  pubkey: scope.pubkey,
  created_at: 1,
  kind: 30617,
  content: "",
  tags: [
    ["d", "app"],
    ["name", "App"],
  ],
};
const client = () =>
  new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity } },
  });

test("warm reentry reuses rows; failed refresh retains them and reconnect invalidates", async () => {
  const queryClient = client();
  let calls = 0;
  let fail = false;
  const options = optionsFor(queryClient, async (kinds) => {
    calls++;
    if (fail) throw Error("relay unavailable");
    return kinds.includes(30617) ? [repo] : [];
  });
  const rows = await queryClient.fetchQuery(options);
  assert.equal(rows.length, 1);
  const cold = calls;
  await queryClient.fetchQuery(options);
  assert.equal(calls, cold);
  await queryClient.invalidateQueries({
    predicate: isRelayDependentQuery,
    refetchType: "none",
  });
  assert.equal(queryClient.getQueryState(options.queryKey).isInvalidated, true);
  fail = true;
  await assert.rejects(queryClient.fetchQuery(options), /relay unavailable/);
  assert.equal(queryClient.getQueryData(options.queryKey), rows);
  // Community and identity switches own a fresh QueryClient upstream.
  assert.equal(client().getQueryData(options.queryKey), undefined);
  queryClient.clear();
});

test("last observer departure cancels unused enumeration before followup queries", async () => {
  const queryClient = client();
  const releases = [];
  let calls = 0;
  const options = optionsFor(queryClient, () => {
    calls++;
    return new Promise((resolve) => releases.push(resolve));
  });
  const observer = new QueryObserver(queryClient, options);
  const unsubscribe = observer.subscribe(() => {});
  await new Promise(setImmediate);
  assert.equal(calls, 2);
  unsubscribe();
  for (const release of releases) release([repo]);
  await new Promise(setImmediate);
  assert.equal(calls, 2);
  assert.equal(queryClient.getQueryData(options.queryKey), undefined);
  queryClient.clear();
});

test("a persistent consumer keeps an enumeration alive after one observer leaves", async () => {
  const queryClient = client();
  const releases = [];
  const options = optionsFor(
    queryClient,
    () => new Promise((resolve) => releases.push(resolve)),
  );
  const first = new QueryObserver(queryClient, options);
  const second = new QueryObserver(queryClient, options);
  const unsub1 = first.subscribe(() => {});
  const unsub2 = second.subscribe(() => {});
  await new Promise(setImmediate);
  unsub1();
  for (const release of releases.splice(0)) release([]);
  await new Promise(setImmediate);
  assert.deepEqual(queryClient.getQueryData(options.queryKey), []);
  unsub2();
  queryClient.clear();
});

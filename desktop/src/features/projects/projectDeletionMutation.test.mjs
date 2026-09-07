import assert from "node:assert/strict";
import test from "node:test";

import {
  MutationObserver,
  QueryClient,
  QueryObserver,
} from "@tanstack/react-query";
import { projectDeletionMutationOptions } from "./projectDeletionMutation.ts";

import { projectCollectionQueryKey } from "./projectCollectionQuery.ts";
const scope = { relayOrigin: "https://relay.example", pubkey: "a".repeat(64) };
const projectsQueryKey = projectCollectionQueryKey(scope);

const project = {
  id: "30621:owner:platform",
  name: "Platform",
};

test("lost deletion acknowledgement refetches and removes the stale project", async () => {
  let fetchCount = 0;
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const queryObserver = new QueryObserver(queryClient, {
    queryKey: projectsQueryKey,
    queryFn: async () => {
      fetchCount += 1;
      return fetchCount === 1 ? [project] : [];
    },
  });
  const unsubscribeQuery = queryObserver.subscribe(() => {});
  await queryObserver.refetch();
  assert.deepEqual(queryClient.getQueryData(projectsQueryKey), [project]);

  const mutationObserver = new MutationObserver(
    queryClient,
    projectDeletionMutationOptions(queryClient, scope, async () => {
      throw new Error(
        "Could not confirm whether the project was deleted. Projects were refreshed.",
      );
    }),
  );
  await assert.rejects(mutationObserver.mutate(project), /Could not confirm/);

  assert.equal(fetchCount, 2);
  assert.deepEqual(queryClient.getQueryData(projectsQueryKey), []);
  unsubscribeQuery();
});

test("successful deletion removes the project before refetch", async () => {
  const queryClient = new QueryClient({
    defaultOptions: { mutations: { retry: false } },
  });
  queryClient.setQueryData(projectsQueryKey, [project]);
  const options = projectDeletionMutationOptions(queryClient, scope);
  // Isolate the real success callback from network publication.
  options.mutationFn = async () => {};
  const mutationObserver = new MutationObserver(queryClient, options);

  await mutationObserver.mutate(project);

  assert.deepEqual(queryClient.getQueryData(projectsQueryKey), []);
});

import assert from "node:assert/strict";
import test from "node:test";
import {
  MutationObserver,
  QueryClient,
  QueryObserver,
} from "@tanstack/react-query";
import { projectCollectionQueryKey } from "./projectCollectionQuery.ts";
import { projectDeletionMutationOptions } from "./projectDeletionMutation.ts";
import { createProjectMutationOptions } from "./useCreateProject.ts";
import { addProjectRepositoryMutationOptions } from "./useAddProjectRepository.ts";
import { attachProjectRepositoryMutationOptions } from "./useAttachProjectRepository.ts";
import { bindProjectRepositoryChannelMutationOptions } from "./useBindProjectRepositoryChannel.ts";

const scope = { relayOrigin: "https://relay.example", pubkey: "A".repeat(64) };
const key = projectCollectionQueryKey(scope);
const project = {
  id: "project",
  owner: "owner",
  dtag: "app",
  repositories: [{ repoAddress: "repo", channelId: "old" }],
};
const updated = { ...project, name: "updated" };
const cases = [
  ["delete", projectDeletionMutationOptions, undefined, []],
  ["create", createProjectMutationOptions, { project: updated }, [updated]],
  [
    "add",
    addProjectRepositoryMutationOptions,
    { previousProjectId: project.id, project: updated },
    [updated],
  ],
  [
    "attach",
    attachProjectRepositoryMutationOptions,
    { previousProjectId: project.id, project: updated },
    [updated],
  ],
  [
    "bind",
    bindProjectRepositoryChannelMutationOptions,
    { repoAddress: "repo", channelId: "new" },
    [{ ...project, repositories: [{ repoAddress: "repo", channelId: "new" }] }],
  ],
];

for (const [name, options, result, expected] of cases) {
  for (const change of ["identity", "relay"]) {
    test(`${name} updates its captured ${change} scope even when refresh fails`, async () => {
      const otherScope =
        change === "identity"
          ? { ...scope, pubkey: "b".repeat(64) }
          : { ...scope, relayOrigin: "https://other.example" };
      const otherKey = projectCollectionQueryKey(otherScope);
      const client = new QueryClient({
        defaultOptions: {
          queries: { retry: false },
          mutations: { retry: false },
        },
      });
      client.setQueryData(key, [project]);
      client.setQueryData(otherKey, [project]);
      client.setQueryData(["projects", "local-repositories"], ["local"]);
      const query = new QueryObserver(client, {
        queryKey: key,
        staleTime: Infinity,
        queryFn: async () => {
          throw new Error("refresh unavailable");
        },
      });
      const unsubscribe = query.subscribe(() => {});
      let finish;
      const pending = new Promise((resolve) => {
        finish = resolve;
      });
      const mutationFn = async () => {
        await pending;
        return result;
      };
      const mutation = new MutationObserver(
        client,
        options(client, scope, mutationFn),
      );
      const write = mutation.mutate(project);
      // Let onMutate capture scope, then model the hook rerendering under a
      // different identity/relay while its previous write is still in flight.
      await new Promise((resolve) => setImmediate(resolve));
      mutation.setOptions(options(client, otherScope, mutationFn));
      finish();
      await write;
      assert.deepEqual(client.getQueryData(key), expected);
      assert.deepEqual(client.getQueryData(otherKey), [project]);
      assert.deepEqual(
        client.getQueryData(["projects", "local-repositories"]),
        ["local"],
      );
      assert.equal(client.getQueryData(["projects"]), undefined);
      assert.match(
        client.getQueryState(key).error.message,
        /refresh unavailable/,
      );
      assert.equal(client.getQueryState(otherKey).isInvalidated, false);
      unsubscribe();
      client.clear();
    });
  }
  test(`${name} keeps its write error and cached rows when refresh also fails`, async () => {
    const client = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    });
    client.setQueryData(key, [project]);
    const query = new QueryObserver(client, {
      queryKey: key,
      staleTime: Infinity,
      queryFn: async () => {
        throw new Error("refresh unavailable");
      },
    });
    const unsubscribe = query.subscribe(() => {});
    const mutation = new MutationObserver(
      client,
      options(client, scope, async () => {
        throw new Error("write acknowledgement uncertain");
      }),
    );
    await assert.rejects(
      mutation.mutate(project),
      /write acknowledgement uncertain/,
    );
    assert.deepEqual(client.getQueryData(key), [project]);
    assert.match(query.getCurrentResult().error.message, /refresh unavailable/);
    unsubscribe();
    client.clear();
  });
}

test("missing scope rejects before invoking a collection write", async () => {
  const client = new QueryClient();
  let writes = 0;
  const mutation = new MutationObserver(
    client,
    projectDeletionMutationOptions(client, null, async () => {
      writes++;
    }),
  );
  await assert.rejects(mutation.mutate(project), /identity is not ready/);
  assert.equal(writes, 0);
  client.clear();
});

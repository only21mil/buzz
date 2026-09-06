import assert from "node:assert/strict";
import test from "node:test";
import {
  MutationObserver,
  QueryClient,
  QueryObserver,
} from "@tanstack/react-query";
import {
  projectCollectionQueryKey,
  projectCollectionQueryOptions,
} from "./projectCollectionQuery.ts";
import {
  isProjectSnapshotRow,
  readProjectSnapshot,
  writeProjectSnapshot,
} from "./projectSnapshot.ts";
import {
  addRelatedChannelToProject,
  addRepositoryToProject,
  buildProjectReadModels,
} from "./projectModels.ts";
import {
  hasAuthoritativeHomeBinding,
  isProjectHomeChannel,
} from "./lib/projectHomeChannel.ts";
import { absorbStandaloneProjectRepositories } from "./lib/projectCollection.ts";
import { bindProjectRepositoryChannelMutationOptions } from "./useBindProjectRepositoryChannel.ts";
import { addProjectRepositoryMutationOptions } from "./useAddProjectRepository.ts";
import { attachProjectRepositoryMutationOptions } from "./useAttachProjectRepository.ts";
import { createProjectMutationOptions } from "./useCreateProject.ts";
import { projectDeletionMutationOptions } from "./projectDeletionMutation.ts";

const owner = "a".repeat(64);
const home = "11111111-1111-4111-8111-111111111111";
const scope = { relayOrigin: "https://relay.example", pubkey: owner };
const event = (kind, dtag, id, tags = []) => ({
  kind,
  tags: [["d", dtag], ["name", dtag], ["buzz-channel", home], ...tags],
  id: id.repeat(64),
  pubkey: owner,
  created_at: 1,
  content: "",
  sig: "0".repeat(128),
});
const events = [
  event(30621, "app", "1", [["a", `30617:${owner}:app`]]),
  event(30617, "app", "2"),
  event(30617, "other", "3"),
];
function seed(targetScope = scope) {
  const map = new Map();
  const storage = {
    getItem: (key) => map.get(key),
    setItem: (key, value) => map.set(key, value),
  };
  writeProjectSnapshot(targetScope, events, storage);
  const rows = readProjectSnapshot(targetScope, storage);
  assert.equal(rows.length, 2);
  return { storage, rows };
}
function assertDisplayOnly(project) {
  assert.equal(isProjectSnapshotRow(project), true);
  assert.equal(hasAuthoritativeHomeBinding(project), false);
  assert.equal(isProjectHomeChannel(home, [project]), false);
}
const mutations = [
  [
    "matching bind",
    bindProjectRepositoryChannelMutationOptions,
    (project) => ({ ...project.repositories[0], name: "bound" }),
  ],
  [
    "unrelated bind",
    bindProjectRepositoryChannelMutationOptions,
    (_project, other) => ({ ...other.repositories[0], name: "bound" }),
  ],
  [
    "add",
    addProjectRepositoryMutationOptions,
    (project, other) => ({
      previousProjectId: project.id,
      project: addRepositoryToProject(project, other.repositories[0], 2),
    }),
  ],
  [
    "attach",
    attachProjectRepositoryMutationOptions,
    (project, other) => ({
      previousProjectId: project.id,
      project: addRepositoryToProject(project, other.repositories[0], 2),
    }),
  ],
  [
    "create unrelated",
    createProjectMutationOptions,
    (_project, other) => ({ project: other }),
  ],
  ["delete unrelated", projectDeletionMutationOptions, () => undefined],
];

for (const [name, options, result] of mutations) {
  for (const change of ["identity", "relay"]) {
    test(`${name} preserves snapshot authority in captured ${change} scope after failed refresh`, async (t) => {
      const otherScope =
        change === "identity"
          ? { ...scope, pubkey: "b".repeat(64) }
          : { ...scope, relayOrigin: "https://other.example" };
      const { storage, rows } = seed();
      const project = rows.find((row) => !row.legacy);
      const other = rows.find((row) => row.legacy);
      assertDisplayOnly(project);
      const key = projectCollectionQueryKey(scope);
      const otherKey = projectCollectionQueryKey(otherScope);
      const client = new QueryClient({
        defaultOptions: {
          queries: { retry: false },
          mutations: { retry: false },
        },
      });
      let live = false;
      const query = new QueryObserver(client, {
        ...projectCollectionQueryOptions(scope, {
          storage,
          fetchExhaustively: async (kinds) => {
            if (!live) throw new Error("refresh unavailable");
            return events.filter((row) => kinds.includes(row.kind));
          },
        }),
        initialData: rows,
        initialDataUpdatedAt: Date.now(),
        staleTime: Infinity,
      });
      const unsubscribe = query.subscribe(() => {});
      t.after(() => {
        unsubscribe();
        client.clear();
      });
      const foreignRows = seed(otherScope).rows;
      client.setQueryData(otherKey, foreignRows);
      let finish;
      const pending = new Promise((resolve) => {
        finish = resolve;
      });
      const mutationFn = async () => {
        await pending;
        return result(project, other);
      };
      const mutation = new MutationObserver(
        client,
        options(client, scope, mutationFn),
      );
      const write = mutation.mutate(
        name === "delete unrelated"
          ? other
          : { project, repository: other.repositories[0], channelId: home },
      );
      await new Promise((resolve) => setImmediate(resolve));
      mutation.setOptions(options(client, otherScope, mutationFn));
      finish();
      await write;
      const next = client.getQueryData(key);
      const nextProject = next.find((row) => row.id === project.id);
      assertDisplayOnly(nextProject);
      if (
        ["unrelated bind", "create unrelated", "delete unrelated"].includes(
          name,
        )
      )
        assert.equal(nextProject, project);
      else assert.notEqual(nextProject, project);
      if (name === "matching bind") {
        assert.equal(nextProject.repositories[0].name, "bound");
        assert.equal(
          next.find((row) => row.id === other.id),
          other,
        );
      }
      if (name === "unrelated bind")
        assert.equal(
          next.find((row) => row.id === other.id).repositories[0].name,
          "bound",
        );
      if (["add", "attach"].includes(name))
        assert.equal(nextProject.repositories.length, 2);
      assert.equal(client.getQueryData(otherKey), foreignRows);
      assert.equal(client.getQueryState(otherKey).isInvalidated, false);
      assert.match(
        client.getQueryState(key).error.message,
        /refresh unavailable/,
      );
      for (const row of next) assertDisplayOnly(row);

      // Only an actual successful collection read replaces snapshot provenance.
      live = true;
      await query.refetch({ throwOnError: true });
      const validated = client.getQueryData(key).find((row) => !row.legacy);
      assert.notEqual(validated, nextProject);
      assert.equal(isProjectSnapshotRow(validated), false);
      assert.equal(hasAuthoritativeHomeBinding(validated), true);
      assert.equal(isProjectHomeChannel(home, [validated]), true);
    });
  }
  test(`${name} leaves snapshot rows untouched when write and refresh fail`, async (t) => {
    const { storage, rows } = seed();
    const client = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    });
    const query = new QueryObserver(client, {
      ...projectCollectionQueryOptions(scope, {
        storage,
        fetchExhaustively: async () => {
          throw new Error("refresh unavailable");
        },
      }),
      initialData: rows,
      initialDataUpdatedAt: Date.now(),
      staleTime: Infinity,
    });
    const unsubscribe = query.subscribe(() => {});
    t.after(() => {
      unsubscribe();
      client.clear();
    });
    const error = new Error("write acknowledgement uncertain");
    const mutation = new MutationObserver(
      client,
      options(client, scope, async () => {
        throw error;
      }),
    );
    await assert.rejects(
      mutation.mutate({ project: rows[0] }),
      (caught) => caught === error,
    );
    assert.equal(client.getQueryData(projectCollectionQueryKey(scope)), rows);
    for (const row of rows) assertDisplayOnly(row);
    assert.match(query.getCurrentResult().error.message, /refresh unavailable/);
  });
}

test("optimistic repository, related-channel and presentation copies preserve snapshot provenance", () => {
  const { rows } = seed();
  const project = rows.find((row) => !row.legacy);
  const repository = rows.find((row) => row.legacy).repositories[0];
  const added = addRepositoryToProject(project, repository, 2);
  const related = addRelatedChannelToProject(
    project,
    "22222222-2222-4222-8222-222222222222",
    2,
  );
  const absorbed = absorbStandaloneProjectRepositories(rows)[0];
  for (const copy of [added, related, absorbed]) {
    assert.notEqual(copy, project);
    assertDisplayOnly(copy);
  }
  assert.equal(added.repositories.length, 2);
  assert.equal(related.relatedChannelIds.length, 1);
  assert.equal(absorbed.repositories.length, 2);
  assert.deepEqual(absorbed.repositoryAddresses, project.repositoryAddresses);
  const [live] = buildProjectReadModels({
    projectEvents: [events[0]],
    repositoryEvents: [events[1]],
    relayOrigin: scope.relayOrigin,
  });
  assert.equal(
    hasAuthoritativeHomeBinding(addRepositoryToProject(live, repository, 2)),
    true,
  );
  assertDisplayOnly(project);
});

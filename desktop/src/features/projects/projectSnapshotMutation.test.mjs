import { projectCollectionQueryKey } from "./projectCollectionQuery.ts";
const scope = { relayOrigin: "https://relay.example", pubkey: "a".repeat(64) };
const projectsQueryKey = projectCollectionQueryKey(scope);
import assert from "node:assert/strict";
import test from "node:test";
import { MutationObserver, QueryClient } from "@tanstack/react-query";
import { projectDeletionMutationOptions } from "./projectDeletionMutation.ts";
import {
  inheritProjectDataProvenance,
  isProjectDataAuthoritative,
  markProjectDataAuthoritative,
  isProjectRelayValidated,
} from "./projectSnapshot.ts";

test("deletion updates only its captured community client and retains display-only rows", async () => {
  const previous = new QueryClient();
  const current = new QueryClient();
  const snapshot = { id: "snapshot" };
  const deleted = { id: "deleted" };
  previous.setQueryData(projectsQueryKey, [snapshot, deleted]);
  current.setQueryData(projectsQueryKey, [deleted]);
  let finish;
  const pending = new Promise((resolve) => {
    finish = resolve;
  });
  const mutation = new MutationObserver(
    previous,
    projectDeletionMutationOptions(previous, scope, () => pending),
  );
  const write = mutation.mutate(deleted);
  await new Promise(setImmediate);
  finish();
  await write;
  assert.deepEqual(previous.getQueryData(projectsQueryKey), [snapshot]);
  assert.equal(
    isProjectDataAuthoritative(previous.getQueryData(projectsQueryKey)[0]),
    false,
  );
  assert.deepEqual(current.getQueryData(projectsQueryKey), [deleted]);
  assert.equal(current.getQueryState(projectsQueryKey).isInvalidated, false);
  previous.clear();
  current.clear();
});

test("optimistic copies preserve upstream provenance without promoting snapshots", () => {
  const snapshot = { id: "snapshot" };
  assert.equal(
    isProjectDataAuthoritative(
      inheritProjectDataProvenance(snapshot, { ...snapshot }),
    ),
    false,
  );
  const relay = markProjectDataAuthoritative({ id: "live" }, "relay");
  assert.equal(
    isProjectRelayValidated(inheritProjectDataProvenance(relay, { ...relay })),
    true,
  );
  const local = markProjectDataAuthoritative({ id: "local" }, "local-write");
  const copy = inheritProjectDataProvenance(local, { ...local });
  assert.equal(isProjectDataAuthoritative(copy), true);
  assert.equal(isProjectRelayValidated(copy), false);
});

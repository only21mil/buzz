import assert from "node:assert/strict";
import test from "node:test";
import {
  cloneFetchErrorMessage,
  gitCloneBrowseMeta,
} from "./git-clone-browse-meta.ts";

test("gitCloneBrowseMeta marks stale clones from ensureClone data", () => {
  const fresh = gitCloneBrowseMeta({ fs: {}, dir: "/a/b" }, null, false);
  assert.equal(fresh.isCloneStale, false);
  assert.equal(fresh.cloneFetchError, null);

  const stale = gitCloneBrowseMeta(
    { fs: {}, dir: "/a/b", stale: true, fetchError: new Error("network") },
    null,
    false,
  );
  assert.equal(stale.isCloneStale, true);
  assert.equal(stale.cloneFetchError?.message, "network");
});

test("gitCloneBrowseMeta keeps hard clone failures separate from stale refresh", () => {
  const failed = gitCloneBrowseMeta(
    undefined,
    new Error("clone failed"),
    false,
  );
  assert.equal(failed.isCloneStale, false);
  assert.equal(failed.cloneError?.message, "clone failed");
});

test("cloneFetchErrorMessage prefers Error and string messages", () => {
  assert.equal(cloneFetchErrorMessage(new Error("offline")), "offline");
  assert.equal(cloneFetchErrorMessage("timeout"), "timeout");
  assert.equal(cloneFetchErrorMessage({}), null);
});

import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { BrowserUnavailableError } from "./capabilityOff.ts";
import {
  assembleRepoSnapshot,
  assertRepositoryWithinSize,
  findReadmePath,
  registerRepoSnapshotCommands,
  repoSnapshotCacheName,
  REPO_SNAPSHOT_FETCH_LIMIT_BYTES,
  REPO_SNAPSHOT_PREVIEW_LIMIT_BYTES,
  selectRepoRef,
  validateRepoCloneUrl,
} from "./repoSnapshot.ts";
import {
  dispatch,
  getUnregisteredCommandMissCount,
  register,
  resetRegistryForTests,
} from "../registry.ts";

const PUBKEY = "a".repeat(64);
const OWNER = "b".repeat(64);
const CLONE_URL = `https://relay.example/git/${OWNER}/buzz.git`;

afterEach(() => resetRegistryForTests());

test("snapshot assembly sorts and caps files while preserving honest shallow history", async () => {
  const exactPreview = new Uint8Array(REPO_SNAPSHOT_PREVIEW_LIMIT_BYTES).fill(
    97,
  );
  const tooLarge = new Uint8Array(REPO_SNAPSHOT_PREVIEW_LIMIT_BYTES + 1).fill(
    98,
  );
  const commit = {
    hash: "c".repeat(40),
    short_hash: "c".repeat(7),
    author_name: "Sats",
    author_email: "sats@example.com",
    timestamp: 1_700_000_000,
    subject: "Tip only",
  };
  const blobs = new Map([
    ["README.md", new TextEncoder().encode("# Buzz\n")],
    ["exact.txt", exactPreview],
    ["large.txt", tooLarge],
    ["binary.dat", Uint8Array.from([1, 0, 2])],
  ]);
  const snapshot = await assembleRepoSnapshot(
    {
      async readCommit() {
        return commit;
      },
      async listFiles() {
        return [
          { path: "large.txt", kind: "blob", oid: "4" },
          { path: "submodule", kind: "commit", oid: "5" },
          { path: "README.md", kind: "blob", oid: "1" },
          { path: "exact.txt", kind: "blob", oid: "2" },
          { path: "binary.dat", kind: "blob", oid: "3" },
        ];
      },
      async readBlob(_oid, path) {
        return blobs.get(path);
      },
    },
    commit.hash,
  );

  assert.equal(snapshot.latest_commit, commit);
  assert.equal(snapshot.commit_count, null);
  assert.deepEqual(snapshot.commits, [commit]);
  assert.deepEqual(
    snapshot.files.map((file) => file.path),
    ["README.md", "binary.dat", "exact.txt", "large.txt", "submodule"],
  );
  assert.equal(snapshot.files[0].preview_content, "# Buzz\n");
  assert.equal(snapshot.files[1].preview_content, null);
  assert.equal(snapshot.files[2].preview_content?.length, exactPreview.length);
  assert.equal(snapshot.files[3].preview_content, null);
  assert.equal(snapshot.files[4].kind, "commit");
  assert.equal(snapshot.files[4].size, null);
  assert.deepEqual(snapshot.contributors, [
    {
      name: "Sats",
      email: "sats@example.com",
      commit_count: 1,
      last_commit_at: 1_700_000_000,
    },
  ]);
});

test("README detection follows root-only web client priority case-insensitively", () => {
  const files = [
    { path: "README.txt", kind: "blob", oid: "1" },
    { path: "docs/README.md", kind: "blob", oid: "2" },
    { path: "ReadMe.MD", kind: "blob", oid: "3" },
  ];
  assert.equal(findReadmePath(files), "ReadMe.MD");
  assert.equal(
    findReadmePath([{ path: "docs/README.md", kind: "blob", oid: "2" }]),
    null,
  );
});

test("ref selection mirrors target-ref, target-commit, then branch precedence", () => {
  const commit = "D".repeat(40);
  assert.deepEqual(
    selectRepoRef({
      defaultBranch: "main",
      baseBranch: "main",
      targetRef: "refs/nostr/pr-1",
      targetCommit: commit,
    }),
    { ref: "refs/nostr/pr-1", expectedCommit: commit.toLowerCase() },
  );
  assert.deepEqual(selectRepoRef({ targetCommit: commit }), {
    ref: commit.toLowerCase(),
    expectedCommit: commit.toLowerCase(),
  });
  assert.deepEqual(selectRepoRef({ defaultBranch: "refs/heads/feature/x" }), {
    ref: "feature/x",
    expectedCommit: null,
  });
  assert.deepEqual(selectRepoRef({ defaultBranch: "../bad" }), {
    ref: "HEAD",
    expectedCommit: null,
  });
});

test("cache names are scoped by signer pubkey", () => {
  const first = repoSnapshotCacheName(PUBKEY, OWNER, "buzz");
  const second = repoSnapshotCacheName("c".repeat(64), OWNER, "buzz");
  assert.notEqual(first, second);
  assert.match(first, new RegExp(`^buzz-git-1-${PUBKEY}-${OWNER}-buzz$`));
});

test("size guard rejects with the browser-unavailable repository message", () => {
  assert.doesNotThrow(() =>
    assertRepositoryWithinSize(REPO_SNAPSHOT_FETCH_LIMIT_BYTES),
  );
  assert.throws(
    () => assertRepositoryWithinSize(REPO_SNAPSHOT_FETCH_LIMIT_BYTES + 1),
    (error) =>
      error instanceof BrowserUnavailableError &&
      /Repository is too large to browse in the web app yet/.test(
        error.message,
      ) &&
      /use the desktop app/.test(error.message),
  );
});

test("clone URL validation accepts only credential-free HTTPS on the relay origin", () => {
  assert.deepEqual(validateRepoCloneUrl(CLONE_URL, "https://relay.example"), {
    url: CLONE_URL,
    owner: OWNER,
    repo: "buzz",
  });
  assert.throws(() => validateRepoCloneUrl(CLONE_URL, "https://other.example"));
  assert.throws(() =>
    validateRepoCloneUrl(
      `https://user:secret@relay.example/git/${OWNER}/buzz.git`,
      "https://relay.example",
    ),
  );
  assert.throws(() =>
    validateRepoCloneUrl(
      `http://relay.example/git/${OWNER}/buzz.git`,
      "http://relay.example",
    ),
  );
});

test("registrar installs a real snapshot command without an unregistered miss", async () => {
  register("get_relay_http_url", () => "https://relay.example");
  const emptySnapshot = {
    latest_commit: null,
    commit_count: null,
    commits: [],
    files: [],
    contributors: [],
  };
  let loaded = false;
  const identity = {
    pubkey: () => PUBKEY,
    repoSnapshotScope: () => `0:${PUBKEY}`,
    sign: (request) =>
      JSON.stringify({
        ...request,
        id: "d".repeat(64),
        pubkey: PUBKEY,
        created_at: 1,
        sig: "e".repeat(128),
      }),
  };
  registerRepoSnapshotCommands(identity, {
    async loadSnapshot(input) {
      loaded = true;
      assert.equal(input.selectedRef.ref, "main");
      assert.equal(input.authorization.startsWith("Nostr "), true);
      return emptySnapshot;
    },
  });

  assert.deepEqual(
    await dispatch("get_project_repo_snapshot", {
      cloneUrl: CLONE_URL,
      defaultBranch: "main",
      baseBranch: "main",
      targetRef: null,
      targetCommit: null,
    }),
    emptySnapshot,
  );
  assert.equal(loaded, true);
  assert.equal(getUnregisteredCommandMissCount(), 0);
});

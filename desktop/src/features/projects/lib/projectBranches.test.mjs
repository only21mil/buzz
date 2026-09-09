import assert from "node:assert/strict";
import { test } from "node:test";

import {
  normalizeProjectBranchName,
  projectBranchCreationReason,
  projectBranchManagementState,
  projectBranchNameError,
  projectBranchOptions,
  resolveProjectDefaultBranch,
} from "./projectBranches.ts";

test("normalizes plain and full branch refs", () => {
  assert.equal(normalizeProjectBranchName(" feature/demo "), "feature/demo");
  assert.equal(normalizeProjectBranchName("refs/heads/release-1"), "release-1");
});

test("rejects unsafe and invalid branch names", () => {
  for (const value of [
    "--upload-pack=/tmp/evil",
    "feature/../main",
    "feature//demo",
    "feature/.hidden",
    "feature/demo.lock",
    "refs/tags/v1",
    "bad name",
  ]) {
    assert.equal(normalizeProjectBranchName(value), null, value);
  }
});

test("reports duplicate branch names", () => {
  assert.equal(
    projectBranchNameError("feature/demo", ["main", "feature/demo"]),
    "A branch with this name already exists.",
  );
  assert.equal(projectBranchNameError("feature/new", ["main"]), null);
});

test("combines remote and local branch options without duplicates", () => {
  assert.deepEqual(
    projectBranchOptions(
      ["main", "feature/remote"],
      ["feature/local", "space"],
    ),
    ["main", "feature/remote", "feature/local", "space"],
  );
  assert.deepEqual(projectBranchOptions(["main"], ["main"]), ["main"]);
});

test("explains why a branch cannot be created", () => {
  assert.equal(
    projectBranchCreationReason({
      activeBranch: "main",
      activeBranchCommit: null,
      localHead: "a".repeat(40),
    }),
    "Push the first local commit to main before creating another branch.",
  );
  assert.equal(
    projectBranchCreationReason({
      activeBranch: "main",
      activeBranchCommit: "a".repeat(40),
    }),
    null,
  );
});

test("ignores a dangling HEAD and selects a published branch", () => {
  assert.equal(
    resolveProjectDefaultBranch("master", {
      branches: [{ name: "main" }],
      head: "master",
    }),
    "main",
  );
  assert.equal(
    resolveProjectDefaultBranch("release", {
      branches: [{ name: "release" }, { name: "main" }],
      head: "missing",
    }),
    "release",
  );
});

test("preserves HEAD for empty repositories", () => {
  assert.equal(
    resolveProjectDefaultBranch("main", { branches: [], head: "master" }),
    "master",
  );
});

test("derives branch commits and deletion safeguards", () => {
  const branches = [
    { name: "main", commit: "a".repeat(40) },
    { name: "feature/demo", commit: "b".repeat(40) },
  ];
  assert.deepEqual(
    projectBranchManagementState({
      activeBranch: "feature/demo",
      branches,
      defaultBranch: "main",
      hasOpenPullRequest: false,
    }),
    {
      activeBranchCommit: "b".repeat(40),
      activeRemoteBranch: branches[1],
      deleteBranchReason: null,
    },
  );
  assert.equal(
    projectBranchManagementState({
      activeBranch: "main",
      branches,
      defaultBranch: "main",
      hasOpenPullRequest: false,
    }).deleteBranchReason,
    "The repository's default branch cannot be deleted.",
  );
});

test("branch labels distinguish remote-only, local-only and checked-out refs", async () => {
  const { projectBranchLocationLabel } = await import("./projectBranches.ts");
  const remote = ["main", "feature/remote"];
  const local = ["main", "feature/local"];
  const checkouts = [
    { branch: "main" },
    { branch: "feature/local" },
    { branch: null },
  ];
  assert.equal(
    projectBranchLocationLabel("feature/remote", remote, local, checkouts),
    "Remote",
  );
  assert.equal(
    projectBranchLocationLabel("feature/local", remote, local, checkouts),
    "Local · Checked out",
  );
  assert.equal(
    projectBranchLocationLabel("main", remote, local, checkouts),
    "Remote · Local · Checked out",
  );
});

test("branch options omit tag and tracking refs and retain discovered worktree branches", async () => {
  const { projectBranchOptionsFromSync } = await import("./projectBranches.ts");
  assert.deepEqual(
    projectBranchOptionsFromSync(
      ["main", "refs/tags/v1", "refs/remotes/origin/main"],
      {
        localBranch: "main",
        localHead: "a".repeat(40),
        localBranches: ["main"],
        localCheckouts: [{ branch: "feature/worktree" }, { branch: null }],
      },
    ),
    ["main", "feature/worktree"],
  );
});

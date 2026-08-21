import assert from "node:assert/strict";
import test from "node:test";
import { parseRepoWorkItems, repoWorkItemFilters } from "./repo-work-items.mjs";

const owner = "ab".repeat(32);
const issueAuthor = "cd".repeat(32);
const pullRequestAuthor = "de".repeat(32);
const attacker = "ef".repeat(32);
const repoAddress = `30617:${owner}:browser-repo`;

function event({ id, kind, pubkey, createdAt, content = "", tags = [] }) {
  return {
    id,
    kind,
    pubkey,
    created_at: createdAt,
    content,
    tags,
    sig: "00".repeat(64),
  };
}

test("builds the desktop-compatible repository a-tag query set", () => {
  assert.deepEqual(repoWorkItemFilters(repoAddress), {
    issues: { kinds: [1621], "#a": [repoAddress], limit: 200 },
    pullRequests: { kinds: [1618], "#a": [repoAddress], limit: 200 },
    pullRequestUpdates: {
      kinds: [1619],
      "#a": [repoAddress],
      limit: 500,
    },
    comments: { kinds: [1], "#a": [repoAddress], limit: 500 },
    statuses: {
      kinds: [1630, 1631, 1632, 1633],
      "#a": [repoAddress],
      limit: 500,
    },
  });
});

test("parses current issue and pull-request state using trusted updates", () => {
  const issueId = "11".repeat(32);
  const pullRequestId = "22".repeat(32);
  const issue = event({
    id: issueId,
    kind: 1621,
    pubkey: issueAuthor,
    createdAt: 100,
    content: "The issue body",
    tags: [
      ["a", repoAddress],
      ["subject", "Fix browser issue"],
      ["t", "web"],
    ],
  });
  const pullRequest = event({
    id: pullRequestId,
    kind: 1618,
    pubkey: pullRequestAuthor,
    createdAt: 110,
    content: "The pull request body",
    tags: [
      ["a", repoAddress],
      ["subject", "Ship browser fix"],
      ["branch-name", "fix/browser"],
      ["target-branch", "main"],
      ["c", "aa".repeat(20)],
    ],
  });

  const result = parseRepoWorkItems({
    issueEvents: [issue],
    pullRequestEvents: [pullRequest],
    updateEvents: [
      event({
        id: "33".repeat(32),
        kind: 1619,
        pubkey: owner,
        createdAt: 220,
        tags: [
          ["a", repoAddress],
          ["E", pullRequestId],
          ["c", "bb".repeat(20)],
        ],
      }),
      event({
        id: "44".repeat(32),
        kind: 1619,
        pubkey: attacker,
        createdAt: 400,
        tags: [
          ["a", repoAddress],
          ["E", pullRequestId],
          ["c", "ff".repeat(20)],
        ],
      }),
    ],
    commentEvents: [
      event({
        id: "55".repeat(32),
        kind: 1,
        pubkey: owner,
        createdAt: 180,
        content: "Issue comment",
        tags: [
          ["a", repoAddress],
          ["e", issueId],
        ],
      }),
      event({
        id: "66".repeat(32),
        kind: 1,
        pubkey: owner,
        createdAt: 230,
        content: "PR comment",
        tags: [
          ["a", repoAddress],
          ["e", pullRequestId],
        ],
      }),
    ],
    statusEvents: [
      event({
        id: "77".repeat(32),
        kind: 1631,
        pubkey: owner,
        createdAt: 200,
        tags: [
          ["a", repoAddress],
          ["e", issueId],
        ],
      }),
      event({
        id: "88".repeat(32),
        kind: 1632,
        pubkey: attacker,
        createdAt: 500,
        tags: [
          ["a", repoAddress],
          ["e", issueId],
        ],
      }),
      event({
        id: "99".repeat(32),
        kind: 1633,
        pubkey: pullRequestAuthor,
        createdAt: 240,
        tags: [
          ["a", repoAddress],
          ["e", pullRequestId],
        ],
      }),
    ],
  });

  assert.equal(result.issues[0].title, "Fix browser issue");
  assert.equal(result.issues[0].status, "Done");
  assert.equal(result.issues[0].comments[0].content, "Issue comment");

  assert.equal(result.pullRequests[0].title, "Ship browser fix");
  assert.equal(result.pullRequests[0].status, "Draft");
  assert.equal(result.pullRequests[0].commit, "bb".repeat(20));
  assert.equal(result.pullRequests[0].updateCount, 1);
  assert.equal(result.pullRequests[0].comments[0].content, "PR comment");
});

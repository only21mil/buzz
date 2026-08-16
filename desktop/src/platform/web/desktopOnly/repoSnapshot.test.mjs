import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { finalizeEvent } from "nostr-tools/pure";

import { BrowserUnavailableError } from "./capabilityOff.ts";
import { registerRepoSnapshotCommands } from "./repoSnapshot.ts";
import {
  dispatch,
  getUnregisteredCommandMissCount,
  register,
  resetRegistryForTests,
} from "../registry.ts";

const SECRET = Uint8Array.from({ length: 32 }, (_, index) =>
  index === 31 ? 1 : 0,
);
const OWNER = "a".repeat(64);
const RELAY_HTTP = "https://relay.example.test";

function identity() {
  return {
    sign(request) {
      return JSON.stringify(
        finalizeEvent(
          {
            kind: request.kind,
            content: request.content,
            tags: request.tags,
            created_at: 100,
          },
          SECRET,
        ),
      );
    },
  };
}

function registerCommands({
  relay = RELAY_HTTP,
  signer = identity(),
  timeoutMs,
} = {}) {
  register("get_relay_http_url", () => relay);
  registerRepoSnapshotCommands(signer, { timeoutMs });
}

function commit(hash = "f".repeat(64)) {
  return {
    hash,
    short_hash: hash.slice(0, 7),
    author_name: "Sats",
    author_email: "sats@example.test",
    timestamp: 123,
    subject: "Snapshot",
  };
}

function snapshot(overrides = {}) {
  return {
    latest_commit: null,
    files: [],
    ...overrides,
  };
}

function successfulResponse(body = snapshot()) {
  return {
    ok: true,
    status: 200,
    async json() {
      return body;
    },
  };
}

function decodeAuthorization(value) {
  assert.match(value, /^Nostr /);
  return JSON.parse(Buffer.from(value.slice("Nostr ".length), "base64"));
}

afterEach(() => {
  resetRegistryForTests();
});

test("repository snapshot signs the exact URL and applies desktop ref precedence", async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  const expectedCommit = "f".repeat(64);
  globalThis.fetch = async (url, init) => {
    requests.push({ url, init });
    return successfulResponse(
      snapshot({ latest_commit: commit(expectedCommit.toUpperCase()) }),
    );
  };
  registerCommands();

  try {
    const base = {
      cloneUrl: `${RELAY_HTTP}/git/${OWNER}/buzz.git`,
      defaultBranch: "main",
      baseBranch: "release",
      targetRef: "refs/heads/topic",
      targetCommit: expectedCommit,
    };
    await dispatch("get_project_repo_snapshot", base);
    await dispatch("get_project_repo_snapshot", {
      ...base,
      targetRef: null,
    });
    await dispatch("get_project_repo_snapshot", {
      ...base,
      targetRef: null,
      targetCommit: null,
    });
    await dispatch("get_project_repo_snapshot", {
      cloneUrl: base.cloneUrl,
      baseBranch: "release",
    });

    assert.deepEqual(
      requests.map(({ url }) => url),
      [
        `${RELAY_HTTP}/git/${OWNER}/buzz/snapshot?ref=refs%2Fheads%2Ftopic&commits=20`,
        `${RELAY_HTTP}/git/${OWNER}/buzz/snapshot?ref=${expectedCommit}&commits=20`,
        `${RELAY_HTTP}/git/${OWNER}/buzz/snapshot?ref=main&commits=20`,
        `${RELAY_HTTP}/git/${OWNER}/buzz/snapshot?commits=20`,
      ],
    );
    for (const { url, init } of requests) {
      assert.equal(init.method, "GET");
      const event = decodeAuthorization(
        new Headers(init.headers).get("Authorization"),
      );
      assert.deepEqual(
        event.tags.find(([name]) => name === "u"),
        ["u", url],
      );
      assert.deepEqual(
        event.tags.find(([name]) => name === "method"),
        ["method", "GET"],
      );
    }
    assert.equal(getUnregisteredCommandMissCount(), 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("repository snapshot rejects a changed target commit", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    successfulResponse(snapshot({ latest_commit: commit("e".repeat(64)) }));
  registerCommands();

  try {
    await assert.rejects(
      dispatch("get_project_repo_snapshot", {
        cloneUrl: `${RELAY_HTTP}/git/${OWNER}/buzz`,
        targetRef: "refs/heads/topic",
        targetCommit: "f".repeat(64),
      }),
      /the requested repository ref changed/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("repository snapshot returns a valid response object as-is", async () => {
  const originalFetch = globalThis.fetch;
  const body = snapshot({
    latest_commit: commit(),
    commits: [commit()],
    files: [{ path: "README.md", kind: "blob" }],
    contributors: [
      {
        name: "Sats",
        email: "sats@example.test",
        commit_count: 1,
        last_commit_at: 123,
      },
    ],
  });
  globalThis.fetch = async () => successfulResponse(body);
  registerCommands();

  try {
    const result = await dispatch("get_project_repo_snapshot", {
      cloneUrl: `${RELAY_HTTP}/git/${OWNER}/buzz`,
    });
    assert.strictEqual(result, body);
    assert.equal(getUnregisteredCommandMissCount(), 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("repository snapshot distinguishes JSON-marker and bare 404 responses", async () => {
  const originalFetch = globalThis.fetch;
  let marked = true;
  globalThis.fetch = async () => ({
    ok: false,
    status: 404,
    async json() {
      if (!marked) throw new SyntaxError("empty body");
      return {
        error: "repository_unavailable",
        message: "repository not found",
      };
    },
  });
  registerCommands();

  try {
    const request = {
      cloneUrl: `${RELAY_HTTP}/git/${OWNER}/buzz`,
    };
    await assert.rejects(
      dispatch("get_project_repo_snapshot", request),
      /repository not found/,
    );
    marked = false;
    await assert.rejects(
      dispatch("get_project_repo_snapshot", request),
      (error) => {
        assert.ok(error instanceof BrowserUnavailableError);
        assert.equal(error.capability, "get_project_repo_snapshot");
        return true;
      },
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("repository snapshot keeps 405 and 501 browser-unavailable", async () => {
  const originalFetch = globalThis.fetch;
  let status = 405;
  globalThis.fetch = async () => ({ ok: false, status });
  registerCommands();

  try {
    const request = { cloneUrl: `${RELAY_HTTP}/git/${OWNER}/buzz` };
    await assert.rejects(
      dispatch("get_project_repo_snapshot", request),
      BrowserUnavailableError,
    );
    status = 501;
    await assert.rejects(
      dispatch("get_project_repo_snapshot", request),
      BrowserUnavailableError,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("repository snapshot maps signing failures separately from fetch failures", async () => {
  const originalFetch = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = async () => {
    fetched = true;
    return successfulResponse();
  };
  registerCommands({
    signer: {
      sign() {
        throw new Error("wallet locked");
      },
    },
  });

  try {
    await assert.rejects(
      dispatch("get_project_repo_snapshot", {
        cloneUrl: `${RELAY_HTTP}/git/${OWNER}/buzz`,
      }),
      (error) => {
        assert.equal(
          error.message,
          "snapshot request could not be signed: wallet locked",
        );
        assert.doesNotMatch(error.message, /connect|timed out/);
        return true;
      },
    );
    assert.equal(fetched, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("repository snapshot maps network failures to connection errors", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new TypeError("offline");
  };
  registerCommands();

  try {
    await assert.rejects(
      dispatch("get_project_repo_snapshot", {
        cloneUrl: `${RELAY_HTTP}/git/${OWNER}/buzz`,
      }),
      /snapshot request failed to connect: offline/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("repository snapshot aborts a pending fetch after the real timeout", async () => {
  const originalFetch = globalThis.fetch;
  let sawAbort = false;
  globalThis.fetch = (_url, init) =>
    new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => {
        sawAbort = true;
        reject(new DOMException("aborted", "AbortError"));
      });
    });
  registerCommands({ timeoutMs: 5 });

  try {
    await assert.rejects(
      dispatch("get_project_repo_snapshot", {
        cloneUrl: `${RELAY_HTTP}/git/${OWNER}/buzz`,
      }),
      /snapshot request timed out/,
    );
    assert.equal(sawAbort, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("repository snapshot maps authorization and relay capacity failures", async () => {
  const originalFetch = globalThis.fetch;
  let status = 403;
  globalThis.fetch = async () => ({ ok: false, status });
  registerCommands();

  try {
    const request = { cloneUrl: `${RELAY_HTTP}/git/${OWNER}/buzz` };
    await assert.rejects(
      dispatch("get_project_repo_snapshot", request),
      /authentication failed \(HTTP 403\)/,
    );
    status = 429;
    await assert.rejects(
      dispatch("get_project_repo_snapshot", request),
      /relay is busy generating the snapshot; timed out/,
    );
    status = 504;
    await assert.rejects(
      dispatch("get_project_repo_snapshot", request),
      /relay timed out generating the snapshot/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("repository snapshot validates mapper-dereferenced response fields", async () => {
  const originalFetch = globalThis.fetch;
  let body;
  globalThis.fetch = async () => successfulResponse(body);
  registerCommands();
  const request = { cloneUrl: `${RELAY_HTTP}/git/${OWNER}/buzz` };
  const invalidBodies = [
    { files: [] },
    snapshot({ latest_commit: { hash: "f" } }),
    snapshot({ files: [{ path: "README.md" }] }),
    snapshot({ commits: [{ ...commit(), timestamp: "123" }] }),
    snapshot({
      contributors: [
        {
          name: "Sats",
          email: "sats@example.test",
          commit_count: "1",
          last_commit_at: 123,
        },
      ],
    }),
  ];

  try {
    for (const invalidBody of invalidBodies) {
      body = invalidBody;
      await assert.rejects(
        dispatch("get_project_repo_snapshot", request),
        /snapshot response has an unexpected shape/,
      );
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("repository snapshot accepts HTTP clones only for an HTTP relay origin", async () => {
  const originalFetch = globalThis.fetch;
  const relay = "http://relay.example.test";
  let fetched = false;
  globalThis.fetch = async () => {
    fetched = true;
    return successfulResponse();
  };
  registerCommands({ relay });

  try {
    await dispatch("get_project_repo_snapshot", {
      cloneUrl: `${relay}/git/${OWNER}/buzz`,
    });
    assert.equal(fetched, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("repository snapshot rejects HTTP clones for an HTTPS relay before fetch", async () => {
  const originalFetch = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = async () => {
    fetched = true;
    return successfulResponse();
  };
  registerCommands();

  try {
    await assert.rejects(
      dispatch("get_project_repo_snapshot", {
        cloneUrl: `http://relay.example.test/git/${OWNER}/buzz`,
      }),
      /active relay uses HTTP/,
    );
    assert.equal(fetched, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("repository snapshot rejects cross-origin clone URLs before fetch", async () => {
  const originalFetch = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = async () => {
    fetched = true;
    return successfulResponse();
  };
  registerCommands();

  try {
    await assert.rejects(
      dispatch("get_project_repo_snapshot", {
        cloneUrl: `https://other.example.test/git/${OWNER}/buzz`,
      }),
      /active relay origin/,
    );
    assert.equal(fetched, false);
    assert.equal(getUnregisteredCommandMissCount(), 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

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

function registerCommands() {
  register("get_relay_http_url", () => RELAY_HTTP);
  registerRepoSnapshotCommands(identity());
}

function successfulResponse(body = { files: [] }) {
  return {
    ok: true,
    status: 200,
    async json() {
      return body;
    },
  };
}

afterEach(() => {
  resetRegistryForTests();
});

test("repository snapshot signs the exact relay URL and applies ref precedence", async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (url, init) => {
    requests.push({ url, init });
    return successfulResponse();
  };
  registerCommands();

  try {
    const base = {
      cloneUrl: `${RELAY_HTTP}/git/${OWNER}/buzz.git`,
      defaultBranch: "main",
      baseBranch: "release",
      targetRef: "refs/heads/topic",
      targetCommit: "f".repeat(64),
    };
    await dispatch("get_project_repo_snapshot", base);
    await dispatch("get_project_repo_snapshot", {
      ...base,
      targetCommit: null,
    });
    await dispatch("get_project_repo_snapshot", {
      ...base,
      targetCommit: null,
      targetRef: null,
    });
    await dispatch("get_project_repo_snapshot", {
      ...base,
      targetCommit: null,
      targetRef: null,
      baseBranch: null,
    });
    await dispatch("get_project_repo_snapshot", {
      cloneUrl: base.cloneUrl,
    });

    assert.deepEqual(
      requests.map(({ url }) => url),
      [
        `${RELAY_HTTP}/git/${OWNER}/buzz/snapshot?ref=${"f".repeat(64)}&commits=20`,
        `${RELAY_HTTP}/git/${OWNER}/buzz/snapshot?ref=refs%2Fheads%2Ftopic&commits=20`,
        `${RELAY_HTTP}/git/${OWNER}/buzz/snapshot?ref=release&commits=20`,
        `${RELAY_HTTP}/git/${OWNER}/buzz/snapshot?ref=main&commits=20`,
        `${RELAY_HTTP}/git/${OWNER}/buzz/snapshot?commits=20`,
      ],
    );
    for (const { init } of requests) {
      assert.equal(init.method, "GET");
      assert.match(new Headers(init.headers).get("Authorization"), /^Nostr /);
    }
    assert.equal(getUnregisteredCommandMissCount(), 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("repository snapshot returns a valid 200 response as-is", async () => {
  const originalFetch = globalThis.fetch;
  const body = {
    latest_commit: null,
    files: [{ path: "README.md", preview_content: "hello" }],
    extra_server_field: { retained: true },
  };
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

test("repository snapshot maps unsupported relay responses to browser unavailable", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: false, status: 404 });
  registerCommands();

  try {
    await assert.rejects(
      dispatch("get_project_repo_snapshot", {
        cloneUrl: `${RELAY_HTTP}/git/${OWNER}/buzz`,
      }),
      (error) => {
        assert.ok(error instanceof BrowserUnavailableError);
        assert.equal(error.capability, "get_project_repo_snapshot");
        assert.match(error.message, /relay's snapshot endpoint/);
        return true;
      },
    );
    assert.equal(getUnregisteredCommandMissCount(), 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("repository snapshot maps authorization failures", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: false, status: 403 });
  registerCommands();

  try {
    await assert.rejects(
      dispatch("get_project_repo_snapshot", {
        cloneUrl: `${RELAY_HTTP}/git/${OWNER}/buzz`,
      }),
      /authentication failed \(HTTP 403\)/,
    );
    assert.equal(getUnregisteredCommandMissCount(), 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("repository snapshot maps aborts to timeouts", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new DOMException("aborted", "AbortError");
  };
  registerCommands();

  try {
    await assert.rejects(
      dispatch("get_project_repo_snapshot", {
        cloneUrl: `${RELAY_HTTP}/git/${OWNER}/buzz`,
      }),
      /timed out/,
    );
    assert.equal(getUnregisteredCommandMissCount(), 0);
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

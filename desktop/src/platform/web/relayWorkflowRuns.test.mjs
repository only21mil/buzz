import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { finalizeEvent, verifyEvent } from "nostr-tools/pure";
import { parseWorkflowRunsPage } from "@/shared/api/tauriWorkflows";
import { registerRelayWorkflowsMembersCommands } from "./desktopOnly/relayWorkflowsMembers.ts";
import { registerRelaySocialConfigCommands } from "./desktopOnly/relaySocialConfig.ts";
import { dispatch, register, resetRegistryForTests } from "./registry.ts";

const workflowId = "00112233-4455-6677-8899-aabbccddeeff";
const runId = "ffeeddcc-bbaa-9988-7766-554433221100";
const before = "2026-09-06T10:00:00.123456+00:00";
const originalFetch = globalThis.fetch;
const key = Uint8Array.from({ length: 32 }, (_, index) =>
  index === 31 ? 1 : 0,
);
const run = {
  id: runId,
  workflow_id: workflowId,
  status: "completed",
  current_step: 1,
  execution_trace: [
    { step_id: "greet", status: "completed", output: { message: "hello" } },
  ],
  started_at: 100,
  completed_at: 110,
  error_message: null,
  created_at: 99,
};

function install(reply = [run], status = 200) {
  const requests = [];
  let origin = "https://relay.example.test";
  registerRelayWorkflowsMembersCommands({}, {});
  // This module used to overwrite the workflow registration with a [] stub.
  registerRelaySocialConfigCommands({});
  register("get_relay_http_url", () => origin);
  register("sign_event", (template) =>
    JSON.stringify(finalizeEvent({ ...template, created_at: 100 }, key)),
  );
  globalThis.fetch = async (url, init) => {
    requests.push({ url, init });
    const authorization = init.headers.get("Authorization");
    assert.ok(authorization.startsWith("Nostr "));
    const event = JSON.parse(atob(authorization.slice(6)));
    assert.ok(verifyEvent(event));
    assert.equal(event.kind, 27235);
    assert.ok(event.tags.some((tag) => tag[0] === "u" && tag[1] === url));
    assert.ok(
      event.tags.some((tag) => tag[0] === "method" && tag[1] === "GET"),
    );
    assert.equal(init.method, "GET");
    assert.equal(init.body, undefined);
    return new Response(JSON.stringify(reply), { status });
  };
  return {
    requests,
    setOrigin(value) {
      origin = value;
    },
  };
}

afterEach(() => {
  globalThis.fetch = originalFetch;
  resetRegistryForTests();
});

test("workflow history fetches authenticated native array and feeds the shared UI parser", async () => {
  const { requests } = install();
  const result = await dispatch("get_workflow_runs", {
    workflowId,
    limit: null,
  });
  assert.deepEqual(result, [run]);
  assert.equal(
    requests[0].url,
    `https://relay.example.test/workflows/${workflowId}/runs?limit=20`,
  );
  const parsed = parseWorkflowRunsPage(result);
  assert.equal(parsed.runs[0].workflowId, workflowId);
  assert.equal(parsed.runs[0].executionTrace[0].output.message, "hello");
  assert.equal(parsed.next, null);
});

test("workflow pages preserve cursor precision, cap limits, and resolve the current relay per read", async () => {
  const page = { runs: [run], next: { before, before_id: runId } };
  const { requests, setOrigin } = install(page);
  const result = await dispatch("get_workflow_runs", {
    workflowId,
    limit: 101,
    page: true,
    before,
    beforeId: runId,
  });
  assert.deepEqual(parseWorkflowRunsPage(result).next, page.next);
  const url = new URL(requests[0].url);
  assert.equal(url.pathname, `/workflows/${workflowId}/runs`);
  assert.deepEqual(Object.fromEntries(url.searchParams), {
    limit: "100",
    page: "true",
    before,
    before_id: runId,
  });
  setOrigin("https://second.example.test/");
  await dispatch("get_workflow_runs", {
    workflowId: workflowId.toUpperCase(),
    limit: 0,
  });
  assert.equal(
    requests[1].url,
    `https://second.example.test/workflows/${workflowId}/runs?limit=0`,
  );
});

test("invalid workflow history arguments fail before requesting or signing", async () => {
  const { requests } = install();
  const cases = [
    [undefined, /object body/],
    [{}, /UUID/],
    [{ workflowId: "../other" }, /UUID/],
    ...[-1, 1.5, "20", 4294967296].map((limit) => [
      { workflowId, limit },
      /unsigned/,
    ]),
    [{ workflowId, page: "true" }, /boolean/],
    [{ workflowId, before }, /supplied together/],
    [{ workflowId, beforeId: runId }, /supplied together/],
    [{ workflowId, before: "yesterday", beforeId: runId }, /timestamp/],
    [
      { workflowId, before: "2026-02-30T00:00:00Z", beforeId: runId },
      /timestamp/,
    ],
    [{ workflowId, before, beforeId: "../run" }, /run ID/],
  ];
  register("sign_event", () => {
    throw new Error("must not sign invalid request");
  });
  for (const [body, message] of cases) {
    await assert.rejects(dispatch("get_workflow_runs", body), message);
  }
  assert.deepEqual(requests, []);
});

test("workflow relay failures and malformed JSON remain errors, while actual empty history stays empty", async () => {
  install([], 403);
  await assert.rejects(dispatch("get_workflow_runs", { workflowId }), /403/);
  globalThis.fetch = async () => {
    throw new Error("offline");
  };
  await assert.rejects(
    dispatch("get_workflow_runs", { workflowId }),
    /offline/,
  );
  globalThis.fetch = async () => new Response("{");
  await assert.rejects(
    dispatch("get_workflow_runs", { workflowId }),
    SyntaxError,
  );
  globalThis.fetch = async () => new Response("[]");
  assert.deepEqual(await dispatch("get_workflow_runs", { workflowId }), []);
});

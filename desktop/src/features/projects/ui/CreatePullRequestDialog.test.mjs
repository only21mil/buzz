import assert from "node:assert/strict";
import { after, test } from "node:test";
import { JSDOM } from "jsdom";

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "https://buzz.example",
});
for (const key of [
  "window",
  "document",
  "navigator",
  "HTMLElement",
  "HTMLInputElement",
  "Element",
  "Node",
  "NodeFilter",
  "MutationObserver",
  "Event",
  "CustomEvent",
  "getComputedStyle",
]) {
  Object.defineProperty(globalThis, key, {
    configurable: true,
    value:
      key === "window"
        ? dom.window
        : key === "getComputedStyle"
          ? dom.window.getComputedStyle.bind(dom.window)
          : dom.window[key],
  });
}
globalThis.IS_REACT_ACT_ENVIRONMENT = true;
dom.window.matchMedia = () => ({
  matches: false,
  addEventListener() {},
  removeEventListener() {},
});
after(() => dom.window.close());
const { createElement: h } = await import("react");
const { render, fireEvent, cleanup, act } = await import(
  "@testing-library/react"
);
const { QueryClient, QueryClientProvider: BaseQueryClientProvider } =
  await import("@tanstack/react-query");
const { ThemeProvider } = await import("@/shared/theme/ThemeProvider");
const { CreatePullRequestDialog } = await import(
  "./CreatePullRequestDialog.tsx"
);
const { beginRelayOriginFetch } = await import("@/shared/lib/mediaUrl");
beginRelayOriginFetch()("https://relay.example");

function QueryClientProvider({ client, children }) {
  return h(
    BaseQueryClientProvider,
    { client },
    h(
      ThemeProvider,
      { defaultTheme: "houston", storageKey: "checkout-test-theme" },
      children,
    ),
  );
}

function fixture() {
  const repositories = ["first", "selected"].map((id) => ({
    id,
    dtag: id,
    name: id,
    defaultBranch: "main",
    cloneUrls: [`https://relay.example/git/owner/${id}.git`],
    repoAddress: `30617:${"a".repeat(64)}:${id}`,
    owner: "a".repeat(64),
    contributors: [],
  }));
  const project = {
    id: "project",
    name: "Project",
    repositories,
    repositoryAddresses: repositories.map((repo) => repo.repoAddress),
    primaryRepositoryAddress: repositories[0].repoAddress,
  };
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: Infinity },
      mutations: { gcTime: 0 },
    },
  });
  for (const repo of repositories) {
    client.setQueryData(["project", repo.id, "repo-state"], {
      branches: ["main", "feature/first", "feature/selected"].map((name) => ({
        name,
        commit: "a".repeat(40),
      })),
    });
    client.setQueryData(["project", repo.id, "pull-requests"], []);
  }
  return { client, project };
}

test("Create PR preselects selected repository and branch, retaining edits after refresh", async () => {
  const { client, project } = fixture();
  const props = {
    initialProjectId: project.id,
    initialRepositoryId: "selected",
    initialSourceBranch: "feature/selected",
    projects: [project],
    open: true,
    onOpenChange() {},
    onCreated() {},
  };
  const element = (value) =>
    h(QueryClientProvider, { client }, h(CreatePullRequestDialog, value));
  try {
    const view = render(element(props));
    assert.equal(
      view.getByTestId("create-pull-request-repository").value,
      "selected",
    );
    assert.equal(
      view.getByTestId("create-pull-request-base-branch").value,
      "main",
    );
    assert.equal(
      view.getByTestId("create-pull-request-compare-branch").value,
      "feature/selected",
    );
    fireEvent.change(view.getByTestId("create-pull-request-compare-branch"), {
      target: { value: "feature/first" },
    });
    view.rerender(element({ ...props, projects: [structuredClone(project)] }));
    await act(async () => {
      client.setQueryData(["project", "selected", "repo-state"], {
        branches: ["main", "feature/selected", "feature/first"].map((name) => ({
          name,
          commit: "b".repeat(40),
        })),
      });
    });
    assert.equal(
      view.getByTestId("create-pull-request-compare-branch").value,
      "feature/first",
    );
    fireEvent.change(view.getByTestId("create-pull-request-repository"), {
      target: { value: "first" },
    });
    assert.equal(
      view.getByTestId("create-pull-request-compare-branch").value,
      "feature/first",
    );
  } finally {
    cleanup();
    client.clear();
  }
});

test("selected default branch remains explicit and same-branch comparison is blocked", () => {
  const { client, project } = fixture();
  try {
    const view = render(
      h(
        QueryClientProvider,
        { client },
        h(CreatePullRequestDialog, {
          initialProjectId: project.id,
          initialRepositoryId: "selected",
          initialSourceBranch: "main",
          projects: [project],
          open: true,
          onOpenChange() {},
          onCreated() {},
        }),
      ),
    );
    assert.equal(
      view.getByTestId("create-pull-request-compare-branch").value,
      "main",
    );
    assert.ok(
      view.getByText("The base and compare branches must be different."),
    );
    assert.equal(view.getByTestId("create-pull-request-submit").disabled, true);
  } finally {
    cleanup();
    client.clear();
  }
});

test("remote-only selected branch stays selected before repository state arrives", () => {
  const { client, project } = fixture();
  client.setQueryData(["project", "selected", "repo-state"], { branches: [] });
  try {
    const view = render(
      h(
        QueryClientProvider,
        { client },
        h(CreatePullRequestDialog, {
          initialProjectId: project.id,
          initialRepositoryId: "selected",
          initialSourceBranch: "feature/remote",
          projects: [project],
          open: true,
          onOpenChange() {},
          onCreated() {},
        }),
      ),
    );
    assert.equal(
      view.getByTestId("create-pull-request-compare-branch").value,
      "feature/remote",
    );
  } finally {
    cleanup();
    client.clear();
  }
});

test("clone and terminal hooks send selected branch and offer a copyable mismatch command", async () => {
  const { renderHook } = await import("@testing-library/react");
  const { mockIPC, clearMocks } = await import("@tauri-apps/api/mocks");
  const { toast } = await import("sonner");
  const { useCloneProjectRepositoryMutation } = await import(
    "../repoSyncHooks.ts"
  );
  const { useOpenProjectTerminal } = await import(
    "./useOpenProjectTerminal.ts"
  );
  const { client, project } = fixture();
  const repo = project.repositories[1];
  const calls = [];
  const command = "git -C '/repo' worktree add '../repo-feature-a' 'feature/a'";
  mockIPC((name, input) => {
    // Media URL initialization may finish after the project modules load.
    if (name === "get_media_proxy_port") return null;
    calls.push({ name, input });
    if (name === "clone_project_repository")
      return { path: "/repo", cloned: true, message: "Cloned" };
    if (name === "open_project_terminal")
      return {
        path: "/repo",
        cloned: false,
        mismatch:
          "Selected branch feature/a has no local checkout. /repo is on main.",
        worktree_command: command,
      };
    throw new Error(`Unexpected native command: ${name}`);
  });
  let copied;
  Object.defineProperty(dom.window.navigator, "clipboard", {
    configurable: true,
    value: {
      async writeText(value) {
        copied = value;
      },
    },
  });
  try {
    const wrapper = ({ children }) =>
      h(BaseQueryClientProvider, { client }, children);
    const clone = renderHook(
      () => useCloneProjectRepositoryMutation(repo, "/repos", "feature/a"),
      { wrapper },
    );
    await act(async () => clone.result.current.mutateAsync());
    const terminal = renderHook(() => useOpenProjectTerminal("/repos"), {
      wrapper,
    });
    await act(async () =>
      terminal.result.current(repo, {
        branch: "feature/a",
        hasLocalCheckout: true,
      }),
    );
    assert.deepEqual(
      calls.map(({ name, input }) => [name, input.defaultBranch]),
      [
        ["clone_project_repository", "feature/a"],
        ["open_project_terminal", "feature/a"],
      ],
    );
    const message = toast
      .getHistory()
      .findLast((entry) => entry.title === "Selected branch needs a worktree");
    assert.match(message.description, /is on main/);
    assert.equal(message.action.label, "Copy command");
    await act(async () => message.action.onClick());
    assert.equal(copied, command);
  } finally {
    cleanup();
    client.clear();
    clearMocks();
    toast.dismiss();
  }
});

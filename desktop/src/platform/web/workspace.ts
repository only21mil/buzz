import type { BrowserIdentityManager } from "./identity";
import { register, type InvokeBody } from "./registry";

function objectBody(body: InvokeBody): Record<string, unknown> {
  if (
    !body ||
    Array.isArray(body) ||
    body instanceof ArrayBuffer ||
    body instanceof Uint8Array
  ) {
    throw new TypeError("Command requires an object body");
  }
  return body;
}

function defaultRelayUrl(): string {
  if (typeof window === "undefined") return "ws://localhost:3000";
  const url = new URL(window.location.href);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = "/";
  url.search = "";
  url.hash = "";
  return url.toString().replace(/\/$/, "");
}

function relayHttpUrl(relayUrl: string): string {
  const url = new URL(relayUrl);
  if (url.protocol !== "ws:" && url.protocol !== "wss:") {
    throw new Error("Relay URL must use ws:// or wss://");
  }
  url.protocol = url.protocol === "wss:" ? "https:" : "http:";
  return url.toString().replace(/\/$/, "");
}

export class BrowserWorkspace {
  private relayUrl = defaultRelayUrl();

  apply(body: InvokeBody): void {
    const record = objectBody(body);
    if (typeof record.relayUrl !== "string") {
      throw new TypeError("relayUrl must be a string");
    }
    const reposDir = record.reposDir;
    if (typeof reposDir === "string" && reposDir.trim()) {
      throw new Error(
        "Browser workspaces do not support a local repositories directory",
      );
    }
    // Parse and validate before publishing the new active context.
    relayHttpUrl(record.relayUrl);
    this.relayUrl = record.relayUrl.trim().replace(/\/$/, "");
  }

  wsUrl(): string {
    return this.relayUrl;
  }

  httpUrl(): string {
    return relayHttpUrl(this.relayUrl);
  }
}

export function registerWorkspaceCommands(
  workspace: BrowserWorkspace,
  identity: BrowserIdentityManager,
): void {
  register("get_default_relay_url", () => defaultRelayUrl());
  register("auto_connect_default_relay_enabled", () => false);
  register("get_relay_ws_url", () => workspace.wsUrl());
  register("get_relay_http_url", () => workspace.httpUrl());
  register("apply_workspace", (body) => workspace.apply(body));
  register("get_active_workspace", () => ({
    relay_url: workspace.wsUrl(),
    pubkey: identity.pubkey(),
  }));
  register("get_legacy_workspace_storage", () => ({
    workspaces: null,
    activeWorkspaceId: null,
    onboardingCompletions: [],
  }));
  register("take_pending_community_deep_link", () => null);
  register("acknowledge_pending_community_deep_link", () => false);
}

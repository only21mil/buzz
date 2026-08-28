import type { BrowserIdentityManager } from "./identity";
import {
  normalizeBrowserRelayUrl,
  relayHttpUrlFromBrowserRelay,
} from "./originPolicy";
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

function defaultRelayUrl(pageUrl?: string | URL): string {
  if (!pageUrl && typeof window === "undefined") return "ws://localhost:3000";
  const url = new URL(pageUrl ?? window.location.href);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = "/";
  url.search = "";
  url.hash = "";
  return url.toString().replace(/\/$/, "");
}

export class BrowserWorkspace {
  private readonly pageUrl?: URL;
  private relayUrl: string;

  constructor(pageUrl?: string | URL) {
    this.pageUrl = pageUrl ? new URL(pageUrl) : undefined;
    this.relayUrl = defaultRelayUrl(this.pageUrl);
  }

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
    // Parse and validate before publishing the new active context. The hosted
    // renderer has no cross-community browser capability, so fail closed on
    // cross-origin, credential-bearing, or path-scoped relay URLs.
    this.relayUrl = normalizeBrowserRelayUrl(
      record.relayUrl.trim(),
      this.pageUrl,
    );
  }

  wsUrl(): string {
    return this.relayUrl;
  }

  httpUrl(): string {
    return relayHttpUrlFromBrowserRelay(this.relayUrl);
  }
}

export function registerWorkspaceCommands(
  workspace: BrowserWorkspace,
  identity: BrowserIdentityManager,
): void {
  register("get_default_relay_url", () => workspace.wsUrl());
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

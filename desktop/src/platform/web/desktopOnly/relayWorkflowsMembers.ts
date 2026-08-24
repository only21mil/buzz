import { relayClient } from "@/shared/api/relayClient";
import { withReadOnlyRelayClient } from "@/shared/api/readOnlyRelayClient";
import { relayMembersFromEvent } from "@/shared/api/relayMembers";
import type { RelayEvent } from "@/shared/api/types";
import { npubEncode } from "nostr-tools/nip19";
import { parse as parseYaml } from "yaml";

import type { BrowserIdentityManager } from "../identity";
import { register } from "../registry";
import { BrowserUnavailableError } from "./capabilityOff";

type RelayFilter = {
  kinds: number[];
  limit?: number;
  authors?: string[];
} & Partial<Record<`#${string}`, string[]>>;

type RelayWorkflowsMembersClient = {
  fetchEvents(filter: RelayFilter): Promise<RelayEvent[]>;
  fetchFirstEvent(filter: RelayFilter): Promise<RelayEvent | null>;
  publishEvent(
    event: RelayEvent,
    timeoutMessage: string,
    sendErrorMessage: string,
  ): Promise<unknown>;
  fetchEventsAt?(relayUrl: string, filter: RelayFilter): Promise<RelayEvent[]>;
  publishEventAt?(relayUrl: string, event: RelayEvent): Promise<unknown>;
};

type ObjectBody = Record<string, unknown>;

type SubmitResponse = {
  event_id: string;
  accepted: boolean;
  message: string;
};

type WorkflowWire = {
  id: string;
  name: string;
  owner_pubkey: string;
  channel_id: string | null;
  definition: Record<string, unknown>;
  status: "active";
  created_at: number;
  updated_at: number;
};

type TargetRelaySession = {
  fetchFirstEvent(
    filter: RelayFilter & { limit: number },
  ): Promise<RelayEvent | null>;
  publishEvent(event: RelayEvent): Promise<unknown>;
};

const WORKFLOW_KIND = 30620;
const MAX_WORKFLOW_CONTENT_BYTES = 64 * 1024;
const VALID_RELAY_ROLES = new Set(["owner", "admin", "member"]);
const VALID_RESPOND_TO = new Set(["owner-only", "allowlist", "anyone"]);

function objectBody(body: unknown, command: string): ObjectBody {
  if (
    !body ||
    Array.isArray(body) ||
    body instanceof ArrayBuffer ||
    body instanceof Uint8Array
  ) {
    throw new TypeError(`${command} requires an object body`);
  }
  return body as ObjectBody;
}

function requiredString(body: ObjectBody, field: string): string {
  const value = body[field];
  if (typeof value !== "string") {
    throw new TypeError(`${field} must be a string`);
  }
  return value;
}

function nullableString(body: ObjectBody, field: string): string | null {
  const value = body[field];
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw new TypeError(`${field} must be a string or null`);
  }
  return value;
}

function requiredStringArray(body: ObjectBody, field: string): string[] {
  const value = body[field];
  if (
    !Array.isArray(value) ||
    !value.every((item) => typeof item === "string")
  ) {
    throw new TypeError(`${field} must be an array of strings`);
  }
  return value;
}

function validatePubkey(pubkey: string): string {
  if (!/^[0-9a-fA-F]{64}$/.test(pubkey)) {
    throw new Error(
      `pubkey must be a 64-character hex string (got ${pubkey.length} chars)`,
    );
  }
  return pubkey.toLowerCase();
}

function validateRelayRole(role: string): string {
  if (!VALID_RELAY_ROLES.has(role)) {
    throw new Error(
      `invalid relay role "${role}" (expected one of: owner, admin, member)`,
    );
  }
  return role;
}

function validateWorkflowContent(yamlDefinition: string): string {
  const byteLength = new TextEncoder().encode(yamlDefinition).byteLength;
  if (byteLength > MAX_WORKFLOW_CONTENT_BYTES) {
    throw new Error(
      `content exceeds maximum size of ${MAX_WORKFLOW_CONTENT_BYTES} bytes (got ${byteLength})`,
    );
  }
  return yamlDefinition;
}

function parseSignedEvent(value: string): RelayEvent {
  const event = JSON.parse(value) as RelayEvent;
  if (
    !event ||
    typeof event.id !== "string" ||
    typeof event.pubkey !== "string" ||
    typeof event.sig !== "string"
  ) {
    throw new Error("Browser identity returned an invalid signed event");
  }
  return event;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function submitResponse(event: RelayEvent, result: unknown): SubmitResponse {
  const record = asRecord(result);
  return {
    event_id: typeof record?.event_id === "string" ? record.event_id : event.id,
    accepted: typeof record?.accepted === "boolean" ? record.accepted : true,
    message: typeof record?.message === "string" ? record.message : "",
  };
}

async function publishSignedEvent(
  identity: BrowserIdentityManager,
  client: RelayWorkflowsMembersClient,
  request: {
    kind: number;
    content: string;
    tags: string[][];
    createdAt?: number;
  },
  operation: string,
): Promise<{ event: RelayEvent; response: SubmitResponse }> {
  const event = parseSignedEvent(identity.sign(request));
  const result = await client.publishEvent(
    event,
    `Timed out while ${operation}.`,
    `Failed while ${operation}.`,
  );
  return { event, response: submitResponse(event, result) };
}

function tagValue(event: RelayEvent, name: string): string | null {
  return event.tags.find((tag) => tag[0] === name)?.[1] ?? null;
}

function parseDefinition(yamlDefinition: string): Record<string, unknown> {
  try {
    return asRecord(parseYaml(yamlDefinition)) ?? {};
  } catch {
    return {};
  }
}

function workflowRecord(
  id: string,
  channelId: string | null,
  ownerPubkey: string,
  yamlDefinition: string,
  createdAt: number,
  updatedAt: number,
): WorkflowWire {
  const definition = parseDefinition(yamlDefinition);
  const rawName = definition.name;
  const name =
    typeof rawName === "string" && rawName.trim() !== "" ? rawName : id;
  return {
    id,
    name,
    owner_pubkey: ownerPubkey,
    channel_id: channelId,
    definition,
    status: "active",
    created_at: createdAt,
    updated_at: updatedAt,
  };
}

function workflowFromEvent(event: RelayEvent): WorkflowWire {
  const timestamp = event.created_at;
  return workflowRecord(
    tagValue(event, "d") ?? "",
    tagValue(event, "h"),
    event.pubkey,
    event.content,
    timestamp,
    timestamp,
  );
}

function isWebhookTriggered(yamlDefinition: string): boolean {
  const trigger = asRecord(parseDefinition(yamlDefinition).trigger);
  return trigger?.on === "webhook" || trigger?.type === "webhook";
}

function stringArray(
  record: Record<string, unknown>,
  field: string,
  fallback: string[] = [],
): string[] {
  const value = record[field];
  if (value === undefined) return fallback;
  if (
    !Array.isArray(value) ||
    !value.every((item) => typeof item === "string")
  ) {
    throw new Error(`agent parse failed: ${field} must be an array of strings`);
  }
  return value;
}

function relayAgentFromEvent(event: RelayEvent) {
  let parsed: unknown;
  try {
    parsed = JSON.parse(event.content);
  } catch {
    parsed = {};
  }
  const record = asRecord(parsed) ?? {};
  const displayName = record.display_name;
  const fallbackName =
    typeof displayName === "string" && displayName.trim() !== ""
      ? displayName
      : npubEncode(event.pubkey);
  const respondTo = record.respond_to;
  if (
    respondTo !== undefined &&
    (typeof respondTo !== "string" || !VALID_RESPOND_TO.has(respondTo))
  ) {
    throw new Error("agent parse failed: invalid respond_to");
  }
  return {
    pubkey: event.pubkey,
    name: typeof record.name === "string" ? record.name : fallbackName,
    agent_type:
      typeof record.agent_type === "string" ? record.agent_type : "agent",
    channels: stringArray(record, "channels"),
    channel_ids: stringArray(record, "channel_ids"),
    capabilities: stringArray(record, "capabilities"),
    status: typeof record.status === "string" ? record.status : "offline",
    respond_to: typeof respondTo === "string" ? respondTo : null,
    respond_to_allowlist: stringArray(record, "respond_to_allowlist"),
  };
}

function profileFromEvent(event: RelayEvent) {
  const content = JSON.parse(event.content) as unknown;
  const record = asRecord(content);
  if (!record) throw new Error("kind:0 content is not valid JSON object");
  const stringValue = (field: string): string | null =>
    typeof record[field] === "string" ? (record[field] as string) : null;
  return {
    pubkey: event.pubkey,
    display_name: stringValue("display_name") ?? stringValue("name"),
    avatar_url: stringValue("picture"),
    about: stringValue("about"),
    nip05_handle: stringValue("nip05"),
    owner_pubkey: null,
    has_profile_event: true,
  };
}

function emptyProfile(pubkey: string) {
  return {
    pubkey,
    display_name: null,
    avatar_url: null,
    about: null,
    nip05_handle: null,
    owner_pubkey: null,
    has_profile_event: false,
  };
}

function normalizedAvatarUrl(value: string | null): string | null {
  const trimmed = value?.trim();
  return trimmed ? trimmed : null;
}

async function withTargetRelay<T>(
  client: RelayWorkflowsMembersClient,
  relayUrl: string,
  callback: (session: TargetRelaySession) => Promise<T>,
): Promise<T> {
  if (client.fetchEventsAt && client.publishEventAt) {
    return callback({
      fetchFirstEvent: async (filter) =>
        (await client.fetchEventsAt?.(relayUrl, filter))?.[0] ?? null,
      publishEvent: (event) =>
        (
          client.publishEventAt as NonNullable<
            RelayWorkflowsMembersClient["publishEventAt"]
          >
        )(relayUrl, event),
    });
  }

  return withReadOnlyRelayClient(relayUrl, (targetClient) =>
    callback({
      fetchFirstEvent: async (filter) =>
        (await targetClient.fetchEvents(filter))[0] ?? null,
      publishEvent: async (event) => {
        await targetClient.publishEvent(event);
        return event;
      },
    }),
  );
}

async function publishRelayAdminEvent(
  body: unknown,
  identity: BrowserIdentityManager,
  client: RelayWorkflowsMembersClient,
  command: string,
  kind: number,
  roleField?: string,
) {
  const input = objectBody(body, command);
  const targetPubkey = validatePubkey(requiredString(input, "targetPubkey"));
  const tags = [["p", targetPubkey]];
  if (roleField) {
    tags.push(["role", validateRelayRole(requiredString(input, roleField))]);
  }
  const { response } = await publishSignedEvent(
    identity,
    client,
    { kind, content: "", tags },
    "updating relay access",
  );
  return response;
}

async function listRelayMembers(client: RelayWorkflowsMembersClient) {
  const event = await client.fetchFirstEvent({
    kinds: [13534],
    limit: 1,
  });
  return {
    members: event
      ? relayMembersFromEvent(event).map((member) => ({
          pubkey: member.pubkey,
          role: member.role,
          added_by: member.addedBy,
          created_at: member.createdAt,
        }))
      : [],
  };
}

async function createWorkflow(
  body: unknown,
  identity: BrowserIdentityManager,
  client: RelayWorkflowsMembersClient,
) {
  const input = objectBody(body, "create_workflow");
  const channelId = requiredString(input, "channelId");
  const yamlDefinition = validateWorkflowContent(
    requiredString(input, "yamlDefinition"),
  );
  // The relay hands back the one-time webhook secret only in the OK message,
  // which the browser relayClient.publishEvent seam discards. Creating a
  // webhook workflow here would look successful and silently lose the secret,
  // so fail closed until that seam exists.
  if (isWebhookTriggered(yamlDefinition)) {
    throw new BrowserUnavailableError(
      "create_workflow",
      "create webhook workflows from the desktop app (the browser cannot receive the one-time webhook secret)",
    );
  }
  const workflowId = crypto.randomUUID();
  await publishSignedEvent(
    identity,
    client,
    {
      kind: WORKFLOW_KIND,
      content: yamlDefinition,
      tags: [
        ["d", workflowId],
        ["h", channelId],
      ],
    },
    "creating the workflow",
  );
  const now = Math.floor(Date.now() / 1000);
  const workflow = workflowRecord(
    workflowId,
    channelId,
    identity.pubkey(),
    yamlDefinition,
    now,
    now,
  );
  return workflow;
}

async function updateWorkflow(
  body: unknown,
  identity: BrowserIdentityManager,
  client: RelayWorkflowsMembersClient,
) {
  const input = objectBody(body, "update_workflow");
  const workflowId = requiredString(input, "workflowId");
  const yamlDefinition = validateWorkflowContent(
    requiredString(input, "yamlDefinition"),
  );
  const prior = await client.fetchFirstEvent({
    kinds: [WORKFLOW_KIND],
    "#d": [workflowId],
    limit: 1,
  });
  const channelId = prior ? tagValue(prior, "h") : null;
  if (!prior || !channelId) throw new Error("workflow not found");
  await publishSignedEvent(
    identity,
    client,
    {
      kind: WORKFLOW_KIND,
      content: yamlDefinition,
      tags: [
        ["d", workflowId],
        ["h", channelId],
      ],
    },
    "updating the workflow",
  );
  return workflowRecord(
    workflowId,
    channelId,
    identity.pubkey(),
    yamlDefinition,
    prior.created_at,
    Math.floor(Date.now() / 1000),
  );
}

async function updateProfileAtRelay(
  body: unknown,
  identity: BrowserIdentityManager,
  client: RelayWorkflowsMembersClient,
) {
  const input = objectBody(body, "update_profile_at_relay");
  const relayUrl = requiredString(input, "relayUrl");
  const expectedPubkey = requiredString(input, "expectedPubkey");
  const expectedAvatarUrl = nullableString(input, "expectedAvatarUrl");
  const avatarUrl = requiredString(input, "avatarUrl");
  if (identity.pubkey() !== expectedPubkey) {
    throw new Error("profile identity changed before avatar save");
  }
  const filter: RelayFilter & { limit: number } = {
    kinds: [0],
    authors: [expectedPubkey],
    limit: 1,
  };

  return withTargetRelay(client, relayUrl, async (session) => {
    const prior = await session.fetchFirstEvent(filter);
    let current: Record<string, unknown> = {};
    if (prior) {
      try {
        current = asRecord(JSON.parse(prior.content)) ?? {};
      } catch {
        current = {};
      }
    }
    const currentAvatarUrl =
      typeof current.picture === "string" ? current.picture : null;
    if (
      normalizedAvatarUrl(currentAvatarUrl) !==
      normalizedAvatarUrl(expectedAvatarUrl)
    ) {
      throw new Error("profile avatar changed before deferred save");
    }

    const nextContent: Record<string, string> = {};
    for (const field of ["display_name", "name", "about", "nip05"] as const) {
      const value = current[field];
      if (typeof value === "string") nextContent[field] = value;
    }
    nextContent.picture = avatarUrl;
    const createdAt = Math.max(
      Math.floor(Date.now() / 1000),
      (prior?.created_at ?? -1) + 1,
    );
    if (identity.pubkey() !== expectedPubkey) {
      throw new Error("profile identity changed before avatar save");
    }
    const event = parseSignedEvent(
      identity.sign({
        kind: 0,
        content: JSON.stringify(nextContent),
        tags: [],
        createdAt,
      }),
    );
    if (event.pubkey !== expectedPubkey) {
      throw new Error("profile identity changed before avatar save");
    }
    await session.publishEvent(event);
    const updated = await session.fetchFirstEvent(filter);
    return updated ? profileFromEvent(updated) : emptyProfile(expectedPubkey);
  });
}

export function registerRelayWorkflowsMembersCommands(
  identity: BrowserIdentityManager,
  client: RelayWorkflowsMembersClient = relayClient as RelayWorkflowsMembersClient,
): void {
  register("add_relay_member", (body) =>
    publishRelayAdminEvent(
      body,
      identity,
      client,
      "add_relay_member",
      9030,
      "role",
    ),
  );
  register("change_relay_member_role", (body) =>
    publishRelayAdminEvent(
      body,
      identity,
      client,
      "change_relay_member_role",
      9032,
      "newRole",
    ),
  );
  register("create_workflow", (body) => createWorkflow(body, identity, client));
  register("delete_workflow", async (body) => {
    const workflowId = requiredString(
      objectBody(body, "delete_workflow"),
      "workflowId",
    );
    await publishSignedEvent(
      identity,
      client,
      {
        kind: 5,
        content: "",
        tags: [["a", `30620:${identity.pubkey()}:${workflowId}`]],
      },
      "deleting the workflow",
    );
  });
  register("get_channel_workflows", (body) => {
    const channelId = requiredString(
      objectBody(body, "get_channel_workflows"),
      "channelId",
    );
    return client
      .fetchEvents({
        kinds: [WORKFLOW_KIND],
        "#h": [channelId],
      })
      .then((events) => events.map(workflowFromEvent));
  });
  register("get_channels_workflows", (body) => {
    const channelIds = requiredStringArray(
      objectBody(body, "get_channels_workflows"),
      "channelIds",
    );
    if (channelIds.length === 0) return [];
    return client
      .fetchEvents({
        kinds: [WORKFLOW_KIND],
        "#h": channelIds,
      })
      .then((events) => events.map(workflowFromEvent));
  });
  register("get_workflow", async (body) => {
    const workflowId = requiredString(
      objectBody(body, "get_workflow"),
      "workflowId",
    );
    const event = await client.fetchFirstEvent({
      kinds: [WORKFLOW_KIND],
      "#d": [workflowId],
      limit: 1,
    });
    if (!event) throw new Error("workflow not found");
    return workflowFromEvent(event);
  });
  register("list_relay_agents", async () =>
    (
      await client.fetchEvents({
        kinds: [10100],
      })
    ).map(relayAgentFromEvent),
  );
  register("list_relay_members", () => listRelayMembers(client));
  register("remove_relay_member", (body) =>
    publishRelayAdminEvent(body, identity, client, "remove_relay_member", 9031),
  );
  register("trigger_workflow", async (body) => {
    const workflowId = requiredString(
      objectBody(body, "trigger_workflow"),
      "workflowId",
    );
    const { response } = await publishSignedEvent(
      identity,
      client,
      { kind: 46020, content: "", tags: [["d", workflowId]] },
      "triggering the workflow",
    );
    return {
      event_id: response.event_id,
      workflow_id: workflowId,
      run_id: null,
      status: "accepted",
    };
  });
  register("update_profile_at_relay", (body) =>
    updateProfileAtRelay(body, identity, client),
  );
  register("update_workflow", (body) => updateWorkflow(body, identity, client));
}

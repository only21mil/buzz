import { z } from "zod";
import { nip98Fetch } from "./nip98";
import { dispatch } from "./registry";

function uuid(value: unknown, message: string): string {
  if (typeof value !== "string") throw new TypeError(message);
  const hex = value.replace(/^urn:uuid:/, "").replace(/^\{(.+)\}$/, "$1");
  if (
    !/^(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$/i.test(hex)
  ) {
    throw new TypeError(message);
  }
  const raw = hex.replaceAll("-", "").toLowerCase();
  return `${raw.slice(0, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}-${raw.slice(16, 20)}-${raw.slice(20)}`;
}

/** Read the relay's authoritative workflow history using the native wire contract. */
export async function getWorkflowRuns(body: unknown): Promise<unknown> {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new TypeError("get_workflow_runs requires an object body");
  }
  const input = body as Record<string, unknown>;
  const workflowId = uuid(input.workflowId, "workflow ID must be a UUID");
  const limit = input.limit ?? 20;
  if (
    typeof limit !== "number" ||
    !Number.isInteger(limit) ||
    limit < 0 ||
    limit > 0xffff_ffff
  ) {
    throw new TypeError("limit must be an unsigned 32-bit integer");
  }
  const page = input.page ?? false;
  if (typeof page !== "boolean") throw new TypeError("page must be a boolean");
  const before = input.before ?? null;
  const beforeId = input.beforeId ?? null;
  if ((before === null) !== (beforeId === null)) {
    throw new TypeError("before and before_id must be supplied together");
  }
  const query = new URLSearchParams({ limit: String(Math.min(limit, 100)) });
  if (page) query.set("page", "true");
  if (before !== null) {
    if (!z.iso.datetime({ offset: true }).safeParse(before).success) {
      throw new TypeError("invalid history timestamp");
    }
    uuid(beforeId, "invalid history run ID");
    query.set("before", before as string);
    query.set("before_id", beforeId as string);
  }
  const relayHttpUrl = await dispatch<string>("get_relay_http_url");
  const response = await nip98Fetch({
    url: `${relayHttpUrl.replace(/\/$/, "")}/workflows/${workflowId}/runs?${query}`,
    method: "GET",
  });
  if (!response.ok) {
    throw new Error(`Workflow history request failed (${response.status}).`);
  }
  return response.json();
}

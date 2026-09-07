import type { AgentPersona } from "./types";

/** Editable content and stable identity shown during an owner draft review. */
export type PersonaReviewContent = Pick<
  AgentPersona,
  | "id"
  | "displayName"
  | "avatarUrl"
  | "systemPrompt"
  | "runtime"
  | "model"
  | "provider"
  | "namePool"
  | "envVars"
  | "respondTo"
  | "respondToAllowlist"
  | "parallelism"
>;

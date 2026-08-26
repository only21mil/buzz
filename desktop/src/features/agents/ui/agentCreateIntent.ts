/**
 * What the user is creating from the unified create dialog.
 *
 * - `definition` — a keyless agent definition (persona record) only.
 * - `definition_stopped` — definition plus a managed identity that stays
 *   stopped and does not auto-start with the app.
 * - `definition_start` — definition plus an immediately created + spawned
 *   managed instance linked via `personaId` (today's quick-start flow).
 */
export type AgentCreateIntent =
  | "definition"
  | "definition_stopped"
  | "definition_start";

export type AgentReviewCreateAction = "create-stopped" | "start-now";

/** Maps the owner-review dialog actions without changing other create callers. */
export function resolveAgentReviewCreateIntent(
  action: AgentReviewCreateAction,
): AgentCreateIntent {
  return action === "start-now" ? "definition_start" : "definition_stopped";
}

/**
 * Default intent for callers that don't pass one. Un-migrated callers of
 * `usePersonaActions.handleSubmit` (AgentDefinitionDialog's duplicate path
 * until B3) must keep today's create-then-start semantics, so the default is
 * `definition_start`, never `definition`.
 */
export function resolveCreateIntent(
  intent?: AgentCreateIntent,
): AgentCreateIntent {
  return intent ?? "definition_start";
}

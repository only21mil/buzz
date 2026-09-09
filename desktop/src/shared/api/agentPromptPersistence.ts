import type {
  AgentPersona,
  ManagedAgent,
  UpdateManagedAgentInput,
  UpdatePersonaInput,
} from "./types";

const PROMPT_SAVE_ERROR =
  "System prompt was not saved. Your edit is still open; try again.";

export function assertManagedAgentPromptPersisted(
  input: UpdateManagedAgentInput,
  saved: Pick<ManagedAgent, "systemPrompt">,
): void {
  if (
    input.systemPrompt !== undefined &&
    saved.systemPrompt !== input.systemPrompt
  ) {
    throw new Error(PROMPT_SAVE_ERROR);
  }
}

export function assertPersonaPromptPersisted(
  input: UpdatePersonaInput,
  saved: Pick<AgentPersona, "systemPrompt">,
): void {
  if (saved.systemPrompt !== input.systemPrompt) {
    throw new Error(PROMPT_SAVE_ERROR);
  }
}

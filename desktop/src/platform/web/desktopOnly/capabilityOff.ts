import { CapabilityUnavailableError, register } from "../registry";

/**
 * Registration helpers for Tauri commands that the browser build cannot honestly
 * mirror. Every renderer-invoked command must be registered so the app never
 * hits an unregistered-command miss.
 *
 * Contract (Lane 3, 2026-08-16):
 *  - reads → typed safe defaults so panels render empty/idle instead of crashing
 *  - mutations → BrowserUnavailableError (a CapabilityUnavailableError subclass)
 *    with a user-readable message, surfaced by the existing UI error paths;
 *    we never fake success on a write.
 */
export class BrowserUnavailableError extends CapabilityUnavailableError {
  constructor(command: string, hint?: string) {
    super(
      command,
      hint
        ? `Not available in the browser build: ${hint}`
        : `Not available in the browser build (${command}).`,
    );
    this.name = "BrowserUnavailableError";
  }
}

const offCommands = new Set<string>();

/** Register a read-style command that returns an inert value in the browser. */
export function registerOffRead<T>(
  command: string,
  value: T | (() => T),
): void {
  offCommands.add(command);
  register(command, () =>
    typeof value === "function" ? (value as () => T)() : value,
  );
}

/** Register a mutation-style command that must not pretend to succeed. */
export function registerOffMutation(command: string, hint?: string): void {
  offCommands.add(command);
  register(command, () => {
    throw new BrowserUnavailableError(command, hint);
  });
}

export function getCapabilityOffCommands(): readonly string[] {
  return [...offCommands].sort();
}

export function resetCapabilityOffForTests(): void {
  offCommands.clear();
}

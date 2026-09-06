import type {
  AcpConfigOptionValue,
  ManagedAgentBackend,
} from "@/shared/api/types";
import type { PersonaDropdownOption } from "./agentConfigOptions";

/** Controlled draft selection; persistence belongs to the dialog Save. */
export const EFFORT_DEFAULT_DROPDOWN_VALUE = "__effort_default__";

/** Offer only the observed local adapter capability. */
export function effortPickerState({
  backend,
  effortConfigId,
  effortOptions,
  currentEffort,
}: {
  backend: ManagedAgentBackend;
  effortConfigId: string | undefined;
  effortOptions: readonly AcpConfigOptionValue[] | undefined;
  currentEffort: string | null;
}): {
  visible: boolean;
  options: PersonaDropdownOption[];
  selectValue: string;
} {
  const visible =
    backend.type === "local" &&
    (effortConfigId !== undefined || currentEffort != null);

  const options: PersonaDropdownOption[] = [
    { label: "Inherit effort", value: EFFORT_DEFAULT_DROPDOWN_VALUE },
    ...(effortOptions ?? []).map((option) => ({
      label: option.displayName ?? option.value,
      value: option.value,
    })),
  ];

  const trimmed = currentEffort?.trim() ?? "";
  if (
    trimmed &&
    !(effortOptions ?? []).some((option) => option.value === trimmed)
  ) {
    options.push({
      label: `${trimmed} (saved; unavailable)`,
      value: trimmed,
      disabled: true,
    });
  }
  const selectValue = trimmed || EFFORT_DEFAULT_DROPDOWN_VALUE;

  return { visible, options, selectValue };
}

/**
 * Map a dropdown selection back to the persisted value sent as
 * `effortLevel` in the locked update payload: the sentinel clears effort
 * (null → inherited preference), any other value is the explicit effort level.
 */
export function effortSelectionToPersistedValue(value: string): string | null {
  return value === EFFORT_DEFAULT_DROPDOWN_VALUE ? null : value;
}

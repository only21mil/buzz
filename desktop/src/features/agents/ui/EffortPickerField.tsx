import type { ManagedAgent, RuntimeConfigSurface } from "@/shared/api/types";
import { PERSONA_LABEL_OPTIONAL_CLASS } from "./agentConfigOptions";
import {
  effortPickerState,
  effortSelectionToPersistedValue,
} from "./effortPicker";
import { PersonaDropdownField } from "./PersonaDropdownField";

/** Controlled draft selection; persistence belongs to the dialog Save. */
export function EffortPickerField({
  agent,
  config,
  disabled,
  value,
  onChange,
}: {
  agent: ManagedAgent;
  config: RuntimeConfigSurface | undefined;
  disabled: boolean;
  /** The pending persisted effort form (`null` = adapter default). */
  value: string | null;
  onChange: (level: string | null) => void;
}) {
  const { visible, options, selectValue } = effortPickerState({
    backend: agent.backend,
    effortConfigId: config?.effortConfigId,
    effortOptions: config?.effortOptions,
    currentEffort: value,
  });

  if (!visible) {
    return null;
  }

  return (
    <div className="space-y-1.5">
      <label
        className="text-sm font-medium text-foreground"
        htmlFor="edit-agent-effort"
      >
        Thinking effort
        <span className={PERSONA_LABEL_OPTIONAL_CLASS}>Optional</span>
      </label>
      <PersonaDropdownField
        disabled={disabled}
        id="edit-agent-effort"
        onValueChange={(next) =>
          onChange(effortSelectionToPersistedValue(next))
        }
        options={options}
        placeholder="Inherit effort"
        value={selectValue}
      />
      <p className="text-xs text-muted-foreground">
        Restart required to apply.
      </p>
    </div>
  );
}

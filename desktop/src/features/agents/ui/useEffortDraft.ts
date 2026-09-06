import { useEffect, useState } from "react";

/** Saved preferences may poll while a dialog is open; only reopen resets a draft. */
export function useEffortDraft(
  open: boolean,
  pubkey: string,
  saved: string | null,
) {
  const [value, setValue] = useState(saved);
  const [touched, setTouched] = useState(false);
  // biome-ignore lint/correctness/useExhaustiveDependencies: polling must not erase unsaved edits
  useEffect(() => {
    if (open) {
      setValue(saved);
      setTouched(false);
    }
  }, [open, pubkey]);
  return {
    value,
    patch: touched ? value : undefined,
    onChange(next: string | null) {
      setTouched(true);
      setValue(next);
    },
  };
}

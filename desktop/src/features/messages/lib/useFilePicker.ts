import * as React from "react";

type FilePickerOptions = {
  accept?: string;
  multiple?: boolean;
  /** Replace the input when a new open belongs to a different draft epoch. */
  ownershipEpoch?: number;
};

/** Reuse a mounted input within each ownership epoch across cancellations. */
export function useFilePicker() {
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const inputEpochRef = React.useRef<number | undefined>(undefined);
  const pendingRef = React.useRef<object | null>(null);
  const mountedRef = React.useRef(false);

  React.useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      pendingRef.current = null;
      const input = inputRef.current;
      if (input) {
        input.onchange = null;
        input.oncancel = null;
        input.remove();
      }
      inputRef.current = null;
    };
  }, []);

  return React.useCallback(
    (options: FilePickerOptions, onFiles: (files: File[]) => void) => {
      if (!mountedRef.current) return;
      let input = inputRef.current;
      if (input && inputEpochRef.current !== options.ownershipEpoch) {
        // Old native events must remain bound to the retired node. Relabeling
        // its callback would let an old selection attach to the new draft.
        pendingRef.current = null;
        input.onchange = null;
        input.oncancel = null;
        input.remove();
        input = null;
      }
      if (!input) {
        input = document.createElement("input");
        input.type = "file";
        input.hidden = true;
        document.body.append(input);
        inputRef.current = input;
        inputEpochRef.current = options.ownershipEpoch;
      }

      // Reentry within one epoch keeps the original callback, including when
      // cancellation emitted no event. A new epoch always has its own node.
      if (!pendingRef.current) {
        input.accept = options.accept ?? "";
        input.multiple = options.multiple ?? false;
        input.value = "";
        const request = {};
        pendingRef.current = request;
        const settle = (selected: boolean) => {
          if (!mountedRef.current || pendingRef.current !== request) return;
          const files = selected ? Array.from(input.files ?? []) : [];
          pendingRef.current = null;
          input.onchange = null;
          input.oncancel = null;
          input.value = "";
          if (files.length) onFiles(files);
        };
        input.onchange = () => settle(true);
        input.oncancel = () => settle(false);
      }
      input.click();
    },
    [],
  );
}

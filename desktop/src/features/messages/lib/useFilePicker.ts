import * as React from "react";

type FilePickerOptions = {
  accept?: string;
  multiple?: boolean;
};

/** Reuse a mounted input across native chooser cancellations and selections. */
export function useFilePicker() {
  const inputRef = React.useRef<HTMLInputElement | null>(null);
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
      if (!input) {
        input = document.createElement("input");
        input.type = "file";
        input.hidden = true;
        document.body.append(input);
        inputRef.current = input;
      }

      // A second click cannot retarget an unsettled chooser to a newer draft.
      // Reuse its original callback even when cancellation emitted no event.
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

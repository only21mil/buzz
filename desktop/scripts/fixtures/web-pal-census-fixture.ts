import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { invoke as invokeTauriRaw } from "@tauri-apps/api/core";
import { invoke as coreAlias } from "@tauri-apps/api/core";
import { invokeTauri as invokeWrapper } from "@/shared/api/tauri";

const bytes = new Uint8Array([1, 2, 3]);

invokeWrapper("fixture_single_line", { enabled: true });

tauriInvoke(
  "fixture_multi_line",
  {
    value: 1,
  },
);

invokeTauriRaw("fixture_raw_body", bytes, { headers: {} });
coreAlias("fixture_inferred_raw", bytes);

invokeWrapper(dynamicCommand, { ignored: true });

import type {
  NormalizedConfig,
  ConfigField,
  ExtensionEntry,
  ConfigSourceReport,
} from "./types";

export type AcpConfigOptionValue = {
  value: string;
  displayName?: string | null;
};

export type RuntimeConfigSurface = {
  effortConfigId?: string;
  effortOptions?: AcpConfigOptionValue[];
  runtimeId: string | null;
  runtimeLabel: string | null;
  isPreSpawn: boolean;
  normalized: NormalizedConfig;
  advanced: ConfigField[];
  extensions: ExtensionEntry[];
  sources: ConfigSourceReport;
};

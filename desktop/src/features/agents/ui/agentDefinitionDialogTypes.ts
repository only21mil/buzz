import type * as React from "react";

import type {
  AcpRuntimeCatalogEntry,
  CreatePersonaInput,
  UpdatePersonaInput,
} from "@/shared/api/types";

export type AgentDefinitionDialogProps = {
  open: boolean;
  embedded?: boolean;
  title: string;
  description: string;
  submitLabel: string;
  initialValues: CreatePersonaInput | UpdatePersonaInput | null;
  error: Error | null;
  isPending: boolean;
  runtimes: AcpRuntimeCatalogEntry[];
  runtimeCatalogStatus?: "loading" | "ready" | "error";
  onDirtyChange?: (dirty: boolean) => void;
  onOpenChange: (open: boolean) => void;
  onSubmit: (
    input: CreatePersonaInput | UpdatePersonaInput,
    options: AgentDefinitionSubmitOptions,
  ) => Promise<unknown>;
  /** Publishes saved changes when the edited agent is shared in the catalog. */
  publishCatalogUpdatesOnSave?: boolean;
  createRunSection?: React.ReactNode;
  /** Optional explicit alternative to the create form's default submit. */
  secondarySubmitLabel?: string;
  /** Extra create-mode submit gate (e.g. incomplete provider config). */
  createSubmitBlocked?: boolean;
};

export type AgentDefinitionSubmitOptions = {
  publishCatalogUpdates: boolean;
  submitAction: "primary" | "secondary";
};

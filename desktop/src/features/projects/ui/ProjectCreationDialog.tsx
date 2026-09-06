import { isTauri } from "@tauri-apps/api/core";
import { toast } from "sonner";

import { useCreateProjectMutation } from "@/features/projects/useCreateProject";
import { CreateProjectDialog } from "@/features/projects/ui/CreateProjectDialog";

/** Shared creation flow for the populated and first-run project views. */
export function ProjectCreationDialog({
  onCreated,
  onOpenChange,
  open,
}: {
  onCreated: () => void;
  onOpenChange: (open: boolean) => void;
  open: boolean;
}) {
  const createProjectMutation = useCreateProjectMutation();

  if (!isTauri()) return null;

  return (
    <CreateProjectDialog
      isCreating={createProjectMutation.isPending}
      onCreate={async (input) => {
        const result = await createProjectMutation.mutateAsync(input);
        if (result.compatibilityWarning) {
          toast.warning("Created as a standalone project", {
            description: result.compatibilityWarning,
          });
        } else {
          toast.success(`Project "${result.project.name}" created.`);
        }
        onCreated();
      }}
      onOpenChange={onOpenChange}
      open={open}
    />
  );
}

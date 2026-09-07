import { ArrowLeft, FolderGit2 } from "lucide-react";
import { Button } from "@/shared/ui/button";

export function ProjectLoadState({
  failed,
  onRetry,
  onBack,
}: {
  failed: boolean;
  onRetry: () => void;
  onBack: () => void;
}) {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-3 px-4 py-16 text-center">
      <FolderGit2 className="h-10 w-10 text-muted-foreground/40" />
      <p
        className={
          failed ? "text-sm text-red-400" : "text-sm text-muted-foreground"
        }
      >
        {failed ? "Failed to load project" : "This project could not be found."}
      </p>
      <div className="flex items-center gap-2">
        {failed ? (
          <Button onClick={onRetry} size="sm" variant="outline">
            Retry
          </Button>
        ) : null}
        <Button
          onClick={onBack}
          size="sm"
          variant={failed ? "ghost" : "outline"}
        >
          <ArrowLeft className="mr-1.5 h-4 w-4" />
          Back to Projects
        </Button>
      </div>
    </div>
  );
}

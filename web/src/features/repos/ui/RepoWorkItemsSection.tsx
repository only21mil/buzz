import {
  CircleDot,
  GitPullRequest,
  MessageSquare,
  RefreshCw,
} from "lucide-react";
import { relativeTime } from "@/shared/lib/relative-time";
import { truncatePubkey } from "@/shared/lib/pubkey";
import { Badge } from "@/shared/ui/badge";
import { Button } from "@/shared/ui/button";
import type { ProjectIssue, ProjectPullRequest } from "../repo-work-items.mjs";

type RepoWorkItem = ProjectIssue | ProjectPullRequest;

interface RepoWorkItemsSectionProps {
  error: Error | null;
  isLoading: boolean;
  items: RepoWorkItem[];
  kind: "issue" | "pull-request";
  onRetry: () => void;
}

function statusClass(status: string): string {
  if (status === "Open" || status === "In Progress" || status === "In Review") {
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";
  }
  if (status === "Merged" || status === "Done") {
    return "border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300";
  }
  return "border-black/15 bg-black/5 text-black/60 dark:border-white/15 dark:bg-white/5 dark:text-white/60";
}

function WorkItemRow({
  item,
  kind,
}: {
  item: RepoWorkItem;
  kind: RepoWorkItemsSectionProps["kind"];
}) {
  const Icon = kind === "issue" ? CircleDot : GitPullRequest;
  const branchName = "branchName" in item ? item.branchName : null;
  const targetBranch = "targetBranch" in item ? item.targetBranch : null;
  const updateCount = "updateCount" in item ? item.updateCount : 0;

  return (
    <details
      className="group border-b border-black/10 last:border-b-0 dark:border-white/10"
      data-testid={`${kind}-row-${item.id}`}
    >
      <summary className="flex cursor-pointer list-none items-start gap-3 px-4 py-3 marker:content-none hover:bg-black/3 dark:hover:bg-white/3">
        <Icon className="mt-0.5 h-4 w-4 shrink-0 text-black/45 dark:text-white/45" />
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium text-black dark:text-white">
            {item.title}
          </p>
          <p className="mt-1 truncate text-xs text-black/50 dark:text-white/50">
            <span className="font-mono">#{item.id.slice(0, 8)}</span>
            <span> by {truncatePubkey(item.author)}</span>
            <span> · updated {relativeTime(item.updatedAt)}</span>
            {item.comments.length > 0 && (
              <span className="ml-2 inline-flex items-center gap-1">
                <MessageSquare className="h-3 w-3" />
                {item.comments.length}
              </span>
            )}
            {updateCount > 0 && (
              <span className="ml-2">
                {updateCount} {updateCount === 1 ? "update" : "updates"}
              </span>
            )}
          </p>
        </div>
        <Badge variant="outline" className={statusClass(item.status)}>
          {item.status}
        </Badge>
      </summary>
      <div className="space-y-3 bg-black/2 px-11 py-4 text-sm dark:bg-white/2">
        {(branchName || targetBranch) && (
          <p className="font-mono text-xs text-black/55 dark:text-white/55">
            {branchName ?? "unknown"} → {targetBranch ?? "default"}
          </p>
        )}
        <p className="whitespace-pre-wrap break-words leading-relaxed text-black/75 dark:text-white/75">
          {item.content || "No description provided."}
        </p>
        {item.labels.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {[...new Set(item.labels)].map((label) => (
              <Badge
                key={label}
                variant="outline"
                className="border-black/10 text-black/55 dark:border-white/10 dark:text-white/55"
              >
                {label}
              </Badge>
            ))}
          </div>
        )}
        {item.comments.length > 0 && (
          <div className="space-y-2 border-t border-black/10 pt-3 dark:border-white/10">
            <p className="text-xs font-medium text-black/60 dark:text-white/60">
              Comments
            </p>
            {item.comments.map((comment) => (
              <div
                key={comment.id}
                className="rounded border border-black/10 bg-white px-3 py-2 dark:border-white/10 dark:bg-white/5"
              >
                <p className="text-xs text-black/45 dark:text-white/45">
                  {truncatePubkey(comment.author)} ·{" "}
                  {relativeTime(comment.createdAt)}
                </p>
                <p className="mt-1 whitespace-pre-wrap break-words text-sm text-black/70 dark:text-white/70">
                  {comment.content}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>
    </details>
  );
}

export function RepoWorkItemsSection({
  error,
  isLoading,
  items,
  kind,
  onRetry,
}: RepoWorkItemsSectionProps) {
  const singular = kind === "issue" ? "issue" : "pull request";
  const plural = kind === "issue" ? "issues" : "pull requests";
  const Icon = kind === "issue" ? CircleDot : GitPullRequest;

  if (isLoading) {
    return (
      <div className="mt-4 rounded-md border border-black/10 bg-white px-4 py-8 text-center text-sm text-black/50 dark:border-white/10 dark:bg-white/5 dark:text-white/50">
        Loading {plural}…
      </div>
    );
  }

  if (error) {
    return (
      <div className="mt-4 rounded-md border border-destructive/50 bg-destructive/10 px-4 py-5 text-sm text-destructive">
        <p className="font-medium">
          {singular === "issue" ? "Issues" : "Pull requests"} unavailable
        </p>
        <p className="mt-1">
          Connect with a community member identity, then try this relay read
          again.
        </p>
        <p className="mt-1 break-words text-xs opacity-80">{error.message}</p>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="mt-3 border-destructive/40 bg-transparent text-destructive hover:bg-destructive/10 hover:text-destructive"
          onClick={onRetry}
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Try again
        </Button>
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="mt-4 rounded-md border border-black/10 bg-white px-4 py-10 text-center dark:border-white/10 dark:bg-white/5">
        <Icon className="mx-auto h-8 w-8 text-black/35 dark:text-white/35" />
        <p className="mt-3 text-sm font-medium text-black dark:text-white">
          No {plural} yet
        </p>
        <p className="mt-1 text-xs text-black/50 dark:text-white/50">
          This view is read-only. New {plural} appear when the relay receives
          them.
        </p>
      </div>
    );
  }

  return (
    <div className="mt-4 overflow-hidden rounded-md border border-black/10 bg-white dark:border-white/10 dark:bg-white/5">
      {items.map((item) => (
        <WorkItemRow key={item.id} item={item} kind={kind} />
      ))}
    </div>
  );
}

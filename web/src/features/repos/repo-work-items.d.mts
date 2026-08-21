import type { NostrEvent, NostrFilter } from "@/shared/lib/nostr-client";

export type ProjectIssueStatus =
  | "Triage"
  | "Backlog"
  | "In Progress"
  | "In Review"
  | "Done"
  | "Closed";

export interface RepoWorkItemComment {
  id: string;
  content: string;
  author: string;
  createdAt: number;
}

export interface ProjectIssue {
  id: string;
  title: string;
  content: string;
  author: string;
  createdAt: number;
  updatedAt: number;
  labels: string[];
  status: ProjectIssueStatus;
  comments: RepoWorkItemComment[];
}

export interface ProjectPullRequestUpdate {
  id: string;
  content: string;
  author: string;
  createdAt: number;
  commit: string | null;
}

export interface ProjectPullRequest {
  id: string;
  title: string;
  content: string;
  author: string;
  createdAt: number;
  updatedAt: number;
  labels: string[];
  status: "Open" | "Merged" | "Closed" | "Draft";
  branchName: string | null;
  targetBranch: string | null;
  commit: string | null;
  updateCount: number;
  comments: RepoWorkItemComment[];
}

export interface RepoWorkItems {
  issues: ProjectIssue[];
  pullRequests: ProjectPullRequest[];
}

export const REPO_WORK_ITEM_KINDS: {
  ISSUE: 1621;
  PULL_REQUEST: 1618;
  PULL_REQUEST_UPDATE: 1619;
  TEXT_NOTE: 1;
  STATUS_OPEN: 1630;
  STATUS_MERGED: 1631;
  STATUS_CLOSED: 1632;
  STATUS_DRAFT: 1633;
};

export const PROJECT_ISSUE_STATUS: Record<string, ProjectIssueStatus>;

export function getTag(event: NostrEvent, name: string): string | undefined;

export function repoWorkItemFilters(repoAddress: string): {
  issues: NostrFilter;
  pullRequests: NostrFilter;
  pullRequestUpdates: NostrFilter;
  comments: NostrFilter;
  statuses: NostrFilter;
};

export function parseRepoWorkItems(input: {
  issueEvents: NostrEvent[];
  pullRequestEvents: NostrEvent[];
  updateEvents?: NostrEvent[];
  commentEvents?: NostrEvent[];
  statusEvents?: NostrEvent[];
}): RepoWorkItems;

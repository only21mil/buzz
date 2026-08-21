export const REPO_WORK_ITEM_KINDS = {
  ISSUE: 1621,
  PULL_REQUEST: 1618,
  PULL_REQUEST_UPDATE: 1619,
  TEXT_NOTE: 1,
  STATUS_OPEN: 1630,
  STATUS_MERGED: 1631,
  STATUS_CLOSED: 1632,
  STATUS_DRAFT: 1633,
};

export const PROJECT_ISSUE_STATUS = {
  TRIAGE: "Triage",
  BACKLOG: "Backlog",
  IN_PROGRESS: "In Progress",
  IN_REVIEW: "In Review",
  DONE: "Done",
  CLOSED: "Closed",
};

export function repoWorkItemFilters(repoAddress) {
  return {
    issues: {
      kinds: [REPO_WORK_ITEM_KINDS.ISSUE],
      "#a": [repoAddress],
      limit: 200,
    },
    pullRequests: {
      kinds: [REPO_WORK_ITEM_KINDS.PULL_REQUEST],
      "#a": [repoAddress],
      limit: 200,
    },
    pullRequestUpdates: {
      kinds: [REPO_WORK_ITEM_KINDS.PULL_REQUEST_UPDATE],
      "#a": [repoAddress],
      limit: 500,
    },
    comments: {
      kinds: [REPO_WORK_ITEM_KINDS.TEXT_NOTE],
      "#a": [repoAddress],
      limit: 500,
    },
    statuses: {
      kinds: [
        REPO_WORK_ITEM_KINDS.STATUS_OPEN,
        REPO_WORK_ITEM_KINDS.STATUS_MERGED,
        REPO_WORK_ITEM_KINDS.STATUS_CLOSED,
        REPO_WORK_ITEM_KINDS.STATUS_DRAFT,
      ],
      "#a": [repoAddress],
      limit: 500,
    },
  };
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

export function getTag(event, name) {
  const value = event.tags.find((tag) => tag[0] === name)?.[1];
  return isNonEmptyString(value) ? value : undefined;
}

function getAllTags(event, name) {
  return event.tags
    .filter((tag) => tag[0] === name && isNonEmptyString(tag[1]))
    .map((tag) => tag[1]);
}

function repoOwnerFromAddress(repoAddress) {
  const owner = (repoAddress ?? "").split(":")[1] ?? "";
  return /^[a-fA-F0-9]{64}$/.test(owner) ? owner.toLowerCase() : null;
}

// Match the desktop trust rule: lifecycle events and PR updates only count
// when the root author or repository owner signed them.
function allowedActorsForRoot(rootEvent) {
  const allowed = new Set([rootEvent.pubkey.toLowerCase()]);
  const owner = repoOwnerFromAddress(getTag(rootEvent, "a"));
  if (owner) allowed.add(owner);
  return allowed;
}

function latestStatusForRoot(root, statusEvents, allowUppercaseReference) {
  const allowedActors = allowedActorsForRoot(root);
  return statusEvents
    .filter(
      (event) =>
        allowedActors.has(event.pubkey.toLowerCase()) &&
        event.tags.some(
          (tag) =>
            (tag[0] === "e" || (allowUppercaseReference && tag[0] === "E")) &&
            tag[1] === root.id,
        ),
    )
    .sort((left, right) => right.created_at - left.created_at)[0];
}

function eventsForRoot(rootId, events) {
  return events
    .filter((event) =>
      event.tags.some(
        (tag) => (tag[0] === "e" || tag[0] === "E") && tag[1] === rootId,
      ),
    )
    .sort((left, right) => left.created_at - right.created_at);
}

function commentsForRoot(rootId, commentEvents) {
  return eventsForRoot(rootId, commentEvents).map((event) => ({
    id: event.id,
    content: event.content,
    author: event.pubkey,
    createdAt: event.created_at,
  }));
}

function issueStatus(issue, statusEvent) {
  if (statusEvent?.kind === REPO_WORK_ITEM_KINDS.STATUS_MERGED) {
    return PROJECT_ISSUE_STATUS.DONE;
  }
  if (statusEvent?.kind === REPO_WORK_ITEM_KINDS.STATUS_CLOSED) {
    return PROJECT_ISSUE_STATUS.CLOSED;
  }
  if (statusEvent?.kind === REPO_WORK_ITEM_KINDS.STATUS_DRAFT) {
    return PROJECT_ISSUE_STATUS.TRIAGE;
  }

  const labels = getAllTags(issue, "t").map((label) => label.toLowerCase());
  if (labels.includes("in-review") || labels.includes("review")) {
    return PROJECT_ISSUE_STATUS.IN_REVIEW;
  }
  if (labels.includes("in-progress") || labels.includes("active")) {
    return PROJECT_ISSUE_STATUS.IN_PROGRESS;
  }
  if (labels.includes("triage")) return PROJECT_ISSUE_STATUS.TRIAGE;
  return PROJECT_ISSUE_STATUS.BACKLOG;
}

function eventToIssue(issue, statusEvents, commentEvents) {
  const latestStatus = latestStatusForRoot(issue, statusEvents, false);
  const comments = commentsForRoot(issue.id, commentEvents);
  return {
    id: issue.id,
    title:
      getTag(issue, "subject") ||
      issue.content.split("\n")[0] ||
      "Untitled issue",
    content: issue.content,
    author: issue.pubkey,
    createdAt: issue.created_at,
    updatedAt:
      [
        ...comments,
        ...(latestStatus ? [{ createdAt: latestStatus.created_at }] : []),
      ].sort((left, right) => right.createdAt - left.createdAt)[0]?.createdAt ??
      issue.created_at,
    labels: getAllTags(issue, "t"),
    status: issueStatus(issue, latestStatus),
    comments,
  };
}

function trustedUpdatesForPullRequest(pullRequest, updateEvents) {
  const allowedActors = allowedActorsForRoot(pullRequest);
  return updateEvents.filter(
    (event) =>
      allowedActors.has(event.pubkey.toLowerCase()) &&
      getTag(event, "E") === pullRequest.id,
  );
}

function pullRequestStatus(pullRequest, statusEvent) {
  if (statusEvent?.kind === REPO_WORK_ITEM_KINDS.STATUS_OPEN) return "Open";
  if (statusEvent?.kind === REPO_WORK_ITEM_KINDS.STATUS_MERGED) return "Merged";
  if (statusEvent?.kind === REPO_WORK_ITEM_KINDS.STATUS_CLOSED) return "Closed";
  if (statusEvent?.kind === REPO_WORK_ITEM_KINDS.STATUS_DRAFT) return "Draft";
  const labels = getAllTags(pullRequest, "t").map((label) =>
    label.toLowerCase(),
  );
  return labels.includes("draft") ? "Draft" : "Open";
}

function eventToPullRequest(
  pullRequest,
  updateEvents,
  commentEvents,
  statusEvents,
) {
  const trustedUpdates = trustedUpdatesForPullRequest(
    pullRequest,
    updateEvents,
  );
  const latestUpdate = [...trustedUpdates].sort(
    (left, right) => right.created_at - left.created_at,
  )[0];
  const latestStatus = latestStatusForRoot(pullRequest, statusEvents, true);
  const updates = eventsForRoot(pullRequest.id, trustedUpdates).map(
    (event) => ({
      id: event.id,
      content: event.content,
      author: event.pubkey,
      createdAt: event.created_at,
      commit: getTag(event, "c") ?? null,
    }),
  );
  const comments = commentsForRoot(pullRequest.id, commentEvents);

  return {
    id: pullRequest.id,
    title:
      getTag(pullRequest, "subject") ||
      pullRequest.content.split("\n")[0] ||
      "Untitled pull request",
    content: pullRequest.content,
    author: pullRequest.pubkey,
    createdAt: pullRequest.created_at,
    updatedAt:
      [
        ...updates,
        ...comments,
        ...(latestStatus ? [{ createdAt: latestStatus.created_at }] : []),
      ].sort((left, right) => right.createdAt - left.createdAt)[0]?.createdAt ??
      latestUpdate?.created_at ??
      pullRequest.created_at,
    labels: getAllTags(pullRequest, "t"),
    status: pullRequestStatus(pullRequest, latestStatus),
    branchName: getTag(pullRequest, "branch-name") ?? null,
    targetBranch: getTag(pullRequest, "target-branch") ?? null,
    commit: getTag(latestUpdate ?? pullRequest, "c") ?? null,
    updateCount: updates.length,
    comments,
  };
}

export function parseRepoWorkItems({
  issueEvents,
  pullRequestEvents,
  updateEvents = [],
  commentEvents = [],
  statusEvents = [],
}) {
  return {
    issues: issueEvents
      .map((issue) => eventToIssue(issue, statusEvents, commentEvents))
      .sort((left, right) => right.updatedAt - left.updatedAt),
    pullRequests: pullRequestEvents
      .map((pullRequest) =>
        eventToPullRequest(
          pullRequest,
          updateEvents,
          commentEvents,
          statusEvents,
        ),
      )
      .sort((left, right) => right.updatedAt - left.updatedAt),
  };
}

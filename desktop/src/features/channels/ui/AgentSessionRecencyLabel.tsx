import * as React from "react";

import { useNow } from "@/shared/lib/useNow";

type AgentSessionRecencyLabelProps = {
  latestActivityAt: number | null;
};

export const AgentSessionRecencyLabel = React.memo(
  function AgentSessionRecencyLabel({
    latestActivityAt,
  }: AgentSessionRecencyLabelProps) {
    if (latestActivityAt === null) {
      return <RecencyLabel label="No updates yet" />;
    }

    return <LiveRecencyLabel latestActivityAt={latestActivityAt} />;
  },
);

function LiveRecencyLabel({ latestActivityAt }: { latestActivityAt: number }) {
  const now = useNow(1000);
  return (
    <RecencyLabel
      label={`Last updated ${formatRelativeActivityTime(latestActivityAt, now)}`}
      title={`Last updated ${new Date(latestActivityAt).toLocaleString()}`}
    />
  );
}

function RecencyLabel({ label, title }: { label: string; title?: string }) {
  return (
    <span
      className="shrink-0"
      data-testid="agent-session-recency-label"
      title={title}
    >
      {label}
    </span>
  );
}

export function formatRelativeActivityTime(
  timestamp: number,
  now: number,
): string {
  const elapsedMs = Math.max(0, now - timestamp);
  const totalSeconds = Math.floor(elapsedMs / 1_000);

  if (totalSeconds < 60) {
    return "just now";
  }

  const totalMinutes = Math.floor(totalSeconds / 60);
  if (totalMinutes < 60) {
    return `${totalMinutes}m ago`;
  }

  const totalHours = Math.floor(totalMinutes / 60);
  if (totalHours < 24) {
    return `${totalHours}h ago`;
  }

  const totalDays = Math.floor(totalHours / 24);
  if (totalDays < 7) {
    return `${totalDays}d ago`;
  }

  const totalWeeks = Math.floor(totalDays / 7);
  return `${totalWeeks}w ago`;
}

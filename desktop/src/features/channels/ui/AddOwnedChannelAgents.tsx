import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useRelayAgentsQuery } from "@/features/agents/hooks";
import {
  addOwnedChannelAgents,
  getOwnedAgentsToAdd,
} from "@/features/agents/lib/ownedChannelAgents";
import {
  invalidateChannelState,
  useChannelMembersQuery,
  useChannelsQuery,
} from "@/features/channels/hooks";
import { canAddChannelMembers } from "@/features/channels/lib/channelMemberAdmission";
import { useIsArchivedPredicate } from "@/features/identity-archive/hooks";
import { useIdentityQuery } from "@/shared/api/hooks";
import { addChannelMembers } from "@/shared/api/tauri";
import { normalizePubkey } from "@/shared/lib/pubkey";
import { Button } from "@/shared/ui/button";
import { Checkbox } from "@/shared/ui/checkbox";

/** Relay membership only. Adding an existing seat does not start its runtime. */
export function AddOwnedChannelAgents({
  channelId,
  disabled = false,
}: {
  channelId: string;
  disabled?: boolean;
}) {
  const selectionId = React.useId();
  const queryClient = useQueryClient();
  const identity = useIdentityQuery();
  const directory = useRelayAgentsQuery();
  const roster = useChannelMembersQuery(channelId);
  const channels = useChannelsQuery();
  const isArchived = useIsArchivedPredicate();
  const [selected, setSelected] = React.useState<ReadonlySet<string>>(
    new Set(),
  );
  const [confirmed, setConfirmed] = React.useState<ReadonlySet<string>>(
    new Set(),
  );
  const [pending, setPending] = React.useState(false);
  const inFlight = React.useRef(false);
  const [notice, setNotice] = React.useState<string | null>(null);
  const [errors, setErrors] = React.useState<string[]>([]);
  const currentPubkey = identity.data?.pubkey;
  const members = roster.data ?? [];
  const channel = channels.data?.find((entry) => entry.id === channelId);
  const self = members.find(
    (member) =>
      normalizePubkey(member.pubkey) === normalizePubkey(currentPubkey ?? ""),
  );
  const allowed =
    channel &&
    !channel.archivedAt &&
    canAddChannelMembers({
      channelType: channel.channelType,
      visibility: channel.visibility,
      selfRole: self?.role,
    });
  const memberPubkeys = new Set([
    ...members.map((member) => normalizePubkey(member.pubkey)),
    ...confirmed,
  ]);
  const agents = getOwnedAgentsToAdd(
    directory.data ?? [],
    currentPubkey,
    memberPubkeys,
  ).filter((agent) => !isArchived(agent.pubkey));
  const ready =
    allowed &&
    identity.isSuccess &&
    directory.isSuccess &&
    roster.isSuccess &&
    channels.isSuccess;

  async function addAgents(selectedOnly: boolean) {
    if (!ready || disabled || inFlight.current || agents.length === 0) return;
    inFlight.current = true;
    setPending(true);
    setErrors([]);
    setNotice(null);
    try {
      // Refresh before retrying so previously accepted writes are never downgraded
      // or repeated merely because the dialog was closed or the response was lost.
      const [fresh, freshDirectory, freshChannels] = await Promise.all([
        roster.refetch({ throwOnError: true }),
        directory.refetch({ throwOnError: true }),
        channels.refetch({ throwOnError: true }),
      ]);
      const freshChannel = freshChannels.data?.find(
        (entry) => entry.id === channelId,
      );
      const freshSelf = fresh.data?.find(
        (member) =>
          normalizePubkey(member.pubkey) ===
          normalizePubkey(currentPubkey ?? ""),
      );
      if (
        !freshChannel ||
        freshChannel.archivedAt ||
        !canAddChannelMembers({
          channelType: freshChannel.channelType,
          visibility: freshChannel.visibility,
          selfRole: freshSelf?.role,
        })
      )
        throw new Error("You can no longer add agents to this channel.");
      const requested = new Set(
        agents
          .filter(
            (agent) =>
              !selectedOnly || selected.has(normalizePubkey(agent.pubkey)),
          )
          .map((agent) => normalizePubkey(agent.pubkey)),
      );
      const candidates = getOwnedAgentsToAdd(
        freshDirectory.data ?? [],
        currentPubkey,
        new Set([
          ...(fresh.data ?? []).map((member) => member.pubkey),
          ...confirmed,
        ]),
      ).filter(
        (agent) =>
          requested.has(normalizePubkey(agent.pubkey)) &&
          !isArchived(agent.pubkey),
      );
      const result = await addOwnedChannelAgents(
        channelId,
        candidates,
        addChannelMembers,
      );
      setConfirmed((previous) => new Set([...previous, ...result.added]));
      setSelected(
        (previous) =>
          new Set(
            [...previous].filter((pubkey) => !result.added.includes(pubkey)),
          ),
      );
      const addedNames = candidates
        .filter((agent) => result.added.includes(normalizePubkey(agent.pubkey)))
        .map((agent) => agent.name);
      setNotice(
        addedNames.length
          ? `Added: ${addedNames.join(", ")}.`
          : "No agents were added.",
      );
      setErrors(
        result.errors.map((failure) => {
          const name =
            candidates.find(
              (agent) => normalizePubkey(agent.pubkey) === failure.pubkey,
            )?.name ?? failure.pubkey;
          return `${name}: ${failure.error}`;
        }),
      );
      await invalidateChannelState(queryClient, channelId);
    } catch (error) {
      setErrors([
        error instanceof Error ? error.message : "Failed to add agents.",
      ]);
    } finally {
      inFlight.current = false;
      setPending(false);
    }
  }

  return (
    <section className="space-y-2" aria-label="Your existing agents">
      {agents.map((agent) => {
        const pubkey = normalizePubkey(agent.pubkey);
        return (
          <label
            key={pubkey}
            htmlFor={`${selectionId}-${pubkey}`}
            className="flex items-center gap-2 text-sm"
          >
            <Checkbox
              id={`${selectionId}-${pubkey}`}
              checked={selected.has(pubkey)}
              disabled={!ready || disabled || pending}
              onCheckedChange={(checked) => {
                setSelected((previous) => {
                  const next = new Set(previous);
                  if (checked === true) next.add(pubkey);
                  else next.delete(pubkey);
                  return next;
                });
              }}
            />
            {agent.name}
          </label>
        );
      })}
      <Button
        type="button"
        variant="outline"
        disabled={
          !ready ||
          disabled ||
          pending ||
          !agents.some((agent) => selected.has(normalizePubkey(agent.pubkey)))
        }
        onClick={() => void addAgents(true)}
      >
        Add selected agents
      </Button>
      <Button
        type="button"
        variant="outline"
        disabled={!ready || disabled || pending || agents.length === 0}
        onClick={() => void addAgents(false)}
      >
        {pending
          ? "Adding agents..."
          : `Add all my agents${agents.length ? ` (${agents.length})` : ""}`}
      </Button>
      <p className="text-xs text-muted-foreground">
        Adds your existing agents as bots. Running agents pick up channel
        membership automatically.
      </p>
      {!ready &&
      (directory.isError ||
        roster.isError ||
        channels.isError ||
        identity.isError) ? (
        <p role="alert" className="text-sm text-destructive">
          Could not load your agents or channel permissions. Reopen this dialog
          to try again.
        </p>
      ) : null}
      {notice ? (
        <p role="status" className="text-sm">
          {notice}
        </p>
      ) : null}
      {errors.length ? (
        <p role="alert" className="text-sm text-destructive">
          {errors.join(" ")}
        </p>
      ) : null}
    </section>
  );
}

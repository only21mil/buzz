import { useChannelsQuery } from "@/features/channels/hooks";
import { Button } from "@/shared/ui/button";
import { useManagedAgentsQuery } from "../hooks";
import { durableDraftStore } from "../durableDraftQueue";
import { useDurableDraftQueue } from "../useDurableDraftQueue";
import {
  draftStatusLabel,
  draftUnavailableReason,
} from "../durableDraftReview";

/** Queue and agent detail both render the same request event and retained operation. */
export function DurableDraftQueue({
  agentPubkey,
  personaId,
  personaName,
}: {
  agentPubkey?: string;
  personaId?: string;
  personaName?: string;
}) {
  const queue = useDurableDraftQueue();
  const agents = useManagedAgentsQuery();
  const channels = useChannelsQuery();
  if (!queue.scope) return null;
  const detail = agentPubkey !== undefined || personaId !== undefined;
  const items = detail
    ? queue.items.filter(
        (item) =>
          item.event.pubkey === agentPubkey ||
          (personaId !== undefined && item.operation?.targetId === personaId) ||
          (item.request?.action === "update" &&
            personaName !== undefined &&
            item.request.request.agentName.trim().toLocaleLowerCase() ===
              personaName.trim().toLocaleLowerCase()),
      )
    : queue.items;
  if (detail && items.length === 0) return null;
  return (
    <section
      aria-label="Agent draft reviews"
      className="max-h-64 shrink-0 space-y-2 overflow-y-auto border-b p-4"
    >
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-sm font-medium">Draft reviews ({items.length})</h2>
        <Button
          onClick={() => {
            void durableDraftStore.refresh();
          }}
          size="sm"
          variant="ghost"
        >
          Refresh
        </Button>
      </div>
      {!queue.ready ? (
        <p className="text-xs text-muted-foreground">
          {queue.error ??
            "Syncing or offline. Retained drafts remain available to inspect."}
        </p>
      ) : null}
      {items.length === 0 ? (
        <p className="text-xs text-muted-foreground">No agent drafts.</p>
      ) : null}
      {items.map((item) => {
        const request = item.request;
        const name =
          request?.action === "create"
            ? request.request.displayName
            : (request?.request.agentName ?? "Unavailable draft");
        const unavailable = draftUnavailableReason(
          item,
          agents.data,
          channels.data,
        );
        return (
          <button
            className="block w-full rounded-md border p-3 text-left hover:bg-muted/30"
            data-request-event-id={item.event.id}
            key={item.event.id}
            onClick={() => {
              if (queue.scope)
                durableDraftStore.select(queue.scope, item.event.id);
            }}
            type="button"
          >
            <span className="block text-sm font-medium">{name}</span>
            <span className="block text-xs text-muted-foreground">
              {draftStatusLabel(item)}
            </span>
            {unavailable ? (
              <span className="block text-xs text-muted-foreground">
                {unavailable}
              </span>
            ) : null}
          </button>
        );
      })}
    </section>
  );
}

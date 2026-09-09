import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { channelsQueryKey, useChannelsQuery } from "@/features/channels/hooks";
import {
  agentDraftApply,
  agentDraftConfirm,
  agentDraftPrepare,
  type DraftAction,
  type DraftScope,
} from "@/shared/api/tauriAgentDrafts";
import type {
  AgentPersona,
  Channel,
  CreatePersonaInput,
  ManagedAgent,
  UpdatePersonaInput,
} from "@/shared/api/types";
import { Button } from "@/shared/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import {
  createInputFromRequest,
  requestTargetsEditablePersona,
} from "../agentManagement";
import {
  durableDraftStore,
  sameDraftScope,
  type DurableDraftItem,
} from "../durableDraftQueue";
import {
  draftCanResume,
  draftStatusLabel,
  draftUnavailableReason,
} from "../durableDraftReview";
import { submitDurableDraft } from "../durableDraftSubmission";
import {
  managedAgentsQueryKey,
  personasQueryKey,
  useAcpRuntimesQuery,
  useManagedAgentsQuery,
  usePersonasQuery,
} from "../hooks";
import { availableRuntimesForStart } from "../lib/instanceInputForDefinition";
import { runLocationForRunOn } from "../lib/agentAccessWarning";
import { useDurableDraftQueue } from "../useDurableDraftQueue";
import { updateInputFromRequest } from "../useAgentManagement";
import { AgentDefinitionDialog } from "./AgentDefinitionDialog";
import { AgentRunLocationProvider } from "./AgentRunLocationContext";
import { editPersonaDialogState } from "./personaDialogState";
import { WhereToRunSection } from "./WhereToRunSection";
import {
  canSubmitWhereToRun,
  emptyWhereToRunDraft,
  resolveBackendIntent,
} from "./whereToRunIntent";

/** Opening, closing and reconnecting inspect retained state without applying it. */
export function DurableDraftReviewDialog() {
  const queue = useDurableDraftQueue();
  const item = queue.items.find(
    (candidate) => candidate.event.id === queue.selectedId,
  );
  if (!queue.scope || !item) return null;
  return (
    <DraftReview
      item={item}
      key={`${queue.scope.owner}:${queue.scope.relayUrl}:${item.event.id}`}
      scope={queue.scope}
    />
  );
}

function DraftReview({
  item,
  scope,
}: {
  item: DurableDraftItem;
  scope: DraftScope;
}) {
  const queryClient = useQueryClient();
  const personas = usePersonasQuery();
  const agents = useManagedAgentsQuery();
  const channels = useChannelsQuery();
  const runtimes = useAcpRuntimesQuery({ enabled: true });
  const queue = useDurableDraftQueue();
  const [action, setAction] = React.useState<Exclude<
    DraftAction,
    "reject"
  > | null>(null);
  const [reviewed, setReviewed] = React.useState<AgentPersona | null>(null);
  const [pending, setPending] = React.useState(false);
  const submitting = React.useRef(false);
  const [error, setError] = React.useState<string | null>(null);
  const [runDraft, setRunDraft] = React.useState(emptyWhereToRunDraft);
  const currentScope = React.useRef(queue.scope);
  const reviewEpoch = React.useRef(durableDraftStore.getEpoch());
  currentScope.current = queue.scope;
  React.useEffect(() => {
    currentScope.current = scope;
    return () => {
      currentScope.current = null;
    };
  }, [scope]);
  const request = item.request;
  const unavailable = draftUnavailableReason(item, agents.data, channels.data);
  const terminal = item.decision !== null || item.operation !== null;
  const canReview = queue.ready && !unavailable && !terminal && !pending;
  const close = () => {
    if (
      !submitting.current &&
      sameDraftScope(scope, currentScope.current) &&
      reviewEpoch.current === durableDraftStore.getEpoch()
    )
      durableDraftStore.select(scope, null);
  };
  const matches =
    request?.action === "update"
      ? (personas.data ?? []).filter(
          (persona) =>
            requestTargetsEditablePersona(persona) &&
            persona.displayName.trim().toLocaleLowerCase() ===
              request.request.agentName.trim().toLocaleLowerCase(),
        )
      : [];
  const targetError =
    request?.action === "update" && matches.length !== 1
      ? "This draft must match exactly one editable personal agent by its current name."
      : null;

  function assertReviewCurrent() {
    if (
      !sameDraftScope(scope, currentScope.current) ||
      reviewEpoch.current !== durableDraftStore.getEpoch()
    )
      throw new Error("The review owner or community changed.");
    return durableDraftStore.assertCurrent(
      scope,
      item.event.id,
      true,
      reviewEpoch.current,
    );
  }

  function assertAvailable(fresh = true, reject = false) {
    const current = assertReviewCurrent();
    const reason = draftUnavailableReason(
      current,
      queryClient.getQueryData<ManagedAgent[]>(managedAgentsQueryKey),
      queryClient.getQueryData<Channel[]>(channelsQueryKey),
    );
    if (reason && !reject) throw new Error(reason);
    if (fresh && (current.decision || current.operation))
      throw new Error(
        "This draft already has a retained decision. Inspect its result before continuing.",
      );
    return current;
  }

  function begin(next: Exclude<DraftAction, "reject">) {
    try {
      assertAvailable();
      if (targetError) throw new Error(targetError);
      setReviewed(matches.length === 1 ? structuredClone(matches[0]) : null);
      setError(null);
      setAction(next);
    } catch (cause) {
      setError(String(cause instanceof Error ? cause.message : cause));
    }
  }

  async function run(work: () => Promise<void>): Promise<boolean> {
    if (submitting.current) return false;
    submitting.current = true;
    setPending(true);
    setError(null);
    try {
      await work();
      await durableDraftStore.refresh();
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: personasQueryKey }),
        queryClient.invalidateQueries({ queryKey: managedAgentsQueryKey }),
      ]);
      setAction(null);
      return true;
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Could not complete this draft action.",
      );
      await durableDraftStore.refresh();
      return false;
    } finally {
      submitting.current = false;
      setPending(false);
    }
  }

  const initialValues = React.useMemo(() => {
    if (request?.action === "create") return createInputFromRequest(request);
    if (request?.action === "update" && reviewed)
      return updateInputFromRequest(
        request,
        editPersonaDialogState(reviewed).initialValues as UpdatePersonaInput,
      );
    return null;
  }, [request, reviewed]);

  async function submit(input: CreatePersonaInput | UpdatePersonaInput) {
    if (!action || !request) return false;
    return run(async () => {
      if (
        (action === "create" || action === "start") &&
        !canSubmitWhereToRun(runDraft)
      )
        throw new Error("Choose where this agent should run.");
      await submitDurableDraft({
        scope,
        requestEventId: item.event.id,
        request,
        action,
        input,
        reviewed,
        backend: resolveBackendIntent(runDraft),
        currentPersona: () =>
          queryClient
            .getQueryData<AgentPersona[]>(personasQueryKey)
            ?.find((persona) => persona.id === reviewed?.id),
        availableRuntimes: () => availableRuntimesForStart(runtimes),
        assertAvailable,
        assertCurrent: assertReviewCurrent,
      });
    });
  }

  const label =
    action === "start"
      ? "Save and start now"
      : action === "create"
        ? "Save and create stopped"
        : reviewed?.shared
          ? "Save and publish changes"
          : "Save definition";
  if (action && initialValues)
    return (
      <AgentRunLocationProvider
        runLocation={runLocationForRunOn(runDraft.runOn)}
      >
        <AgentDefinitionDialog
          createRunSection={
            action === "create" || action === "start" ? (
              <WhereToRunSection
                draft={runDraft}
                isPending={pending}
                onDraftChange={setRunDraft}
              />
            ) : undefined
          }
          createSubmitBlocked={
            !queue.ready ||
            Boolean(unavailable) ||
            terminal ||
            ((action === "create" || action === "start") &&
              !canSubmitWhereToRun(runDraft))
          }
          description={
            action === "start"
              ? "Review this definition and run location before starting one instance and adding it to the originating channel."
              : action === "create"
                ? "Create one stopped instance. It will not start when the app opens."
                : reviewed?.shared
                  ? "Saving also publishes these reviewed changes to the community catalog."
                  : "Save this definition for later use."
          }
          error={error ? new Error(error) : null}
          initialValues={initialValues}
          isPending={pending}
          onOpenChange={(open) => {
            if (!open) close();
          }}
          onSubmit={submit}
          open
          runtimes={runtimes.data ?? []}
          runtimeCatalogStatus={
            runtimes.isLoading
              ? "loading"
              : runtimes.isError
                ? "error"
                : "ready"
          }
          submitLabel={label}
          title="Review agent draft"
        />
      </AgentRunLocationProvider>
    );
  return (
    <Dialog
      onOpenChange={(open) => {
        if (!open) close();
      }}
      open
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Agent draft review</DialogTitle>
          <DialogDescription>{draftStatusLabel(item)}</DialogDescription>
        </DialogHeader>
        <div className="max-h-72 space-y-3 overflow-y-auto">
          {request ? (
            <>
              <p className="font-medium">
                {request.action === "create"
                  ? request.request.displayName
                  : request.request.agentName}
              </p>
              <p className="text-xs text-muted-foreground">
                Requested from{" "}
                {channels.data?.find(
                  (channel) => channel.id === request.request.channelId,
                )?.name ?? "the originating channel"}
              </p>
              {request.request.systemPrompt ? (
                <p className="whitespace-pre-wrap break-words text-sm">
                  {request.request.systemPrompt}
                </p>
              ) : null}
              {request.action === "update" ? (
                <dl className="text-sm">
                  {Object.entries(request.request)
                    .filter(
                      ([field]) =>
                        !["channelId", "agentName", "systemPrompt"].includes(
                          field,
                        ),
                    )
                    .map(([field, value]) => (
                      <div className="flex gap-2" key={field}>
                        <dt>
                          {
                            (
                              {
                                displayName: "Name",
                                runtime: "Runtime",
                                provider: "Provider",
                                model: "Model",
                                respondTo: "Respond to",
                              } as Record<string, string>
                            )[field]
                          }
                        </dt>
                        <dd>{value}</dd>
                      </div>
                    ))}
                </dl>
              ) : null}
            </>
          ) : null}
          {item.operation ? (
            <div className="space-y-2 border-t pt-3">
              <p className="text-sm font-medium">
                Retained approval: {item.operation.action}
                {item.operation.publishShared
                  ? " and publish to the community catalog"
                  : ""}
              </p>
              {item.operation.input ? (
                <>
                  <p className="text-sm">{item.operation.input.displayName}</p>
                  <p className="whitespace-pre-wrap text-sm">
                    {item.operation.input.systemPrompt}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {[
                      item.operation.input.runtime,
                      item.operation.input.provider,
                      item.operation.input.model,
                    ]
                      .filter(Boolean)
                      .join(" / ")}
                  </p>
                </>
              ) : null}
              {item.operation.instanceInput ? (
                <p className="text-xs text-muted-foreground">
                  Run location:{" "}
                  {item.operation.instanceInput.backend?.type === "provider"
                    ? item.operation.instanceInput.backend.id
                    : "This device"}
                </p>
              ) : null}
            </div>
          ) : null}
          {unavailable ? (
            <p className="text-sm text-muted-foreground">{unavailable}</p>
          ) : null}
          {targetError ? (
            <p className="text-sm text-muted-foreground">{targetError}</p>
          ) : null}
          {!queue.ready ? (
            <p className="text-sm text-muted-foreground">
              {queue.error ?? "Reconnect and sync before deciding this draft."}
            </p>
          ) : null}
          {error || item.operation?.error ? (
            <p className="text-sm text-destructive" role="alert">
              {error ?? item.operation?.error}
            </p>
          ) : null}
        </div>
        <div className="flex flex-wrap gap-2">
          <Button
            disabled={!canReview || Boolean(targetError)}
            onClick={() => begin("save")}
          >
            Review and save
          </Button>
          {request?.action === "create" ? (
            <>
              <Button
                disabled={!canReview}
                onClick={() => begin("create")}
                variant="outline"
              >
                Review and create
              </Button>
              <Button
                disabled={!canReview}
                onClick={() => begin("start")}
                variant="outline"
              >
                Review and start
              </Button>
            </>
          ) : null}
          <Button
            disabled={!queue.ready || terminal || pending}
            onClick={() => {
              void run(async () => {
                assertAvailable(true, true);
                await agentDraftPrepare({
                  ...scope,
                  requestEventId: item.event.id,
                  action: "reject",
                  input: null,
                  expectedContent: null,
                  instanceInput: null,
                  publishShared: false,
                });
                assertReviewCurrent();
                await agentDraftApply(scope, item.event.id);
              });
            }}
            variant="outline"
          >
            Reject
          </Button>
          {item.operation && draftCanResume(item) ? (
            <Button
              disabled={
                !queue.ready ||
                pending ||
                (item.operation.action !== "reject" && Boolean(unavailable))
              }
              onClick={() => {
                void run(async () => {
                  const current = assertAvailable(
                    false,
                    item.operation?.action === "reject",
                  );
                  if (!draftCanResume(current))
                    throw new Error(
                      "This operation already has a terminal owner decision.",
                    );
                  if (current.operation?.state === "saved")
                    await agentDraftConfirm(scope, item.event.id);
                  else if (
                    current.operation?.state === "prepared" ||
                    current.operation?.state === "claimed"
                  )
                    await agentDraftApply(scope, item.event.id);
                  else
                    throw new Error(
                      "This operation changed. Reopen its retained result.",
                    );
                });
              }}
              variant="outline"
            >
              {item.operation.state === "saved"
                ? "Retry retained publication"
                : "Complete approved action"}
            </Button>
          ) : null}
          <Button disabled={pending} onClick={close} variant="ghost">
            Close
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

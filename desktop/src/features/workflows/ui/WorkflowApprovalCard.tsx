import type { WorkflowApproval } from "@/shared/api/types";

export function WorkflowApprovalCard({
  approval,
}: {
  approval: WorkflowApproval;
}) {
  return (
    <div
      className="rounded-lg border border-border bg-muted/20 p-3"
      data-testid="workflow-approval-card"
    >
      <p className="mb-2 text-sm font-medium">Approval: {approval.status}</p>
      <p className="text-xs text-muted-foreground">
        Approver: {approval.approverSpec}
      </p>
      <p className="text-xs text-muted-foreground">
        Expires: {new Date(approval.expiresAt).toLocaleString()}
      </p>
      {approval.note ? <p className="mt-2 text-xs">{approval.note}</p> : null}
      {approval.status === "pending" ? (
        <p className="mt-2 text-xs text-muted-foreground">
          Respond using the signed approval request.
        </p>
      ) : null}
    </div>
  );
}

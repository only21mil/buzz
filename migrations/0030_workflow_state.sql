-- Workflow-scoped durable state. Revisions advance in the write transaction
-- for each row; there is deliberately no global sequence. The incarnation
-- changes if an expired key is deleted and later recreated, preventing ABA in
-- the public <incarnation>:<revision> compare-and-swap token.
CREATE TABLE workflow_state (
    community_id      UUID NOT NULL REFERENCES communities(id),
    workflow_id       UUID NOT NULL,
    state_key         TEXT NOT NULL CHECK (octet_length(state_key) BETWEEN 1 AND 512),
    value             TEXT NOT NULL CHECK (octet_length(value) <= 65536),
    state_incarnation UUID NOT NULL DEFAULT gen_random_uuid(),
    revision          BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    expires_at        TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (community_id, workflow_id, state_key),
    FOREIGN KEY (community_id, workflow_id)
        REFERENCES workflows (community_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_workflow_state_expires_at ON workflow_state (expires_at);

-- One immutable execution result per run step. Migration 0029 adds the
-- workflow_runs (community_id, id, workflow_id) unique key used below, binding
-- each receipt's tenant, run, and workflow as one database invariant.
CREATE TABLE workflow_state_receipts (
    community_id UUID NOT NULL REFERENCES communities(id),
    workflow_id  UUID NOT NULL,
    run_id       UUID NOT NULL,
    step_id      VARCHAR(64) NOT NULL,
    request_hash BYTEA NOT NULL CHECK (octet_length(request_hash) = 32),
    result       JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (community_id, run_id, step_id),
    FOREIGN KEY (community_id, workflow_id)
        REFERENCES workflows (community_id, id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, run_id, workflow_id)
        REFERENCES workflow_runs (community_id, id, workflow_id) ON DELETE CASCADE
);

CREATE FUNCTION reject_workflow_state_receipt_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'workflow state receipts are immutable';
END;
$$;

CREATE TRIGGER workflow_state_receipt_immutable
BEFORE UPDATE ON workflow_state_receipts
FOR EACH ROW
EXECUTE FUNCTION reject_workflow_state_receipt_update();

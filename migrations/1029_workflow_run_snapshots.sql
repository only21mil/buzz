-- Persist the workflow definition used to create each run. Existing runs
-- inherit the current definition before the snapshot columns become required.
ALTER TABLE workflow_runs
    ADD COLUMN definition_snapshot JSONB,
    ADD COLUMN definition_hash BYTEA,
    ADD COLUMN generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0);

UPDATE workflow_runs AS run
SET definition_snapshot = workflow.definition,
    definition_hash = workflow.definition_hash
FROM workflows AS workflow
WHERE workflow.community_id = run.community_id
  AND workflow.id = run.workflow_id;

ALTER TABLE workflow_runs
    ALTER COLUMN definition_snapshot SET NOT NULL,
    ALTER COLUMN definition_hash SET NOT NULL,
    ADD CONSTRAINT workflow_runs_definition_hash_length
        CHECK (octet_length(definition_hash) = 32),
    ADD CONSTRAINT workflow_runs_community_id_id_workflow_id_key
        UNIQUE (community_id, id, workflow_id);

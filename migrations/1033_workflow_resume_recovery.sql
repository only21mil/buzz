-- Durable leases let the relay reclaim approval continuations after a process
-- exits without allowing a stale executor to finalize a newer generation.
ALTER TABLE workflow_runs
    ADD COLUMN resume_lease_expires_at TIMESTAMPTZ;

-- A relay restart makes every pre-migration continuation executor stale. Mark
-- granted runs that were already claimed as immediately reclaimable. Ordinary
-- running workflows have no granted gate and remain outside this worker.
UPDATE workflow_runs AS run
SET resume_lease_expires_at = '-infinity'::timestamptz
WHERE run.status = 'running'
  AND EXISTS (
      SELECT 1
      FROM workflow_approval_gates AS gate
      WHERE gate.community_id = run.community_id
        AND gate.run_id = run.id
        AND gate.status = 'granted'
        AND gate.deleted_at IS NULL
  );

ALTER TABLE workflow_runs
    ADD CONSTRAINT workflow_runs_resume_lease_running
        CHECK (resume_lease_expires_at IS NULL OR status = 'running');

CREATE INDEX idx_workflow_runs_resume_lease_recovery
    ON workflow_runs (resume_lease_expires_at, community_id, id)
    WHERE status = 'running' AND resume_lease_expires_at IS NOT NULL;

CREATE INDEX idx_workflow_approval_gates_resume_recovery
    ON workflow_approval_gates (decided_at, community_id, run_id)
    WHERE status = 'granted' AND deleted_at IS NULL;

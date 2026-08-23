-- Approval gates persist the exact resume point and prior outputs in the run.
-- Existing traces are converted once; future resume code must read step_outputs
-- directly rather than treating the display trace as executable state.
ALTER TYPE run_status ADD VALUE 'resume_pending' AFTER 'waiting_approval';

ALTER TABLE workflow_runs
    ADD COLUMN next_step INTEGER NOT NULL DEFAULT 0 CHECK (next_step >= 0),
    ADD COLUMN step_outputs JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(step_outputs) = 'object');

UPDATE workflow_runs AS run
SET step_outputs = COALESCE(
    (
        SELECT jsonb_object_agg(entry->>'step_id', entry->'output')
        FROM jsonb_array_elements(run.execution_trace) AS entry
        WHERE jsonb_typeof(entry) = 'object'
          AND entry ? 'step_id'
          AND entry ? 'output'
    ),
    '{}'::jsonb
),
next_step = GREATEST(run.current_step, 0);

UPDATE workflow_runs AS run
SET next_step = approval.next_step
FROM (
    SELECT community_id, run_id, MAX(step_index) + 1 AS next_step
    FROM workflow_approvals
    GROUP BY community_id, run_id
) AS approval
WHERE run.community_id = approval.community_id
  AND run.id = approval.run_id
  AND run.status = 'waiting_approval';

-- Bind every approval to the frozen run definition and generation with one FK.
ALTER TABLE workflow_runs
    ADD CONSTRAINT workflow_runs_approval_binding_key
        UNIQUE (community_id, id, workflow_id, definition_hash, generation);

-- Replace the legacy token-hash authority table. The old enum is renamed so
-- the replacement type can add unsatisfiable without using a freshly added
-- enum value in the same transaction.
ALTER TABLE workflow_approvals RENAME TO workflow_approvals_legacy_0031;
ALTER TABLE workflow_approvals_legacy_0031
    RENAME CONSTRAINT workflow_approvals_pkey
    TO workflow_approvals_legacy_0031_pkey;
ALTER INDEX idx_workflow_approvals_workflow
    RENAME TO idx_workflow_approvals_legacy_0031_workflow;
ALTER INDEX idx_workflow_approvals_run
    RENAME TO idx_workflow_approvals_legacy_0031_run;
ALTER INDEX idx_workflow_approvals_status
    RENAME TO idx_workflow_approvals_legacy_0031_status;

ALTER TYPE approval_status RENAME TO approval_status_legacy_0031;
CREATE TYPE approval_status AS ENUM
    ('pending', 'granted', 'denied', 'expired', 'unsatisfiable');

-- A legacy approval has no stored channel. Recover it from the workflow or run
-- trigger context, but never invent an audit binding when neither is valid.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM workflow_approvals_legacy_0031 AS approval
        JOIN workflows AS workflow
          ON workflow.community_id = approval.community_id
         AND workflow.id = approval.workflow_id
        JOIN workflow_runs AS run
          ON run.community_id = approval.community_id
         AND run.id = approval.run_id
         AND run.workflow_id = approval.workflow_id
        LEFT JOIN channels AS channel
          ON channel.community_id = approval.community_id
         AND channel.id = COALESCE(
             workflow.channel_id,
             CASE
                 WHEN run.trigger_context->>'channel_id' ~
                     '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
                 THEN (run.trigger_context->>'channel_id')::uuid
             END
         )
        WHERE channel.id IS NULL
    ) THEN
        RAISE EXCEPTION
            'workflow approval migration blocked: legacy approval has no valid channel binding';
    END IF;
END;
$$;

CREATE TABLE workflow_approvals (
    community_id UUID NOT NULL REFERENCES communities(id),
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    channel_id UUID NOT NULL,
    workflow_id UUID NOT NULL,
    run_id UUID NOT NULL,
    definition_hash BYTEA NOT NULL CHECK (octet_length(definition_hash) = 32),
    step_id VARCHAR(64) NOT NULL CHECK (octet_length(step_id) BETWEEN 1 AND 64),
    step_index INTEGER NOT NULL CHECK (step_index >= 0),
    generation BIGINT NOT NULL CHECK (generation > 0),
    policy_snapshot JSONB NOT NULL CHECK (jsonb_typeof(policy_snapshot) = 'object'),
    resolved_approver_set JSONB NOT NULL
        CHECK (jsonb_typeof(resolved_approver_set) = 'object'),
    status approval_status NOT NULL DEFAULT 'pending',
    decision_actor_pubkey BYTEA
        CHECK (decision_actor_pubkey IS NULL OR octet_length(decision_actor_pubkey) = 32),
    decision_actor_role member_role,
    decision_actor_kind TEXT
        CHECK (decision_actor_kind IS NULL OR decision_actor_kind IN ('human', 'agent', 'bot', 'unknown')),
    actor_is_definition_owner BOOLEAN,
    matched_policy JSONB CHECK (matched_policy IS NULL OR jsonb_typeof(matched_policy) = 'object'),
    note TEXT CHECK (note IS NULL OR octet_length(note) BETWEEN 1 AND 2000),
    request_event_id BYTEA
        CHECK (request_event_id IS NULL OR octet_length(request_event_id) = 32),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decision_event_id BYTEA
        CHECK (decision_event_id IS NULL OR octet_length(decision_event_id) = 32),
    decided_at TIMESTAMPTZ,
    resolved_event_id BYTEA
        CHECK (resolved_event_id IS NULL OR octet_length(resolved_event_id) = 32),
    resolved_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    PRIMARY KEY (community_id, id),
    UNIQUE (community_id, run_id, step_index),
    CONSTRAINT workflow_approvals_channel_fkey
        FOREIGN KEY (community_id, channel_id)
        REFERENCES channels (community_id, id) ON DELETE NO ACTION,
    CONSTRAINT workflow_approvals_workflow_fkey
        FOREIGN KEY (community_id, workflow_id)
        REFERENCES workflows (community_id, id) ON DELETE NO ACTION,
    CONSTRAINT workflow_approvals_run_binding_fkey
        FOREIGN KEY (community_id, run_id, workflow_id, definition_hash, generation)
        REFERENCES workflow_runs
            (community_id, id, workflow_id, definition_hash, generation)
        ON DELETE NO ACTION,
    CONSTRAINT workflow_approvals_actor_snapshot_complete
        CHECK (
            (decision_actor_pubkey IS NULL
                AND decision_actor_role IS NULL
                AND decision_actor_kind IS NULL
                AND actor_is_definition_owner IS NULL
                AND matched_policy IS NULL)
            OR
            (decision_actor_pubkey IS NOT NULL
                AND decision_actor_kind IS NOT NULL
                AND actor_is_definition_owner IS NOT NULL
                AND matched_policy IS NOT NULL)
        ),
    CONSTRAINT workflow_approvals_denial_note_required
        CHECK (status <> 'denied' OR note IS NOT NULL),
    CONSTRAINT workflow_approvals_terminal_timestamp
        CHECK ((status = 'pending' AND resolved_at IS NULL)
            OR (status <> 'pending' AND resolved_at IS NOT NULL))
);

INSERT INTO workflow_approvals (
    community_id, id, channel_id, workflow_id, run_id, definition_hash,
    step_id, step_index, generation, policy_snapshot,
    resolved_approver_set, status, decision_actor_pubkey,
    decision_actor_kind, actor_is_definition_owner, matched_policy, note,
    requested_at, decided_at, resolved_at, expires_at, created_at
)
SELECT
    approval.community_id,
    gen_random_uuid(),
    channel.id,
    approval.workflow_id,
    approval.run_id,
    run.definition_hash,
    approval.step_id,
    approval.step_index,
    run.generation,
    policy.snapshot,
    jsonb_build_object(
        'pubkeys', resolved.pubkeys,
        'roles', CASE
            WHEN policy.role_name IS NULL THEN '[]'::jsonb
            ELSE jsonb_build_array(policy.role_name)
        END
    ),
    CASE
        WHEN approval.status::text = 'pending'
             AND (policy.policy_type = 'unsatisfiable'
                  OR jsonb_array_length(resolved.pubkeys) = 0)
            THEN 'unsatisfiable'::approval_status
        ELSE approval.status::text::approval_status
    END,
    approval.approver_pubkey,
    CASE WHEN approval.approver_pubkey IS NULL THEN NULL ELSE 'unknown' END,
    CASE
        WHEN approval.approver_pubkey IS NULL THEN NULL
        ELSE approval.approver_pubkey = workflow.owner_pubkey
    END,
    CASE WHEN approval.approver_pubkey IS NULL THEN NULL ELSE policy.snapshot END,
    CASE
        WHEN approval.status::text = 'denied'
             AND (approval.note IS NULL OR btrim(approval.note) = '')
            THEN 'Legacy denial did not retain a note'
        WHEN approval.note IS NOT NULL AND octet_length(approval.note) > 2000
            THEN left(approval.note, 500)
        ELSE approval.note
    END,
    approval.created_at,
    CASE approval.status::text
        WHEN 'granted' THEN COALESCE(approval.granted_at, approval.created_at)
        WHEN 'denied' THEN COALESCE(approval.denied_at, approval.created_at)
        ELSE NULL
    END,
    CASE
        WHEN approval.status::text = 'pending'
             AND policy.policy_type <> 'unsatisfiable'
             AND jsonb_array_length(resolved.pubkeys) > 0
            THEN NULL
        WHEN approval.status::text = 'granted'
            THEN COALESCE(approval.granted_at, approval.created_at)
        WHEN approval.status::text = 'denied'
            THEN COALESCE(approval.denied_at, approval.created_at)
        WHEN approval.status::text = 'expired' THEN approval.expires_at
        ELSE now()
    END,
    approval.expires_at,
    approval.created_at
FROM workflow_approvals_legacy_0031 AS approval
JOIN workflows AS workflow
  ON workflow.community_id = approval.community_id
 AND workflow.id = approval.workflow_id
JOIN workflow_runs AS run
  ON run.community_id = approval.community_id
 AND run.id = approval.run_id
 AND run.workflow_id = approval.workflow_id
JOIN channels AS channel
  ON channel.community_id = approval.community_id
 AND channel.id = COALESCE(
     workflow.channel_id,
     CASE
         WHEN run.trigger_context->>'channel_id' ~
             '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
         THEN (run.trigger_context->>'channel_id')::uuid
     END
 )
CROSS JOIN LATERAL (
    SELECT
        CASE
            WHEN approval.approver_spec ~ '^[0-9a-fA-F]{64}$' THEN 'pubkey'
            WHEN lower(btrim(approval.approver_spec)) IN ('owner', 'admin') THEN 'role'
            ELSE 'unsatisfiable'
        END AS policy_type,
        CASE
            WHEN lower(btrim(approval.approver_spec)) IN ('owner', 'admin')
                THEN lower(btrim(approval.approver_spec))
        END AS role_name,
        CASE
            WHEN approval.approver_spec ~ '^[0-9a-fA-F]{64}$'
                THEN jsonb_build_object(
                    'type', 'pubkey', 'pubkey', lower(approval.approver_spec))
            WHEN lower(btrim(approval.approver_spec)) IN ('owner', 'admin')
                THEN jsonb_build_object(
                    'type', 'role', 'role', lower(btrim(approval.approver_spec)))
            ELSE jsonb_build_object(
                'type', 'unsatisfiable', 'reason', 'legacy_policy_unsupported')
        END AS snapshot
) AS policy
CROSS JOIN LATERAL (
    SELECT COALESCE(
        jsonb_agg(encode(member.pubkey, 'hex') ORDER BY member.pubkey),
        '[]'::jsonb
    ) AS pubkeys
    FROM channel_members AS member
    WHERE member.community_id = approval.community_id
      AND member.channel_id = channel.id
      AND member.removed_at IS NULL
      AND (
          (policy.policy_type = 'pubkey'
              AND encode(member.pubkey, 'hex') = lower(approval.approver_spec))
          OR
          (policy.policy_type = 'role'
              AND member.role::text = policy.role_name)
      )
) AS resolved;

DROP TABLE workflow_approvals_legacy_0031;
DROP TYPE approval_status_legacy_0031;

CREATE INDEX idx_workflow_approvals_workflow
    ON workflow_approvals (community_id, workflow_id);
CREATE INDEX idx_workflow_approvals_run
    ON workflow_approvals (community_id, run_id);
CREATE INDEX idx_workflow_approvals_status
    ON workflow_approvals (community_id, status) WHERE deleted_at IS NULL;

-- Gate identity, frozen policy, and recorded evidence never change. A decision
-- may fill previously-null evidence once, and a terminal decision cannot reopen.
CREATE FUNCTION enforce_workflow_approval_history()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'workflow approval history cannot be deleted';
    END IF;

    IF NEW.community_id IS DISTINCT FROM OLD.community_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.channel_id IS DISTINCT FROM OLD.channel_id
       OR NEW.workflow_id IS DISTINCT FROM OLD.workflow_id
       OR NEW.run_id IS DISTINCT FROM OLD.run_id
       OR NEW.definition_hash IS DISTINCT FROM OLD.definition_hash
       OR NEW.step_id IS DISTINCT FROM OLD.step_id
       OR NEW.step_index IS DISTINCT FROM OLD.step_index
       OR NEW.generation IS DISTINCT FROM OLD.generation
       OR NEW.policy_snapshot IS DISTINCT FROM OLD.policy_snapshot
       OR NEW.resolved_approver_set IS DISTINCT FROM OLD.resolved_approver_set
       OR NEW.requested_at IS DISTINCT FROM OLD.requested_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'workflow approval identity and policy are immutable';
    END IF;

    IF OLD.status <> 'pending' AND NEW.status IS DISTINCT FROM OLD.status THEN
        RAISE EXCEPTION 'terminal workflow approval cannot change status';
    END IF;
    IF OLD.status = 'pending'
       AND NEW.status NOT IN ('pending', 'granted', 'denied', 'expired', 'unsatisfiable') THEN
        RAISE EXCEPTION 'invalid workflow approval transition';
    END IF;

    IF OLD.request_event_id IS NOT NULL
       AND NEW.request_event_id IS DISTINCT FROM OLD.request_event_id THEN
        RAISE EXCEPTION 'workflow approval request evidence is immutable';
    END IF;
    IF OLD.decision_actor_pubkey IS NOT NULL
       AND (NEW.decision_actor_pubkey IS DISTINCT FROM OLD.decision_actor_pubkey
            OR NEW.decision_actor_role IS DISTINCT FROM OLD.decision_actor_role
            OR NEW.decision_actor_kind IS DISTINCT FROM OLD.decision_actor_kind
            OR NEW.actor_is_definition_owner IS DISTINCT FROM OLD.actor_is_definition_owner
            OR NEW.matched_policy IS DISTINCT FROM OLD.matched_policy
            OR NEW.decision_event_id IS DISTINCT FROM OLD.decision_event_id
            OR NEW.decided_at IS DISTINCT FROM OLD.decided_at
            OR NEW.note IS DISTINCT FROM OLD.note) THEN
        RAISE EXCEPTION 'workflow approval decision evidence is immutable';
    END IF;
    IF OLD.resolved_event_id IS NOT NULL
       AND NEW.resolved_event_id IS DISTINCT FROM OLD.resolved_event_id THEN
        RAISE EXCEPTION 'workflow approval resolution evidence is immutable';
    END IF;
    IF OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN
        RAISE EXCEPTION 'workflow approval deletion timestamp is immutable';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER workflow_approval_history_update
BEFORE UPDATE ON workflow_approvals
FOR EACH ROW
EXECUTE FUNCTION enforce_workflow_approval_history();

CREATE TRIGGER workflow_approval_history_delete
BEFORE DELETE ON workflow_approvals
FOR EACH ROW
EXECUTE FUNCTION enforce_workflow_approval_history();

-- Lifecycle classes are semantic names. Nostr kind numbers belong in the
-- publisher, not in durable transactional state.
CREATE TABLE workflow_approval_outbox (
    community_id UUID NOT NULL REFERENCES communities(id),
    id BIGINT GENERATED ALWAYS AS IDENTITY,
    approval_id UUID NOT NULL,
    class TEXT NOT NULL CHECK (class IN (
        'approval_requested',
        'approval_granted',
        'approval_denied',
        'approval_expired',
        'approval_unsatisfiable',
        'workflow_resume_pending',
        'workflow_cancelled',
        'workflow_failed'
    )),
    payload_version SMALLINT NOT NULL DEFAULT 1 CHECK (payload_version > 0),
    payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    dedupe_key VARCHAR(255) NOT NULL CHECK (octet_length(dedupe_key) BETWEEN 1 AND 255),
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'publishing', 'published', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_owner TEXT CHECK (lease_owner IS NULL OR octet_length(lease_owner) BETWEEN 1 AND 255),
    lease_expires_at TIMESTAMPTZ,
    last_error TEXT CHECK (last_error IS NULL OR octet_length(last_error) <= 2000),
    published_event_id BYTEA
        CHECK (published_event_id IS NULL OR octet_length(published_event_id) = 32),
    published_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (community_id, id),
    UNIQUE (community_id, dedupe_key),
    CONSTRAINT workflow_approval_outbox_approval_fkey
        FOREIGN KEY (community_id, approval_id)
        REFERENCES workflow_approvals (community_id, id) ON DELETE NO ACTION,
    CONSTRAINT workflow_approval_outbox_lease_complete
        CHECK ((lease_owner IS NULL AND lease_expires_at IS NULL)
            OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CONSTRAINT workflow_approval_outbox_publish_complete
        CHECK ((state = 'published' AND published_event_id IS NOT NULL AND published_at IS NOT NULL)
            OR (state <> 'published' AND published_at IS NULL))
);

CREATE INDEX idx_workflow_approval_outbox_due
    ON workflow_approval_outbox (community_id, next_attempt_at, id)
    WHERE state = 'pending';
CREATE INDEX idx_workflow_approval_outbox_recovery
    ON workflow_approval_outbox (community_id, lease_expires_at, id)
    WHERE state = 'publishing';

CREATE FUNCTION enforce_workflow_approval_outbox_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.community_id IS DISTINCT FROM OLD.community_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.approval_id IS DISTINCT FROM OLD.approval_id
       OR NEW.class IS DISTINCT FROM OLD.class
       OR NEW.payload_version IS DISTINCT FROM OLD.payload_version
       OR NEW.payload IS DISTINCT FROM OLD.payload
       OR NEW.dedupe_key IS DISTINCT FROM OLD.dedupe_key
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'workflow approval outbox identity and payload are immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workflow_approval_outbox_identity_immutable
BEFORE UPDATE ON workflow_approval_outbox
FOR EACH ROW
EXECUTE FUNCTION enforce_workflow_approval_outbox_identity();

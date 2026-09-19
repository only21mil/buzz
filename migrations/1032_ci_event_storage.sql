-- Durable Buzz-native CI run identity and accepted-event ordering.
--
-- The canonical signed event remains in the partitioned `events` table. These
-- tables are an immutable, query-oriented index over those rows; repository
-- policy deliberately forbids foreign keys to the partitioned events table.

CREATE TABLE ci_runs (
    community_id UUID NOT NULL REFERENCES communities(id),
    channel_id UUID NOT NULL,
    run_id UUID NOT NULL,
    initial_request_event_id BYTEA NOT NULL
        CHECK (octet_length(initial_request_event_id) = 32),
    target_repo_a TEXT NOT NULL
        CHECK (octet_length(target_repo_a) BETWEEN 1 AND 1024),
    tip_oid TEXT NOT NULL CHECK (tip_oid ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
    base_oid TEXT NOT NULL CHECK (base_oid ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
    workflow_id TEXT NOT NULL
        CHECK (octet_length(workflow_id) BETWEEN 1 AND 255),
    workflow_digest BYTEA NOT NULL CHECK (octet_length(workflow_digest) = 32),
    immutable_tuple_digest BYTEA NOT NULL
        CHECK (octet_length(immutable_tuple_digest) = 32),
    last_watch_cursor BIGINT NOT NULL DEFAULT 0
        CHECK (last_watch_cursor BETWEEN 0 AND 9007199254740991),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (community_id, run_id),
    UNIQUE (community_id, initial_request_event_id),
    CONSTRAINT ci_runs_channel_fkey
        FOREIGN KEY (community_id, channel_id)
        REFERENCES channels (community_id, id) ON DELETE NO ACTION,
    CONSTRAINT ci_runs_oid_width_matches
        CHECK (octet_length(tip_oid) = octet_length(base_oid))
);

CREATE INDEX idx_ci_runs_repo_tip
    ON ci_runs (community_id, target_repo_a, tip_oid, created_at DESC);

CREATE TABLE ci_run_events (
    community_id UUID NOT NULL,
    run_id UUID NOT NULL,
    watch_cursor BIGINT NOT NULL
        CHECK (watch_cursor BETWEEN 1 AND 9007199254740991),
    event_id BYTEA NOT NULL CHECK (octet_length(event_id) = 32),
    event_created_at TIMESTAMPTZ NOT NULL,
    request_event_id BYTEA NOT NULL
        CHECK (octet_length(request_event_id) = 32),
    event_kind INTEGER NOT NULL CHECK (event_kind BETWEEN 46100 AND 46106),
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    job_id TEXT CHECK (
        job_id IS NULL OR octet_length(job_id) BETWEEN 1 AND 64
    ),
    status_state TEXT CHECK (status_state IS NULL OR status_state IN (
        'queued', 'running', 'success', 'failure', 'cancelled', 'timed_out',
        'skipped', 'infrastructure_failure'
    )),
    sequence BIGINT CHECK (sequence IS NULL OR sequence > 0),
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (community_id, run_id, watch_cursor),
    UNIQUE (community_id, event_id),
    CONSTRAINT ci_run_events_run_fkey
        FOREIGN KEY (community_id, run_id)
        REFERENCES ci_runs (community_id, run_id) ON DELETE NO ACTION,
    CONSTRAINT ci_run_events_shape CHECK (
        (event_kind = 46100 AND status_state IS NULL AND sequence IS NULL)
        OR (event_kind = 46101 AND job_id IS NULL
            AND status_state IN ('queued', 'running', 'success', 'failure',
                'cancelled', 'timed_out', 'infrastructure_failure')
            AND sequence IS NOT NULL)
        OR (event_kind = 46102 AND job_id IS NOT NULL
            AND status_state IN ('queued', 'running', 'success', 'failure',
                'cancelled', 'timed_out', 'skipped')
            AND sequence IS NOT NULL)
        OR (event_kind IN (46103, 46104) AND job_id IS NOT NULL
            AND status_state IS NULL AND sequence IS NULL)
        OR (event_kind IN (46105, 46106) AND job_id IS NULL
            AND status_state IS NULL AND sequence IS NULL)
    )
);

CREATE UNIQUE INDEX idx_ci_run_events_initial_request
    ON ci_run_events (community_id, run_id)
    WHERE event_kind = 46100 AND attempt = 1;
CREATE UNIQUE INDEX idx_ci_run_events_rerun_lineage
    ON ci_run_events (community_id, run_id, job_id, attempt)
    WHERE event_kind = 46100 AND attempt > 1;
CREATE UNIQUE INDEX idx_ci_run_events_run_sequence
    ON ci_run_events (community_id, run_id, attempt, sequence)
    WHERE event_kind = 46101;
CREATE UNIQUE INDEX idx_ci_run_events_job_sequence
    ON ci_run_events (community_id, run_id, job_id, attempt, sequence)
    WHERE event_kind = 46102;
CREATE UNIQUE INDEX idx_ci_run_events_evidence_finalized
    ON ci_run_events (community_id, run_id)
    WHERE event_kind = 46105;
CREATE UNIQUE INDEX idx_ci_run_events_teardown_attestation
    ON ci_run_events (community_id, run_id)
    WHERE event_kind = 46106;
CREATE INDEX idx_ci_run_events_request
    ON ci_run_events (community_id, request_event_id, watch_cursor);

CREATE FUNCTION enforce_ci_run_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.community_id IS DISTINCT FROM OLD.community_id
       OR NEW.channel_id IS DISTINCT FROM OLD.channel_id
       OR NEW.run_id IS DISTINCT FROM OLD.run_id
       OR NEW.initial_request_event_id IS DISTINCT FROM OLD.initial_request_event_id
       OR NEW.target_repo_a IS DISTINCT FROM OLD.target_repo_a
       OR NEW.tip_oid IS DISTINCT FROM OLD.tip_oid
       OR NEW.base_oid IS DISTINCT FROM OLD.base_oid
       OR NEW.workflow_id IS DISTINCT FROM OLD.workflow_id
       OR NEW.workflow_digest IS DISTINCT FROM OLD.workflow_digest
       OR NEW.immutable_tuple_digest IS DISTINCT FROM OLD.immutable_tuple_digest
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'CI run identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER ci_run_identity_immutable
BEFORE UPDATE ON ci_runs
FOR EACH ROW EXECUTE FUNCTION enforce_ci_run_identity();

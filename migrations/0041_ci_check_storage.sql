-- Kind 46108 terminal checks join the CI run index.
--
-- A check summarises already stored facts for one accepted request: no job,
-- no status state, no sequence, and at most one per request. The relay
-- cross-checks the named run status and terminal facts before insert; the
-- partial unique index makes "one check per request" hold under concurrent
-- writers as well.

ALTER TABLE ci_run_events DROP CONSTRAINT ci_run_events_event_kind_check;
ALTER TABLE ci_run_events ADD CONSTRAINT ci_run_events_event_kind_check
    CHECK (event_kind BETWEEN 46100 AND 46106 OR event_kind = 46108);

ALTER TABLE ci_run_events DROP CONSTRAINT ci_run_events_shape;
ALTER TABLE ci_run_events ADD CONSTRAINT ci_run_events_shape CHECK (
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
    OR (event_kind IN (46105, 46106, 46108) AND job_id IS NULL
        AND status_state IS NULL AND sequence IS NULL)
);

CREATE UNIQUE INDEX idx_ci_run_events_check
    ON ci_run_events (community_id, request_event_id)
    WHERE event_kind = 46108;

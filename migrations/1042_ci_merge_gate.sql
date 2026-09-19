-- Merge gate decisions and owner-signed bypasses (docs/ci/BUZZ_MERGE_GATE_DESIGN.md
-- sections 1.5 and 1.7).
--
-- git_merge_gate_decisions is append-only: every gate evaluation of a gated
-- ref update inserts one row, in shadow and enforce mode alike, and the
-- finalize fence reads the latest allow row for the exact (ref, old, new,
-- pusher). `code` is `allow` or one of the refusal codes of section 1.4.
-- Rows are never updated or deleted; a trigger enforces it.
--
-- ci_merge_bypasses stores accepted kind 46109 events outside the
-- ci_run_events CHECK. A bypass names one exact ref update of one repository,
-- is signed by the repository owner, and covers at most one hour. It is
-- consumed once: the publish it covered sets consumed_by to the decision row
-- that allowed it, and a non-null consumed_by is what "unconsumed" tests.

CREATE TABLE git_merge_gate_decisions (
    community_id UUID NOT NULL REFERENCES communities(id),
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    target_repo_a TEXT NOT NULL CHECK (octet_length(target_repo_a) BETWEEN 1 AND 1024),
    ref_name TEXT NOT NULL CHECK (octet_length(ref_name) BETWEEN 1 AND 1024),
    old_oid TEXT NOT NULL CHECK (old_oid ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
    new_oid TEXT NOT NULL CHECK (new_oid ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
    candidate_oid TEXT CHECK (candidate_oid IS NULL OR candidate_oid ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
    classification TEXT NOT NULL CHECK (octet_length(classification) BETWEEN 1 AND 64),
    run_id UUID,
    check_event_id BYTEA CHECK (check_event_id IS NULL OR octet_length(check_event_id) = 32),
    signer TEXT CHECK (signer IS NULL OR signer ~ '^[0-9a-f]{64}$'),
    code TEXT NOT NULL CHECK (code IN (
        'allow', 'no_check', 'check_pending', 'check_not_success', 'reducer_disagrees',
        'base_moved', 'not_descendant', 'parent_shape', 'tree_mismatch',
        'workflow_digest_mismatch', 'required_jobs_missing', 'signer_unauthorized',
        'check_expired', 'bypass_invalid', 'gate_misconfigured'
    )),
    mode TEXT NOT NULL CHECK (mode IN ('shadow', 'enforce')),
    pusher TEXT NOT NULL CHECK (pusher ~ '^[0-9a-f]{64}$'),
    bypass_event_id BYTEA CHECK (bypass_event_id IS NULL OR octet_length(bypass_event_id) = 32),
    decided_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (community_id, id),
    CONSTRAINT git_merge_gate_decisions_oid_width_matches
        CHECK (octet_length(old_oid) = octet_length(new_oid))
);

CREATE INDEX idx_git_merge_gate_decisions_update
    ON git_merge_gate_decisions (community_id, target_repo_a, ref_name, old_oid, new_oid, decided_at DESC);
CREATE INDEX idx_git_merge_gate_decisions_landed
    ON git_merge_gate_decisions (community_id, target_repo_a, ref_name, new_oid, decided_at DESC);

CREATE FUNCTION guard_git_merge_gate_decisions_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'git_merge_gate_decisions is append-only';
END;
$$;

CREATE TRIGGER trg_git_merge_gate_decisions_append_only
BEFORE UPDATE OR DELETE ON git_merge_gate_decisions
FOR EACH ROW EXECUTE FUNCTION guard_git_merge_gate_decisions_append_only();

CREATE TABLE ci_merge_bypasses (
    community_id UUID NOT NULL REFERENCES communities(id),
    event_id BYTEA NOT NULL CHECK (octet_length(event_id) = 32),
    channel_id UUID NOT NULL,
    issuer_pubkey TEXT NOT NULL CHECK (issuer_pubkey ~ '^[0-9a-f]{64}$'),
    target_repo_a TEXT NOT NULL CHECK (octet_length(target_repo_a) BETWEEN 1 AND 1024),
    ref_name TEXT NOT NULL CHECK (octet_length(ref_name) BETWEEN 1 AND 1024),
    old_oid TEXT NOT NULL CHECK (old_oid ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
    new_oid TEXT NOT NULL CHECK (new_oid ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
    reason TEXT NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 1024),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_by UUID,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (community_id, event_id),
    CONSTRAINT ci_merge_bypasses_channel_fkey
        FOREIGN KEY (community_id, channel_id)
        REFERENCES channels (community_id, id) ON DELETE NO ACTION,
    CONSTRAINT ci_merge_bypasses_decision_fkey
        FOREIGN KEY (community_id, consumed_by)
        REFERENCES git_merge_gate_decisions (community_id, id) ON DELETE NO ACTION,
    CONSTRAINT ci_merge_bypasses_window
        CHECK (expires_at > issued_at AND expires_at <= issued_at + INTERVAL '1 hour'),
    CONSTRAINT ci_merge_bypasses_oid_width_matches
        CHECK (octet_length(old_oid) = octet_length(new_oid))
);

CREATE INDEX idx_ci_merge_bypasses_update
    ON ci_merge_bypasses (community_id, target_repo_a, ref_name, old_oid, new_oid);

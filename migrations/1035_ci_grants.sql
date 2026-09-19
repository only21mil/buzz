-- CI control-plane signer grants: which pubkeys are authorized to sign
-- kind 46101-46106 status/control-plane events for a repository channel.
--
-- The relay's CI ingest gate loads the active grant set for
-- (community_id, channel_id, target_repo_a) and accepts status events only
-- from signers whose pubkey appears in that set at the event's recorded
-- time.  Kind 46100 (CI request) does not require a grant — its actor is the
-- requester, not a status signer — but the envelope and tag validation still
-- run on ingest.
--
-- A grant is upserted by a channel owner/admin via a kind 46107 grant event.
-- `granted_by` records the owner/admin who signed the grant event so the
-- audit trail is complete.  The validity window (`valid_from`, `valid_until`)
-- bounds the grant in time; `get_active_ci_signers` filters by `now` between
-- them.  `valid_until` may be NULL for an open-ended grant.
--
-- Keyed by (community_id, channel_id, target_repo_a, signer_pubkey) so a
-- signer can be independently granted for distinct repos in the same channel,
-- and a re-grant by the same owner is an idempotent upsert.
CREATE TABLE ci_grants (
    community_id    UUID        NOT NULL REFERENCES communities(id),
    channel_id      UUID        NOT NULL,
    target_repo_a   TEXT        NOT NULL,
    signer_pubkey   TEXT        NOT NULL,
    valid_from      TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_until     TIMESTAMPTZ,
    granted_by      TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (community_id, channel_id, target_repo_a, signer_pubkey),
    FOREIGN KEY (community_id, channel_id)
        REFERENCES channels (community_id, id) ON DELETE CASCADE
);

CREATE INDEX ci_grants_channel_repo_idx
    ON ci_grants (community_id, channel_id, target_repo_a);

-- Workflow effects survive generation changes. A recovered executor reuses the
-- same claim and idempotency key instead of creating a second external effect.
CREATE TABLE workflow_effect_claims (
    community_id UUID NOT NULL REFERENCES communities(id),
    run_id UUID NOT NULL,
    step_id VARCHAR(64) NOT NULL,
    effect_index SMALLINT NOT NULL CHECK (effect_index >= 0),
    effect_kind TEXT NOT NULL CHECK (octet_length(effect_kind) BETWEEN 1 AND 64),
    effect_spec JSONB NOT NULL CHECK (jsonb_typeof(effect_spec) = 'object'),
    idempotency_key UUID NOT NULL DEFAULT gen_random_uuid(),
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    fired_at TIMESTAMPTZ,
    output JSONB,
    PRIMARY KEY (community_id, run_id, step_id, effect_index),
    UNIQUE (community_id, idempotency_key),
    FOREIGN KEY (community_id, run_id)
        REFERENCES workflow_runs (community_id, id) ON DELETE CASCADE,
    CONSTRAINT workflow_effect_claims_fired_complete
        CHECK ((fired_at IS NULL AND output IS NULL)
            OR (fired_at IS NOT NULL AND output IS NOT NULL))
);

CREATE FUNCTION enforce_workflow_effect_claim_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.community_id IS DISTINCT FROM OLD.community_id
       OR NEW.run_id IS DISTINCT FROM OLD.run_id
       OR NEW.step_id IS DISTINCT FROM OLD.step_id
       OR NEW.effect_index IS DISTINCT FROM OLD.effect_index
       OR NEW.effect_kind IS DISTINCT FROM OLD.effect_kind
       OR NEW.effect_spec IS DISTINCT FROM OLD.effect_spec
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.claimed_at IS DISTINCT FROM OLD.claimed_at THEN
        RAISE EXCEPTION 'workflow effect claim identity is immutable';
    END IF;
    IF OLD.fired_at IS NOT NULL
       AND (NEW.fired_at IS DISTINCT FROM OLD.fired_at
            OR NEW.output IS DISTINCT FROM OLD.output) THEN
        RAISE EXCEPTION 'fired workflow effect claim is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workflow_effect_claim_identity_immutable
BEFORE UPDATE ON workflow_effect_claims
FOR EACH ROW
EXECUTE FUNCTION enforce_workflow_effect_claim_identity();

-- Depends on reserved 0039 relay authorization migration; source only.
-- No expiry: accepted requests and terminal decisions are retained indefinitely.
CREATE TABLE agent_drafts (
 community_id UUID NOT NULL REFERENCES communities(id),
 owner BYTEA NOT NULL CHECK (octet_length(owner)=32),
 agent BYTEA NOT NULL CHECK (octet_length(agent)=32),
 request_id UUID NOT NULL,
 request_event_id BYTEA NOT NULL CHECK (octet_length(request_event_id)=32),
 channel_id UUID NOT NULL,
 head_event_id BYTEA NOT NULL CHECK (octet_length(head_event_id)=32),
 generation BIGINT NOT NULL DEFAULT 0 CHECK (generation BETWEEN 0 AND 2),
 state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','applying','applied','rejected')),
 PRIMARY KEY (community_id,owner,agent,request_id),
 UNIQUE (community_id,request_event_id)
);

-- Draft requests (14201) and decisions (14202) carry owner-scoped ciphertext and
-- must never be discoverable through NIP-50 search. As in migration 0014, wrap
-- the database's current generated expression instead of replacing it, so the
-- fresh-install allowlist from 0008 and any brownfield or operator-managed
-- expression keep their policy for every other kind.
DO $$
DECLARE
    existing_expression TEXT;
BEGIN
    SELECT pg_get_expr(d.adbin, d.adrelid)
      INTO existing_expression
      FROM pg_attrdef d
      JOIN pg_attribute a
        ON a.attrelid = d.adrelid
       AND a.attnum = d.adnum
     WHERE d.adrelid = 'events'::regclass
       AND a.attname = 'search_tsv';

    IF existing_expression IS NULL THEN
        RAISE EXCEPTION 'events.search_tsv generated expression not found';
    END IF;

    ALTER TABLE events DROP COLUMN search_tsv;
    EXECUTE format(
        'ALTER TABLE events ADD COLUMN search_tsv TSVECTOR GENERATED ALWAYS AS (CASE WHEN kind IN (14201, 14202) THEN NULL::tsvector ELSE (%s) END) STORED',
        existing_expression
    );
    CREATE INDEX idx_events_search_tsv ON events USING GIN (search_tsv);
END $$;

-- Ordinary deletion/age cleanup cannot erase a pending review or a terminal
-- tombstone. A future explicit retention horizon requires a separate migration.
CREATE FUNCTION preserve_agent_draft_history() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.kind IN (14201,14202) THEN
  RAISE EXCEPTION 'durable agent draft history cannot be deleted or rewritten';
 END IF;
 IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END
$$;
CREATE TRIGGER events_preserve_agent_drafts BEFORE DELETE OR UPDATE ON events
 FOR EACH ROW EXECUTE FUNCTION preserve_agent_draft_history();

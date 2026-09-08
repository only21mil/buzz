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

ALTER TABLE events DROP COLUMN search_tsv;
ALTER TABLE events ADD COLUMN search_tsv TSVECTOR GENERATED ALWAYS AS (
 CASE WHEN kind IN (1059,14201,14202,30300,30350,30622,44100,44101,44200) THEN NULL::tsvector
 ELSE to_tsvector('simple',content) END
) STORED;
CREATE INDEX idx_events_search_tsv ON events USING GIN (search_tsv);

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

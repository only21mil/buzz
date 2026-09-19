-- Agent draft history: keep the rows immutable, let policy own deletion.
--
-- 1040 raised on every DELETE or UPDATE that touched a kind 14201/14202 row,
-- including a soft delete that only sets deleted_at. That turned a kind 5 or
-- kind 9005 aimed at a draft into "soft_delete_event failed", an internal
-- error rather than a policy rejection, and aborted any bulk UPDATE whose
-- range held one draft row. The relay now refuses explicit deletions of draft
-- events before the query (see validate_admin_event and
-- validate_standard_deletion_event in crates/buzz-relay). The trigger keeps
-- the durable part durable: a hard DELETE still raises, and so does any
-- rewrite of the signed event columns (id, community_id, pubkey, created_at,
-- kind, tags, content, sig). Bookkeeping columns such as deleted_at,
-- delivered_at, channel_id, d_tag and not_before may change.
--
-- 1040 is frozen, so the function body is replaced here. The trigger
-- events_preserve_agent_drafts is unchanged and keeps calling this function.
CREATE OR REPLACE FUNCTION preserve_agent_draft_history() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.kind IN (14201,14202) THEN
  IF TG_OP = 'DELETE' THEN
   RAISE EXCEPTION 'durable agent draft history cannot be deleted';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
   OR NEW.community_id IS DISTINCT FROM OLD.community_id
   OR NEW.pubkey IS DISTINCT FROM OLD.pubkey
   OR NEW.created_at IS DISTINCT FROM OLD.created_at
   OR NEW.kind IS DISTINCT FROM OLD.kind
   OR NEW.tags IS DISTINCT FROM OLD.tags
   OR NEW.content IS DISTINCT FROM OLD.content
   OR NEW.sig IS DISTINCT FROM OLD.sig THEN
   RAISE EXCEPTION 'durable agent draft history cannot be rewritten';
  END IF;
 END IF;
 IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END
$$;

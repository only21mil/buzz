-- Attach the upstream deletion fence after all fork tables exist.
-- The helper checks pg_trigger, so fresh and rewritten databases converge.
SELECT attach_community_write_fence('workflow_state');
SELECT attach_community_write_fence('workflow_state_receipts');
SELECT attach_community_write_fence('workflow_approval_gates');
SELECT attach_community_write_fence('workflow_approval_outbox');
SELECT attach_community_write_fence('ci_runs');
SELECT attach_community_write_fence('ci_run_events');
SELECT attach_community_write_fence('workflow_effect_claims');
SELECT attach_community_write_fence('ci_grants');
SELECT attach_community_write_fence('agent_drafts');
SELECT attach_community_write_fence('ci_merge_bypasses');
SELECT attach_community_write_fence('git_merge_gate_decisions');

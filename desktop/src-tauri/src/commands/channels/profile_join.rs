/// Cap for the kind:0 profile join in `get_channel_members`. Enriching a
/// huge roster required an `authors` filter carrying every member pubkey — a
/// query whose size and relay cost grow linearly with membership and which
/// dominated channel-open latency on large channels. Members past the cap
/// keep `display_name: None` (the UI falls back to pubkey-derived labels and
/// resolves visible names through its profile caches); `role == "bot"` agent
/// flags are roster-derived and unaffected by the cap.
pub(super) const MEMBER_PROFILE_JOIN_LIMIT: usize = 500;

/// The pubkeys eligible for the kind:0 profile join: roster order, capped.
pub(super) fn profile_join_pubkeys(
    members: &[crate::models::ChannelMemberInfo],
    limit: usize,
) -> Vec<String> {
    members
        .iter()
        .take(limit)
        .map(|member| member.pubkey.clone())
        .collect()
}

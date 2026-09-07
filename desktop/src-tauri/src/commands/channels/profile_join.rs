use crate::models::ChannelMemberInfo;

/// Maximum authors per kind:0 request. All roster members need a lookup:
/// a verified owner profile can identify an agent with any channel role.
/// A cold 10k-member roster therefore needs 20 sequential requests.
pub(super) const MEMBER_PROFILE_JOIN_LIMIT: usize = 500;

/// Fetch profiles for the complete roster with one bounded request in flight.
/// Failed batches contribute no events, preserving the existing scoped cache
/// fallback. Dropping this future cancels the current request and prevents
/// subsequent batches from starting.
pub(super) async fn query_member_profiles<F, Fut>(
    members: &[ChannelMemberInfo],
    mut query: F,
) -> Vec<nostr::Event>
where
    F: FnMut(serde_json::Value) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<nostr::Event>, String>>,
{
    let mut events = Vec::new();
    for batch in members.chunks(MEMBER_PROFILE_JOIN_LIMIT) {
        let authors: Vec<&str> = batch.iter().map(|member| member.pubkey.as_str()).collect();
        if let Ok(page) = query(serde_json::json!({
            "kinds": [0],
            "authors": authors,
            "limit": authors.len()
        }))
        .await
        {
            events.extend(page);
        }
    }
    events
}

#[cfg(test)]
#[path = "profile_join_tests.rs"]
mod tests;

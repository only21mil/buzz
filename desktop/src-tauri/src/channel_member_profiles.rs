use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        LockResult, Mutex, MutexGuard,
    },
};

pub(crate) struct ChannelMemberProfileCacheEntry {
    pub request_id: u64,
    pub is_agent: bool,
    pub display_name: Option<String>,
}

pub(crate) type Entries = HashMap<(String, String), ChannelMemberProfileCacheEntry>;

#[derive(Default)]
pub(crate) struct ChannelMemberProfileCache {
    next_request_id: AtomicU64,
    entries: Mutex<Entries>,
}

impl ChannelMemberProfileCache {
    pub(crate) fn next_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) fn lock(&self) -> LockResult<MutexGuard<'_, Entries>> {
        self.entries.lock()
    }
}

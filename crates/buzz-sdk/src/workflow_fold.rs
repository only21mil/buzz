//! Client-side folding for workflow definition replacements and NIP-09 deletions.

use std::collections::HashMap;

use nostr::{Event, Kind};

use crate::kind::KIND_WORKFLOW_DEF;

/// Return the live head for each workflow definition coordinate in `events`.
///
/// A coordinate is `(author pubkey, d-tag)`. The newest kind 30620 wins, with
/// the lower event id breaking equal-timestamp ties per NIP-01. A kind 5 only
/// removes that head when the deletion author owns the coordinate, targets the
/// head by `e` tag or the coordinate by `a` tag, and is at least as new as the
/// head. A later replacement therefore recreates a deleted workflow.
pub fn fold_workflow_definitions(events: &[Event]) -> Vec<&Event> {
    let mut heads: HashMap<(String, String), &Event> = HashMap::new();

    for event in events
        .iter()
        .filter(|event| event.kind.as_u16() as u32 == KIND_WORKFLOW_DEF)
    {
        let Some(d_tag) = tag_value(event, "d") else {
            continue;
        };
        let coordinate = (event.pubkey.to_hex(), d_tag.to_owned());
        let replace = heads.get(&coordinate).is_none_or(|head| {
            event.created_at > head.created_at
                || (event.created_at == head.created_at && event.id < head.id)
        });
        if replace {
            heads.insert(coordinate, event);
        }
    }

    events
        .iter()
        .filter(|event| {
            if event.kind.as_u16() as u32 != KIND_WORKFLOW_DEF {
                return false;
            }
            let Some(d_tag) = tag_value(event, "d") else {
                return false;
            };
            let author = event.pubkey.to_hex();
            let coordinate = (author.clone(), d_tag.to_owned());
            if heads
                .get(&coordinate)
                .is_none_or(|head| head.id != event.id)
            {
                return false;
            }

            let address = format!("{KIND_WORKFLOW_DEF}:{author}:{d_tag}");
            !events.iter().any(|deletion| {
                deletion.kind == Kind::EventDeletion
                    && deletion.pubkey == event.pubkey
                    && deletion.created_at >= event.created_at
                    && deletion.tags.iter().any(|tag| {
                        let parts = tag.as_slice();
                        matches!(parts, [kind, target, ..]
                            if (kind == "e" && target == &event.id.to_hex())
                                || (kind == "a" && target == &address))
                    })
            })
        })
        .collect()
}

fn tag_value<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    event.tags.iter().find_map(|tag| {
        let parts = tag.as_slice();
        (parts.first().map(String::as_str) == Some(name))
            .then(|| parts.get(1).map(String::as_str))
            .flatten()
    })
}

#[cfg(test)]
mod tests {
    use nostr::{EventBuilder, Keys, Tag, Timestamp};

    use super::*;

    const SENTINEL: &str = "2d9e6ee2-b530-4a19-80b9-17bc834055bd";

    fn definition(keys: &Keys, d_tag: &str, created_at: u64) -> Event {
        EventBuilder::new(Kind::Custom(KIND_WORKFLOW_DEF as u16), "name: fixture")
            .tags(vec![Tag::parse(["d", d_tag]).expect("d tag")])
            .custom_created_at(Timestamp::from(created_at))
            .sign_with_keys(keys)
            .expect("sign definition")
    }

    fn coordinate_deletion(keys: &Keys, owner: &Keys, d_tag: &str, created_at: u64) -> Event {
        let address = format!(
            "{KIND_WORKFLOW_DEF}:{}:{d_tag}",
            owner.public_key().to_hex()
        );
        EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::parse(["a", &address]).expect("a tag")])
            .custom_created_at(Timestamp::from(created_at))
            .sign_with_keys(keys)
            .expect("sign deletion")
    }

    #[test]
    fn folds_owner_tombstones_foreign_deletions_and_recreations() {
        let owner = Keys::generate();
        let other = Keys::generate();

        let deleted = definition(&owner, SENTINEL, 10);
        let owner_tombstone = coordinate_deletion(&owner, &owner, SENTINEL, 11);
        assert!(fold_workflow_definitions(&[deleted, owner_tombstone]).is_empty());

        let live = definition(&owner, SENTINEL, 10);
        let foreign_tombstone = coordinate_deletion(&other, &owner, SENTINEL, 11);
        let events = [live.clone(), foreign_tombstone];
        let folded = fold_workflow_definitions(&events);
        assert_eq!(
            folded.iter().map(|event| event.id).collect::<Vec<_>>(),
            [live.id]
        );

        let old = definition(&owner, SENTINEL, 10);
        let tombstone = coordinate_deletion(&owner, &owner, SENTINEL, 11);
        let recreated = definition(&owner, SENTINEL, 12);
        let events = [old, tombstone, recreated.clone()];
        let folded = fold_workflow_definitions(&events);
        assert_eq!(
            folded.iter().map(|event| event.id).collect::<Vec<_>>(),
            [recreated.id]
        );
    }

    #[test]
    fn folds_event_id_tombstone_and_keeps_newest_definition() {
        let owner = Keys::generate();
        let old = definition(&owner, SENTINEL, 10);
        let head = definition(&owner, SENTINEL, 11);
        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::parse(["e", &head.id.to_hex()]).expect("e tag")])
            .custom_created_at(Timestamp::from(12))
            .sign_with_keys(&owner)
            .expect("sign deletion");

        assert!(fold_workflow_definitions(&[old, head, deletion]).is_empty());
    }
}

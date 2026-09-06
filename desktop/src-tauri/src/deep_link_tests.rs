use super::{parse_entity_deep_link, PendingEntityDeepLinks, ENTITY_LINK_TABS};
use url::Url;
fn entity_link_golden() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../test-fixtures/entity-links.json"))
        .expect("valid fixture")
}
#[test]
fn parse_entity_deep_link_accepts_every_share_link_shape() {
    let golden = entity_link_golden();
    let owner = golden["owner"].as_str().unwrap();
    let dtag = golden["dtag"].as_str().unwrap();
    for raw in golden["links"]
        .as_object()
        .unwrap()
        .values()
        .map(|value| value.as_str().unwrap().to_owned())
        .chain(golden["tabs"].as_array().unwrap().iter().map(|tab| {
            format!(
                "buzz://repo?owner={owner}&d={dtag}&tab={}",
                tab.as_str().unwrap()
            )
        }))
    {
        assert!(
            parse_entity_deep_link(&Url::parse(&raw).unwrap()).is_some(),
            "{raw}"
        );
    }
    let expected_tabs = golden["tabs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tab| tab.as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(ENTITY_LINK_TABS.as_slice(), expected_tabs);
}
#[test]
fn parse_entity_deep_link_rejects_malformed_and_non_canonical_links() {
    let golden = entity_link_golden();
    let owner = golden["owner"].as_str().unwrap();
    let event_id = golden["eventId"].as_str().unwrap();
    for raw in [
        // Missing or malformed identifiers.
        format!("buzz://repo?owner={owner}"),
        "buzz://repo?owner=nope&d=buzz-world".to_owned(),
        format!("buzz://repo?owner={owner}&d=.hidden"),
        format!("buzz://repo?owner={owner}&d=has%20space"),
        format!("buzz://pr?owner={owner}&d=buzz-world"),
        format!("buzz://pr?id=short&owner={owner}&d=buzz-world"),
        // Coordinate links take no event id.
        format!("buzz://repo?id={event_id}&owner={owner}&d=buzz-world"),
        // Non-canonical: unknown param, duplicate param, path, fragment.
        format!("buzz://repo?owner={owner}&d=buzz-world&relay=wss%3A%2F%2Fx.example"),
        format!("buzz://repo?owner={owner}&owner={owner}&d=buzz-world"),
        // Unknown tab value, duplicate tab, and tab on an event link.
        format!("buzz://repo?owner={owner}&d=buzz-world&tab=overview"),
        format!("buzz://repo?owner={owner}&d=buzz-world&tab=prs&tab=prs"),
        format!("buzz://pr?id={event_id}&owner={owner}&d=buzz-world&tab=prs"),
        format!("buzz://repo/extra?owner={owner}&d=buzz-world"),
        format!("buzz://repo?owner={owner}&d=buzz-world#top"),
        // Not an entity host.
        format!("buzz://message?owner={owner}&d=buzz-world"),
    ] {
        assert!(
            parse_entity_deep_link(&Url::parse(&raw).unwrap()).is_none(),
            "{raw}"
        );
    }
}
#[test]
fn pending_entity_links_survive_until_acknowledged_in_order() {
    let queue = PendingEntityDeepLinks::default();
    let first = queue.enqueue("buzz://project?owner=aa&d=first".to_owned());
    let second = queue.enqueue("buzz://project?owner=aa&d=second".to_owned());

    assert_eq!(queue.first(), Some(first.clone()));
    assert!(!queue.acknowledge(&second.id));
    assert!(queue.acknowledge(&first.id));
    assert_eq!(queue.first(), Some(second));
}
#[test]
fn pending_entity_links_dedupe_launch_and_open_callbacks() {
    let queue = PendingEntityDeepLinks::default();
    let href = "buzz://project?owner=aa&d=buzz".to_owned();
    let first = queue.enqueue(href.clone());
    let duplicate = queue.enqueue(href);

    assert_eq!(duplicate.id, first.id);
    assert!(queue.acknowledge(&first.id));
    assert!(queue.first().is_none());
}

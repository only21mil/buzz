//! Community moderation authorization (Phase 1 contract).
//!
//! One capability seam for every moderation decision, per
//! `PLANS/COMMUNITY_MODERATION_PLAN.md` §0.1: roles are community
//! `owner`/`admin` (from tenant-scoped `relay_members`) plus existing
//! channel-level owner/admin. There is no Moderator tier in v1 — but all
//! authorization routes through [`authorize_moderation_action`] so adding one
//! later is a policy change, not a rewrite.
//!
//! ## Tenant invariant
//! Authority never crosses the tenant fence: the actor's role is read from
//! `relay_members` / `channel_members` under `tenant.community()` only, and
//! callers must have already resolved `target` inside the same tenant.
//!
//! Lane ownership: L2 (Mari). Signatures below are the contract.

use std::sync::Arc;

use buzz_core::tenant::TenantContext;
use uuid::Uuid;

use crate::state::AppState;

/// A moderation capability being exercised.
///
/// V1 capability grid (plan §4 Gap A): community owner/admin hold all of
/// these community-wide; channel owner/admin hold `DeleteMessage`/`Kick`
/// within their channel only; members hold none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModerationAction {
    /// Delete any message (kind:9005 path).
    DeleteMessage,
    /// Remove/kick a user from a channel (kind:9001 path).
    Kick,
    /// Add channel members or change their channel roles.
    ManageMembers,
    /// Edit privileged channel metadata.
    EditMetadata,
    /// Delete a channel, restricted to an owner.
    DeleteChannel,
    /// Ban a user from the community (community owner/admin only).
    Ban,
    /// Lift a community ban.
    Unban,
    /// Time-box a user's writes (community owner/admin only).
    Timeout,
    /// Clear a timeout early.
    Untimeout,
    /// Resolve/dismiss/escalate reports in the moderation queue.
    ResolveReport,
    /// Read the moderation queue and audit log.
    ViewQueue,
}

/// What the action is aimed at (already tenant-resolved by the caller).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModerationTarget<'a> {
    /// An event (32-byte id) in `channel_id`'s community.
    Event(&'a [u8]),
    /// A member pubkey in this community.
    Pubkey(&'a [u8]),
    /// No specific target (queue/audit reads).
    None,
}

/// Why an authorization succeeded — recorded in the audit row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModerationAuthority {
    /// Actor is community `owner` in `relay_members`.
    CommunityOwner,
    /// Actor is community `admin` in `relay_members`.
    CommunityAdmin,
    /// Actor is channel owner/admin of the target's channel.
    ChannelRole,
}

/// Decide whether `actor` may perform `action` on `target`.
///
/// - Community `owner`/`admin` (tenant-scoped `relay_members.role`) are
///   authorized community-wide, except channel deletion requires an owner, in their
///   community. Channel-admin events use the same seam.
/// - Channel owner/admin keep their existing channel-local authority for
///   `DeleteMessage`/`Kick` (via `channel_id`).
/// - Guard rails (plan): an admin cannot ban/timeout the community owner or
///   a fellow admin; only the owner can action an admin.
///
/// Returns the matched authority for the audit row, or `Err` with a
/// client-safe denial message.
pub async fn authorize_moderation_action(
    tenant: &TenantContext,
    state: &Arc<AppState>,
    actor_pubkey: &[u8],
    channel_id: Option<Uuid>,
    target: ModerationTarget<'_>,
    action: ModerationAction,
) -> anyhow::Result<ModerationAuthority> {
    let community = tenant.community();

    // Community role: `relay_members` stores pubkeys as 64-char hex, fenced to
    // `community` in the query itself. This is the primary authority — owner and
    // admin can moderate any channel in their community.
    let actor_role = state
        .db
        .get_relay_member(community, &hex::encode(actor_pubkey))
        .await?
        .map(|m| m.role);

    // The target's community role is read only for the admin guard rail — i.e.
    // an admin actioning a pubkey with ban/timeout — so the owner and
    // channel-role paths stay at a single query.
    let target_role = match (actor_role.as_deref(), action, target) {
        (
            Some("admin"),
            ModerationAction::Ban
            | ModerationAction::Timeout
            | ModerationAction::Kick
            | ModerationAction::ManageMembers,
            target,
        ) => match target {
            ModerationTarget::Pubkey(pk) => state
                .db
                .get_relay_member(community, &hex::encode(pk))
                .await?
                .map(|m| m.role),
            _ => None,
        },
        _ => None,
    };

    // The channel role is read only when community authority does not apply and
    // the action is channel-local (DeleteMessage/Kick within `channel_id`).
    let channel_role = match (actor_role.as_deref(), action, channel_id) {
        (Some("owner") | Some("admin"), _, _) => None,
        (_, ModerationAction::DeleteMessage | ModerationAction::Kick, Some(channel_id)) => {
            state
                .db
                .get_member_role(community, channel_id, actor_pubkey)
                .await?
        }
        _ => None,
    };

    decide_authority(
        actor_role.as_deref(),
        target_role.as_deref(),
        channel_role.as_deref(),
        action,
    )
}

/// Pure authorization decision from resolved roles — the policy, factored out
/// of the I/O so it is exhaustively unit-testable.
///
/// - `actor_role` / `target_role`: community `relay_members` role, if any.
/// - `channel_role`: the actor's channel role, resolved by the caller only when
///   community authority does not apply and the action is channel-local.
fn decide_authority(
    actor_role: Option<&str>,
    target_role: Option<&str>,
    channel_role: Option<&str>,
    action: ModerationAction,
) -> anyhow::Result<ModerationAuthority> {
    match actor_role {
        // Owner holds every capability, community-wide, with no guard rail.
        Some("owner") => Ok(ModerationAuthority::CommunityOwner),
        // Admin holds channel management except deletion, but cannot restrict the owner or a
        // fellow admin — only the owner may action an admin. The guard trips only
        // on a target *role* of owner/admin: a target with no `relay_members` row
        // (a drive-by spammer who already left) is bannable. Unban/Untimeout lift
        // a restriction and are intentionally unguarded at this role seam. The
        // command handler separately rejects a banned actor on every transport,
        // so the reachable case is an unrestricted admin lifting another admin's
        // restriction; that remains benign, audited, and owner-reversible.
        Some("admin") => {
            if action == ModerationAction::DeleteChannel {
                anyhow::bail!("only owner can delete group");
            }
            if matches!(
                action,
                ModerationAction::Ban
                    | ModerationAction::Timeout
                    | ModerationAction::Kick
                    | ModerationAction::ManageMembers
            ) && matches!(target_role, Some("owner") | Some("admin"))
            {
                anyhow::bail!("an admin cannot restrict a community owner or fellow admin");
            }
            Ok(ModerationAuthority::CommunityAdmin)
        }
        // Not a community owner/admin: channel owner/admin keep channel-local
        // authority for DeleteMessage/Kick only.
        _ => match (action, channel_role) {
            (
                ModerationAction::DeleteMessage | ModerationAction::Kick,
                Some("owner") | Some("admin"),
            ) => Ok(ModerationAuthority::ChannelRole),
            _ => anyhow::bail!("moderator access required"),
        },
    }
}

/// Community authority for a channel command. The signer remains the audit actor.
pub(crate) struct ChannelAdminGrant {
    pub(crate) principal: Vec<u8>,
    pub(crate) authority: ModerationAuthority,
}

/// Resolve community authority without converting admission into an implicit grant.
/// A delegated command must carry a valid, action-scoped NIP-OA tag and match
/// the durable tenant-local owner. Current restrictions apply to both principals.
pub(crate) async fn channel_admin_grant(
    tenant: &TenantContext,
    state: &Arc<AppState>,
    event: &nostr::Event,
) -> anyhow::Result<Option<ChannelAdminGrant>> {
    let action = match event.kind.as_u16() {
        9000 => ModerationAction::ManageMembers,
        9001 => ModerationAction::Kick,
        9002 => ModerationAction::EditMetadata,
        9005 => ModerationAction::DeleteMessage,
        9008 => ModerationAction::DeleteChannel,
        _ => return Ok(None),
    };
    let community = tenant.community();
    let signer = event.pubkey.to_bytes();
    let mut principal = signer.to_vec();
    let direct_role = state
        .db
        .get_relay_member(community, &event.pubkey.to_hex())
        .await?;
    let mut principal_is_admin = direct_role.as_ref().is_some_and(|m| m.role == "admin");
    if !direct_role.is_some_and(|m| matches!(m.role.as_str(), "owner" | "admin")) {
        let Some(tag) = super::auth::extract_auth_tag_json(event) else {
            return Ok(None);
        };
        let owner = buzz_sdk::nip_oa::verify_auth_tag_for_action(&tag, event)?;
        if !state
            .db
            .is_agent_owner(community, &signer, owner.as_bytes())
            .await?
        {
            anyhow::bail!("delegation does not match the registered agent owner");
        }
        principal = owner.to_bytes().to_vec();
        let owner_role = state
            .db
            .get_relay_member(community, &owner.to_hex())
            .await?;
        principal_is_admin = owner_role.as_ref().is_some_and(|m| m.role == "admin");
        if !owner_role.is_some_and(|m| matches!(m.role.as_str(), "owner" | "admin")) {
            return Ok(None);
        }
    }
    for pk in [&signer[..], principal.as_slice()] {
        let restriction = state.db.moderation_restriction_state(community, pk).await?;
        if restriction.banned
            || restriction
                .muted_until
                .is_some_and(|until| until > chrono::Utc::now())
        {
            anyhow::bail!("restricted: moderator principal is restricted");
        }
    }
    // Community admin grants no channel-deletion capability. Fall back to
    // the existing validator so an admin who is also that channel's owner
    // keeps their channel-local deletion authority.
    if action == ModerationAction::DeleteChannel && principal_is_admin {
        return Ok(None);
    }
    let channel_id = super::side_effects::extract_h_tag_channel(event)
        .ok_or_else(|| anyhow::anyhow!("missing or invalid h tag"))?;
    state.db.get_channel(community, channel_id).await?;
    let target_pubkey = match action {
        ModerationAction::ManageMembers | ModerationAction::Kick => Some(
            super::side_effects::extract_p_tag(event)
                .ok_or_else(|| anyhow::anyhow!("missing p tag"))?,
        ),
        _ => None,
    };
    // Self-removal retains its existing active-member and last-owner rules.
    if action == ModerationAction::Kick && target_pubkey.as_deref() == Some(&signer[..]) {
        return Ok(None);
    }
    let authority = authorize_moderation_action(
        tenant,
        state,
        &principal,
        Some(channel_id),
        target_pubkey
            .as_deref()
            .map(ModerationTarget::Pubkey)
            .unwrap_or(ModerationTarget::None),
        action,
    )
    .await?;
    if authority == ModerationAuthority::CommunityAdmin {
        if let Some(target) = target_pubkey.as_deref() {
            let role = state
                .db
                .get_member_role(community, channel_id, target)
                .await?;
            if matches!(role.as_deref(), Some("owner") | Some("admin")) {
                anyhow::bail!("an admin cannot change a channel owner or fellow admin");
            }
        }
        if action == ModerationAction::ManageMembers
            && event
                .tags
                .iter()
                .any(|t| t.as_slice()[0] == "role" && t.content() == Some("owner"))
        {
            anyhow::bail!("only owner may grant channel ownership");
        }
    }
    Ok(Some(ChannelAdminGrant {
        principal,
        authority,
    }))
}

/// Persist the accepted community-authorized command before its mutation.
/// A failed audit write fails the command closed; retries retain the signed event id.
pub(crate) async fn audit_channel_admin_event(
    tenant: &TenantContext,
    state: &Arc<AppState>,
    event: &nostr::Event,
    grant: &ChannelAdminGrant,
) -> anyhow::Result<()> {
    let action = match event.kind.as_u16() {
        9000 => "add_member",
        9001 => "kick",
        9002 => "edit_metadata",
        9005 => "delete_message",
        9008 => "delete_channel",
        _ => return Ok(()),
    };
    let target = super::side_effects::extract_p_tag(event);
    let target_event = event
        .tags
        .iter()
        .find(|t| t.as_slice()[0] == "e")
        .and_then(|t| t.content())
        .map(hex::decode)
        .transpose()?;
    let provenance = format!(
        "event={} principal={} authority={:?}",
        event.id,
        hex::encode(&grant.principal),
        grant.authority
    );
    state
        .db
        .insert_moderation_action(
            tenant.community(),
            buzz_db::moderation::NewAction {
                actor_pubkey: event.pubkey.as_bytes(),
                action,
                target_pubkey: target.as_deref(),
                target_event_id: target_event.as_deref(),
                channel_id: super::side_effects::extract_h_tag_channel(event),
                reason_code: Some("channel_admin"),
                public_reason: None,
                private_reason: Some(&provenance),
                matched_principal: Some(if grant.principal == event.pubkey.as_bytes() {
                    "self"
                } else {
                    "owner"
                }),
            },
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every community-wide action a community owner can take. Channel-local
    /// actions (DeleteMessage/Kick) are included — the owner holds them too.
    const ALL_ACTIONS: [ModerationAction; 11] = [
        ModerationAction::DeleteMessage,
        ModerationAction::Kick,
        ModerationAction::ManageMembers,
        ModerationAction::EditMetadata,
        ModerationAction::DeleteChannel,
        ModerationAction::Ban,
        ModerationAction::Unban,
        ModerationAction::Timeout,
        ModerationAction::Untimeout,
        ModerationAction::ResolveReport,
        ModerationAction::ViewQueue,
    ];

    fn ok(r: anyhow::Result<ModerationAuthority>) -> ModerationAuthority {
        r.expect("expected authorization")
    }

    #[test]
    fn community_owner_authorized_for_everything() {
        for action in ALL_ACTIONS {
            // Even against another owner/admin target: the owner has no guard rail.
            assert_eq!(
                ok(decide_authority(Some("owner"), Some("admin"), None, action)),
                ModerationAuthority::CommunityOwner,
                "owner must be authorized for {action:?}"
            );
        }
    }

    #[test]
    fn community_admin_authorized_against_non_privileged_targets() {
        for action in ALL_ACTIONS
            .into_iter()
            .filter(|a| *a != ModerationAction::DeleteChannel)
        {
            // Target is a plain member (or unknown) — admin holds every capability.
            assert_eq!(
                ok(decide_authority(
                    Some("admin"),
                    Some("member"),
                    None,
                    action
                )),
                ModerationAuthority::CommunityAdmin,
                "admin must be authorized for {action:?} against a member"
            );
            assert_eq!(
                ok(decide_authority(Some("admin"), None, None, action)),
                ModerationAuthority::CommunityAdmin,
                "admin must be authorized for {action:?} against a non-member"
            );
        }
    }

    #[test]
    fn admin_cannot_ban_or_timeout_owner_or_fellow_admin() {
        for target in ["owner", "admin"] {
            for action in [
                ModerationAction::Ban,
                ModerationAction::Timeout,
                ModerationAction::Kick,
                ModerationAction::ManageMembers,
            ] {
                assert!(
                    decide_authority(Some("admin"), Some(target), None, action).is_err(),
                    "admin must not {action:?} a community {target}"
                );
            }
        }
    }

    #[test]
    fn admin_can_ban_or_timeout_a_non_member_target() {
        // A target with no `relay_members` row (e.g. a drive-by spammer who
        // already left) must still be bannable — the guard trips on a privileged
        // *role*, never on a missing row.
        for action in [ModerationAction::Ban, ModerationAction::Timeout] {
            assert_eq!(
                ok(decide_authority(Some("admin"), None, None, action)),
                ModerationAuthority::CommunityAdmin,
                "admin must be able to {action:?} a non-member target"
            );
            // A plain member target is likewise fair game.
            assert_eq!(
                ok(decide_authority(
                    Some("admin"),
                    Some("member"),
                    None,
                    action
                )),
                ModerationAuthority::CommunityAdmin,
                "admin must be able to {action:?} a plain member"
            );
        }
    }

    #[test]
    fn admin_guard_rail_allows_reversals_and_metadata_actions() {
        // Reversals and non-restriction actions against an admin target are allowed —
        // the guard rail protects against *applying* a restriction, not lifting one.
        for action in [
            ModerationAction::Unban,
            ModerationAction::Untimeout,
            ModerationAction::DeleteMessage,
            ModerationAction::EditMetadata,
            ModerationAction::ResolveReport,
            ModerationAction::ViewQueue,
        ] {
            assert_eq!(
                ok(decide_authority(Some("admin"), Some("admin"), None, action)),
                ModerationAuthority::CommunityAdmin,
                "admin must be authorized for {action:?} even against an admin target"
            );
        }
    }

    #[test]
    fn channel_role_covers_only_delete_and_kick() {
        for role in ["owner", "admin"] {
            for action in [ModerationAction::DeleteMessage, ModerationAction::Kick] {
                assert_eq!(
                    ok(decide_authority(None, None, Some(role), action)),
                    ModerationAuthority::ChannelRole,
                    "channel {role} must be authorized for {action:?}"
                );
            }
            // No community authority: channel role does NOT grant community actions.
            for action in [
                ModerationAction::Ban,
                ModerationAction::Timeout,
                ModerationAction::Unban,
                ModerationAction::Untimeout,
                ModerationAction::ResolveReport,
                ModerationAction::ViewQueue,
            ] {
                assert!(
                    decide_authority(None, None, Some(role), action).is_err(),
                    "channel {role} must NOT be authorized for community action {action:?}"
                );
            }
        }
    }

    #[test]
    fn plain_channel_member_and_stranger_are_denied() {
        for action in ALL_ACTIONS {
            assert!(
                decide_authority(None, None, Some("member"), action).is_err(),
                "channel member must be denied {action:?}"
            );
            assert!(
                decide_authority(None, None, None, action).is_err(),
                "user with no role must be denied {action:?}"
            );
        }
    }
    #[test]
    fn community_channel_admin_roles_preserve_owner_boundary() {
        for action in [
            ModerationAction::Kick,
            ModerationAction::ManageMembers,
            ModerationAction::EditMetadata,
        ] {
            assert_eq!(
                decide_authority(Some("admin"), Some("member"), None, action).unwrap(),
                ModerationAuthority::CommunityAdmin
            );
            assert!(decide_authority(Some("member"), None, None, action).is_err());
            assert!(decide_authority(None, None, None, action).is_err());
        }
        assert!(
            decide_authority(Some("admin"), None, None, ModerationAction::DeleteChannel).is_err()
        );
        assert_eq!(
            decide_authority(Some("owner"), None, None, ModerationAction::DeleteChannel).unwrap(),
            ModerationAuthority::CommunityOwner
        );
    }
}

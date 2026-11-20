//! Discord-style granular permissions: server-defined roles carrying a
//! bitflag permission set, assigned to members, plus per-channel
//! overwrites (by role and by individual member) that take precedence
//! over a member's role permissions in that one channel.
//!
//! This sits alongside `access.rs`'s simple owner/admin/moderator/member
//! rank, which still governs who can kick, ban or transfer ownership --
//! that hierarchy is about acting on OTHER MEMBERS, not about what a
//! member can do in a given channel, and isn't replaced by this module.
//!
//! Resolution order, closely mirroring Discord's own algorithm:
//!   1. The site owner, a server's owner, or anyone holding a role with
//!      `ADMINISTRATOR` gets every permission, unconditionally -- no
//!      overwrite can take anything away from them.
//!   2. Otherwise, start from the union of the member's roles' permission
//!      bits (every member implicitly has the server's default/"@everyone"
//!      role too).
//!   3. If resolving for a specific channel: apply every role-level
//!      overwrite that channel has for one of the member's roles --
//!      denies from ALL of them first, then allows from all of them --
//!      then apply that channel's member-specific overwrite (if any) the
//!      same way, last, so it has the final say.

use std::collections::HashSet;

use uuid::Uuid;

use crate::access::channel_server_id;
use crate::db::Database;
use crate::errors::AppError;

pub type Bits = i64;

/// A single permission bit. `ADMINISTRATOR` bypasses every other check and
/// every overwrite -- see the module docs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Permission(pub Bits);

impl Permission {
    pub const VIEW_CHANNEL: Permission = Permission(1 << 0);
    pub const SEND_MESSAGES: Permission = Permission(1 << 1);
    pub const MANAGE_MESSAGES: Permission = Permission(1 << 2);
    pub const MANAGE_CHANNELS: Permission = Permission(1 << 3);
    pub const MANAGE_ROLES: Permission = Permission(1 << 4);
    pub const MANAGE_SERVER: Permission = Permission(1 << 5);
    pub const KICK_MEMBERS: Permission = Permission(1 << 6);
    pub const BAN_MEMBERS: Permission = Permission(1 << 7);
    pub const MANAGE_EMOJIS: Permission = Permission(1 << 8);
    pub const CREATE_INVITE: Permission = Permission(1 << 9);
    pub const MENTION_EVERYONE: Permission = Permission(1 << 10);
    pub const ATTACH_FILES: Permission = Permission(1 << 11);
    pub const ADD_REACTIONS: Permission = Permission(1 << 12);
    pub const ADMINISTRATOR: Permission = Permission(1 << 13);

    /// Every bit this module currently defines -- what `ADMINISTRATOR`
    /// (and site/server ownership) resolves to.
    pub const ALL: Bits = (1 << 14) - 1;

    /// All names, for validating a role's permissions in API input and for
    /// listing them to the frontend. Order matters for display only.
    pub const ALL_NAMED: &'static [(&'static str, Permission)] = &[
        ("view_channel", Permission::VIEW_CHANNEL),
        ("send_messages", Permission::SEND_MESSAGES),
        ("manage_messages", Permission::MANAGE_MESSAGES),
        ("manage_channels", Permission::MANAGE_CHANNELS),
        ("manage_roles", Permission::MANAGE_ROLES),
        ("manage_server", Permission::MANAGE_SERVER),
        ("kick_members", Permission::KICK_MEMBERS),
        ("ban_members", Permission::BAN_MEMBERS),
        ("manage_emojis", Permission::MANAGE_EMOJIS),
        ("create_invite", Permission::CREATE_INVITE),
        ("mention_everyone", Permission::MENTION_EVERYONE),
        ("attach_files", Permission::ATTACH_FILES),
        ("add_reactions", Permission::ADD_REACTIONS),
        ("administrator", Permission::ADMINISTRATOR),
    ];

    pub fn name(self) -> Option<&'static str> {
        Self::ALL_NAMED.iter().find(|(_, p)| *p == self).map(|(n, _)| *n)
    }

    pub fn from_name(name: &str) -> Option<Permission> {
        Self::ALL_NAMED.iter().find(|(n, _)| *n == name).map(|(_, p)| *p)
    }
}

/// A resolved (or role-stored, or overwrite-stored) set of permission
/// bits. Bits outside `Permission::ALL` are harmless and ignored.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Permissions(pub Bits);

impl Permissions {
    pub const NONE: Permissions = Permissions(0);
    pub const ALL: Permissions = Permissions(Permission::ALL);

    pub fn has(self, p: Permission) -> bool {
        self.0 & p.0 != 0
    }

    pub fn with(self, p: Permission) -> Permissions {
        Permissions(self.0 | p.0)
    }

    pub fn union(self, other: Permissions) -> Permissions {
        Permissions(self.0 | other.0)
    }

    /// Masks out `deny`'s bits, then sets `allow`'s -- an overwrite's
    /// effect, applied in that order so allow always wins over deny
    /// within the SAME overwrite (Discord's own rule: a single
    /// role/member overwrite can't deny and allow the same bit at once in
    /// a way that matters, but if it somehow did, allow takes it).
    pub fn apply_overwrite(self, allow: Bits, deny: Bits) -> Permissions {
        Permissions((self.0 & !deny) | allow)
    }

    /// Named bits set, for API responses.
    pub fn names(self) -> Vec<&'static str> {
        Permission::ALL_NAMED.iter().filter(|(_, p)| self.has(*p)).map(|(n, _)| *n).collect()
    }
}

/// Validates a JSON permission-name list from API input into stored
/// bits, rejecting anything not in `Permission::ALL_NAMED`.
pub fn bits_from_names(names: &[String]) -> Result<Bits, AppError> {
    let mut bits = 0;
    for name in names {
        let p = Permission::from_name(name)
            .ok_or_else(|| AppError::BadRequest(format!("Unknown permission: {name}")))?;
        bits |= p.0;
    }
    Ok(bits)
}

/// Whether `user_id` bypasses every permission check in `server_id`
/// outright: this server's own owner, or the site owner -- but, same as
/// `access::require_member`, only once they've actually joined this
/// server. A site owner hasn't joined every server just by being the
/// site owner, and shouldn't see into one they haven't (see the e2e test
/// "a site owner outranks server owners but can't see servers they
/// haven't joined").
async fn is_unconditional_owner(db: &Database, server_id: Uuid, user_id: Uuid) -> Result<bool, AppError> {
    let row: Option<(Uuid, bool)> = sqlx::query_as(
        r#"
        SELECT s.owner_id, COALESCE(u.site_role = 'owner', false)
        FROM server_members sm
        JOIN servers s ON s.id = sm.server_id
        JOIN users u ON u.id = sm.user_id
        WHERE sm.server_id = $1 AND sm.user_id = $2
        "#,
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(match row {
        Some((owner_id, is_site_owner)) => is_site_owner || owner_id == user_id,
        None => false,
    })
}

/// The union of permission bits granted by every role `user_id` holds in
/// `server_id`, including the server's default ("@everyone") role that
/// every member implicitly has. `None` if they aren't a member at all.
/// A server created through `create_server` (or migrated by 0036) always
/// has a default role; a handful of test fixtures across the codebase
/// insert directly into `servers`/`server_members` with raw SQL,
/// bypassing that, and have no roles at all. For those, synthesize the
/// same bits migration 0036 would have seeded from `server_members.role`
/// (member/moderator/admin/owner), so permission resolution gives the
/// same answer either way rather than silently granting nothing.
const LEGACY_DEFAULT_BITS: Bits = Permission::VIEW_CHANNEL.0
    | Permission::SEND_MESSAGES.0
    | Permission::CREATE_INVITE.0
    | Permission::ATTACH_FILES.0
    | Permission::ADD_REACTIONS.0;

async fn legacy_fallback_bits(db: &Database, server_id: Uuid, user_id: Uuid) -> Result<Bits, AppError> {
    let role: Option<String> = sqlx::query_scalar(
        "SELECT role FROM server_members WHERE server_id = $1 AND user_id = $2",
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(match role.as_deref() {
        Some("owner") | Some("admin") => Permission::ADMINISTRATOR.0,
        Some("moderator") => LEGACY_DEFAULT_BITS | Permission::MANAGE_MESSAGES.0,
        _ => LEGACY_DEFAULT_BITS,
    })
}

async fn base_permissions(db: &Database, server_id: Uuid, user_id: Uuid) -> Result<Option<Permissions>, AppError> {
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM server_members WHERE server_id = $1 AND user_id = $2)",
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    if !is_member {
        return Ok(None);
    }

    let has_default_role: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM roles WHERE server_id = $1 AND is_default = true)")
            .bind(server_id)
            .fetch_one(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    if !has_default_role {
        return Ok(Some(Permissions(legacy_fallback_bits(db, server_id, user_id).await?)));
    }

    let bits: Vec<Bits> = sqlx::query_scalar(
        r#"
        SELECT permissions FROM roles WHERE server_id = $1 AND is_default = true
        UNION ALL
        SELECT r.permissions FROM roles r
        JOIN member_roles mr ON mr.role_id = r.id
        WHERE mr.server_id = $1 AND mr.user_id = $2
        "#,
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Some(Permissions(bits.into_iter().fold(0, |acc, b| acc | b))))
}

/// A member's effective permissions in `server_id` as a whole (no
/// channel overwrites apply at this level -- use `resolve_channel` for a
/// specific channel).
pub async fn resolve_server(db: &Database, server_id: Uuid, user_id: Uuid) -> Result<Permissions, AppError> {
    if is_unconditional_owner(db, server_id, user_id).await? {
        return Ok(Permissions::ALL);
    }
    let base = base_permissions(db, server_id, user_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("You are not a member of this server".into()))?;
    if base.has(Permission::ADMINISTRATOR) {
        return Ok(Permissions::ALL);
    }
    Ok(base)
}

/// A member's effective permissions in one specific channel: their base
/// (role-derived) permissions, with that channel's role overwrites
/// applied (denies from every matching role first, then allows from
/// every matching role), then that channel's member-specific overwrite
/// applied last, so it has the final say.
pub async fn resolve_channel(db: &Database, channel_id: Uuid, user_id: Uuid) -> Result<Permissions, AppError> {
    let server_id = channel_server_id(db, channel_id).await?;

    if is_unconditional_owner(db, server_id, user_id).await? {
        return Ok(Permissions::ALL);
    }
    let base = base_permissions(db, server_id, user_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("You are not a member of this server".into()))?;
    if base.has(Permission::ADMINISTRATOR) {
        return Ok(Permissions::ALL);
    }

    let role_ids: HashSet<Uuid> = {
        let mut ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT role_id FROM member_roles WHERE server_id = $1 AND user_id = $2",
        )
        .bind(server_id)
        .bind(user_id)
        .fetch_all(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        let default_role: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM roles WHERE server_id = $1 AND is_default = true")
                .bind(server_id)
                .fetch_optional(&db.pool)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        if let Some(id) = default_role {
            ids.push(id);
        }
        ids.into_iter().collect()
    };

    let role_overwrites: Vec<(Bits, Bits)> = if role_ids.is_empty() {
        Vec::new()
    } else {
        let ids: Vec<Uuid> = role_ids.into_iter().collect();
        sqlx::query_as("SELECT allow, deny FROM channel_role_overwrites WHERE channel_id = $1 AND role_id = ANY($2)")
            .bind(channel_id)
            .bind(&ids)
            .fetch_all(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
    };
    let combined_deny = role_overwrites.iter().fold(0, |acc, (_, deny)| acc | deny);
    let combined_allow = role_overwrites.iter().fold(0, |acc, (allow, _)| acc | allow);
    let mut perms = base.apply_overwrite(combined_allow, combined_deny);

    let member_overwrite: Option<(Bits, Bits)> = sqlx::query_as(
        "SELECT allow, deny FROM channel_member_overwrites WHERE channel_id = $1 AND user_id = $2",
    )
    .bind(channel_id)
    .bind(user_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    if let Some((allow, deny)) = member_overwrite {
        perms = perms.apply_overwrite(allow, deny);
    }

    Ok(perms)
}

/// Resolves the channel's permissions for `user_id` and requires `p`,
/// otherwise `Forbidden`.
pub async fn require_channel_permission(
    db: &Database,
    channel_id: Uuid,
    user_id: Uuid,
    p: Permission,
) -> Result<(), AppError> {
    let perms = resolve_channel(db, channel_id, user_id).await?;
    if perms.has(p) {
        Ok(())
    } else {
        Err(AppError::Forbidden(format!(
            "You don't have the {} permission in this channel",
            p.name().unwrap_or("required")
        )))
    }
}

/// Resolves the server's permissions for `user_id` and requires `p`,
/// otherwise `Forbidden`.
pub async fn require_server_permission(
    db: &Database,
    server_id: Uuid,
    user_id: Uuid,
    p: Permission,
) -> Result<(), AppError> {
    let perms = resolve_server(db, server_id, user_id).await?;
    if perms.has(p) {
        Ok(())
    } else {
        Err(AppError::Forbidden(format!(
            "You don't have the {} permission in this server",
            p.name().unwrap_or("required")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overwrite_deny_then_allow_within_the_same_overwrite() {
        let base = Permissions(Permission::VIEW_CHANNEL.0 | Permission::SEND_MESSAGES.0);
        // Deny SEND_MESSAGES, allow it back in the same overwrite -- allow wins.
        let out = base.apply_overwrite(Permission::SEND_MESSAGES.0, Permission::SEND_MESSAGES.0);
        assert!(out.has(Permission::SEND_MESSAGES));
    }

    #[test]
    fn overwrite_can_deny_a_base_permission() {
        let base = Permissions(Permission::VIEW_CHANNEL.0 | Permission::SEND_MESSAGES.0);
        let out = base.apply_overwrite(0, Permission::SEND_MESSAGES.0);
        assert!(out.has(Permission::VIEW_CHANNEL));
        assert!(!out.has(Permission::SEND_MESSAGES));
    }

    #[test]
    fn overwrite_can_grant_beyond_base() {
        let base = Permissions::NONE;
        let out = base.apply_overwrite(Permission::VIEW_CHANNEL.0, 0);
        assert!(out.has(Permission::VIEW_CHANNEL));
    }

    #[test]
    fn bits_from_names_rejects_unknown_names() {
        assert!(bits_from_names(&["not_a_real_permission".to_string()]).is_err());
    }

    #[test]
    fn bits_from_names_accepts_known_names() {
        let bits = bits_from_names(&["view_channel".to_string(), "send_messages".to_string()]).unwrap();
        assert_eq!(bits, Permission::VIEW_CHANNEL.0 | Permission::SEND_MESSAGES.0);
    }

    #[test]
    fn permission_name_roundtrips() {
        for (name, p) in Permission::ALL_NAMED {
            assert_eq!(Permission::from_name(name), Some(*p));
            assert_eq!(p.name(), Some(*name));
        }
    }
}

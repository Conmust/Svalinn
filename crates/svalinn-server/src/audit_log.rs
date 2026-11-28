//! A durable record of moderation actions within a server (kicks, bans,
//! unbans, role changes, a moderator deleting someone else's message), so
//! "who did what, and when" doesn't rely on anyone having been watching at
//! the time. See `migrations/0053_moderation_audit_log.sql` for the schema
//! and `routes::moderation` for the read side.
//!
//! [`record`] is called right after the action it's logging has already
//! succeeded. A failure here is logged (by user id only, matching
//! `email_privacy`'s convention of never trusting a log line with anything
//! sensitive) and swallowed rather than surfaced to the caller: the
//! moderation action itself already happened and already told the acting
//! moderator it succeeded, so failing their whole request at this point --
//! purely because the *record* of it couldn't be written -- would be a
//! worse outcome than a gap in the log.

use serde_json::Value;
use uuid::Uuid;

use crate::db::Database;

/// A member was kicked. `target_user_id` is who; no `reason` field exists
/// on the kick endpoint today.
pub const MEMBER_KICKED: &str = "member_kicked";
/// A member was banned. `target_user_id` is who; `reason` is whatever the
/// banning moderator gave, if anything.
pub const MEMBER_BANNED: &str = "member_banned";
/// A server ban was lifted. `target_user_id` is who.
pub const MEMBER_UNBANNED: &str = "member_unbanned";
/// A member's built-in rank role changed (member/moderator/admin).
/// `target_user_id` is who; `metadata` carries `{"old_role", "new_role"}`.
pub const ROLE_CHANGED: &str = "role_changed";
/// A custom role (see `routes::roles`) was assigned to a member.
/// `target_user_id` is who; `metadata` carries `{"role_id"}`.
pub const CUSTOM_ROLE_ASSIGNED: &str = "custom_role_assigned";
/// A custom role was removed from a member. Same shape as
/// [`CUSTOM_ROLE_ASSIGNED`].
pub const CUSTOM_ROLE_UNASSIGNED: &str = "custom_role_unassigned";
/// A moderator deleted a message that wasn't their own. `target_user_id` is
/// the message's author, `target_channel_id` is where it was,
/// `metadata` carries `{"message_id"}`. A user deleting their own message
/// is ordinary usage, not a moderation action, and is never logged here.
pub const MESSAGE_DELETED: &str = "message_deleted";

/// Records one moderation action. `action` should be one of the constants
/// above. `metadata` defaults to `{}` if you have nothing extra to attach --
/// pass `serde_json::json!({})`.
#[allow(clippy::too_many_arguments)]
pub async fn record(
    db: &Database,
    server_id: Uuid,
    actor_id: Uuid,
    action: &str,
    target_user_id: Option<Uuid>,
    target_channel_id: Option<Uuid>,
    reason: Option<&str>,
    metadata: Value,
) {
    let result = sqlx::query(
        r#"
        INSERT INTO moderation_audit_log
            (server_id, actor_id, action, target_user_id, target_channel_id, reason, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(server_id)
    .bind(actor_id)
    .bind(action)
    .bind(target_user_id)
    .bind(target_channel_id)
    .bind(reason)
    .bind(metadata)
    .execute(&db.pool)
    .await;

    if let Err(e) = result {
        eprintln!(
            "❌ Failed to record audit log entry ({action}) for server {server_id}, actor {actor_id}: {e}"
        );
    }
}

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::access::{channel_server_id, member_rank, require_member};
use crate::models::device::ParticipantDevice;
use crate::models::message::BroadcastMessage;
use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;
use crate::permissions::{resolve_channel, resolve_server, Permission};

#[derive(Serialize, FromRow)]
pub struct Channel {
    pub id: Uuid,
    pub server_id: Uuid,
    pub name: String,
    pub channel_type: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub has_unread: bool,
    /// Minimum seconds an ordinary member must wait between messages in
    /// this channel; 0 means no slowmode. See `set_channel_slowmode` and
    /// its enforcement in `routes::messages::create_message`.
    pub slowmode_seconds: i32,
}

#[derive(Deserialize)]
pub struct CreateChannelRequest {
    pub name: String,
    #[serde(default)]
    pub channel_type: Option<String>,
}

/// Channel types: "text" or "voice". Defaults to "text" when absent, for
/// backward compatibility with clients that don't send it.
fn clean_channel_type(channel_type: Option<String>) -> Result<String, AppError> {
    let channel_type = channel_type.unwrap_or_else(|| "text".to_string());
    if !["text", "voice"].contains(&channel_type.as_str()) {
        return Err(AppError::BadRequest("Invalid channel type".into()));
    }
    Ok(channel_type)
}

/// GET /api/v1/servers/:server_id/channels
///
/// Only returns channels the caller can actually view -- a channel
/// where a role/member overwrite denies `VIEW_CHANNEL` (a private
/// channel) is simply absent, the same way it's absent from message
/// reads (`messages::get_channel_messages` already requires
/// `VIEW_CHANNEL`; this is the list-level counterpart, so a hidden
/// channel never even shows up to be clicked).
pub async fn get_server_channels(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
) -> Result<Json<Vec<Channel>>, AppError> {
    require_member(&db, server_id, user_id).await?;

    // A channel is unread if it has a message newer than the user's last read.
    let channels: Vec<Channel> = sqlx::query_as(
        r#"
        SELECT
            c.id, c.server_id, c.name, COALESCE(c.type, 'text') AS channel_type, c.created_at,
            c.slowmode_seconds,
            EXISTS(
                SELECT 1 FROM messages m
                WHERE m.channel_id = c.id
                  AND m.user_id != $2
                  AND m.created_at > COALESCE(cr.last_read_at, '-infinity'::timestamptz)
            ) AS has_unread
        FROM channels c
        LEFT JOIN channel_reads cr ON cr.channel_id = c.id AND cr.user_id = $2
        WHERE c.server_id = $1
        ORDER BY c.created_at ASC
        "#,
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut visible = Vec::with_capacity(channels.len());
    for channel in channels {
        if resolve_channel(&db, channel.id, user_id).await?.has(Permission::VIEW_CHANNEL) {
            visible.push(channel);
        }
    }

    Ok(Json(visible))
}

/// POST /api/v1/servers/:server_id/channels
/// Channel names: trimmed, 1-100 characters.
fn clean_name(name: &str) -> Result<&str, AppError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("Channel name cannot be empty".into()));
    }
    if name.chars().count() > 100 {
        return Err(AppError::BadRequest("Channel name must be at most 100 characters".into()));
    }
    Ok(name)
}

/// The server members who currently hold `VIEW_CHANNEL` on this channel --
/// i.e. who a channel_created/updated/deleted event about it should reach.
/// Computed up front (before any mutation) so a channel_deleted broadcast
/// still has someone to check permissions against: by delivery time the
/// channel row, and its overwrites, no longer exist.
pub(crate) async fn members_who_can_view(db: &Database, server_id: Uuid, channel_id: Uuid) -> Result<Vec<Uuid>, AppError> {
    let member_ids: Vec<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM server_members WHERE server_id = $1")
            .bind(server_id)
            .fetch_all(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    let mut visible = Vec::with_capacity(member_ids.len());
    for user_id in member_ids {
        if resolve_channel(db, channel_id, user_id).await?.has(Permission::VIEW_CHANNEL) {
            visible.push(user_id);
        }
    }
    Ok(visible)
}

/// Renaming and deleting channels needs admin rank or above.
/// Admin rank or above always qualifies, same as before; a member who
/// isn't admin-ranked but has been granted `MANAGE_CHANNELS` through a
/// custom role now also qualifies -- purely additive, nothing that could
/// rename or delete a channel before loses that ability here.
async fn require_channel_admin(db: &Database, server_id: Uuid, user_id: Uuid) -> Result<(), AppError> {
    match member_rank(db, server_id, user_id).await? {
        Some(rank) if rank >= 3 => return Ok(()),
        Some(_) => {}
        None => return Err(AppError::Forbidden("You are not a member of this server".into())),
    }
    if resolve_server(db, server_id, user_id).await?.has(Permission::MANAGE_CHANNELS) {
        return Ok(());
    }
    Err(AppError::Forbidden("Only admins, or members with the manage_channels permission, can rename or delete channels".into()))
}

pub async fn create_channel(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
    Json(payload): Json<CreateChannelRequest>,
) -> Result<Json<Channel>, AppError> {
    let name = clean_name(&payload.name)?;
    let channel_type = clean_channel_type(payload.channel_type)?;

    require_member(&db, server_id, user_id).await?;

    let channel: Channel = sqlx::query_as(
        r#"
        INSERT INTO channels (server_id, name, type) VALUES ($1, $2, $3)
        RETURNING id, server_id, name, COALESCE(type, 'text') AS channel_type, created_at, false AS has_unread, slowmode_seconds
        "#,
    )
    .bind(server_id)
    .bind(name)
    .bind(channel_type)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Everyone else's channel list updates straight away -- but only for
    // members who can actually see this channel (it may be private from
    // the moment it's created, via its default role's overwrites).
    let recipients = members_who_can_view(&db, server_id, channel.id).await?;
    let _ = db.message_tx.send(BroadcastMessage::to_users(
        "channel_created",
        serde_json::json!({ "id": channel.id, "server_id": server_id, "name": channel.name, "channel_type": channel.channel_type, "created_at": channel.created_at }),
        recipients,
    ));

    Ok(Json(channel))
}

/// PATCH /api/v1/channels/:channel_id  `{ "name": "..." }`
pub async fn rename_channel(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(channel_id): Path<Uuid>,
    Json(payload): Json<CreateChannelRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let name = clean_name(&payload.name)?;
    let server_id = channel_server_id(&db, channel_id).await?;
    require_channel_admin(&db, server_id, user_id).await?;

    sqlx::query("UPDATE channels SET name = $1 WHERE id = $2")
        .bind(name)
        .bind(channel_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let payload = serde_json::json!({ "id": channel_id, "server_id": server_id, "name": name });
    let recipients = members_who_can_view(&db, server_id, channel_id).await?;
    let _ = db.message_tx.send(BroadcastMessage::to_users("channel_updated", payload.clone(), recipients));
    Ok(Json(payload))
}

/// Six hours -- comfortably above anything a real slowmode setting would
/// use (Discord's own UI tops out at the same value), just a backstop
/// against a typo locking a channel to an absurd wait.
pub const MAX_SLOWMODE_SECONDS: i32 = 21_600;

#[derive(Deserialize)]
pub struct SetSlowmodeRequest {
    pub seconds: i32,
}

/// PATCH /api/v1/channels/:channel_id/slowmode  `{ "seconds": 0 }`
///
/// Sets the minimum gap an ordinary member must leave between messages in
/// this channel; 0 turns slowmode off. Any non-negative value up to
/// `MAX_SLOWMODE_SECONDS` is accepted -- the client is expected to offer
/// quick presets (15s, 30s, ...) alongside a custom value, but the server
/// doesn't restrict it to those presets. Same gate as rename/delete:
/// admin rank or the `manage_channels` permission.
///
/// Enforcement itself lives in `routes::messages::create_message`; members
/// holding `manage_messages` on the channel are exempt from it, same as
/// Discord's moderator exemption.
pub async fn set_channel_slowmode(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(channel_id): Path<Uuid>,
    Json(payload): Json<SetSlowmodeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let server_id = channel_server_id(&db, channel_id).await?;
    require_channel_admin(&db, server_id, user_id).await?;

    if !(0..=MAX_SLOWMODE_SECONDS).contains(&payload.seconds) {
        return Err(AppError::BadRequest(format!(
            "slowmode seconds must be between 0 and {MAX_SLOWMODE_SECONDS}"
        )));
    }

    sqlx::query("UPDATE channels SET slowmode_seconds = $1 WHERE id = $2")
        .bind(payload.seconds)
        .bind(channel_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let payload = serde_json::json!({ "id": channel_id, "server_id": server_id, "slowmode_seconds": payload.seconds });
    let recipients = members_who_can_view(&db, server_id, channel_id).await?;
    let _ = db.message_tx.send(BroadcastMessage::to_users("channel_updated", payload.clone(), recipients));
    Ok(Json(payload))
}

/// DELETE /api/v1/channels/:channel_id — deletes the channel and its messages.
pub async fn delete_channel(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(channel_id): Path<Uuid>,
) -> Result<axum::http::StatusCode, AppError> {
    let server_id = channel_server_id(&db, channel_id).await?;
    require_channel_admin(&db, server_id, user_id).await?;

    // Who can see this channel right now -- computed before it's deleted,
    // since afterwards there's no channel (or overwrites) left to check
    // permissions against.
    let recipients = members_who_can_view(&db, server_id, channel_id).await?;

    // Messages, reactions and read markers go with the channel (ON DELETE
    // CASCADE); collect attachment files first so they can be removed too.
    let files: Vec<String> = sqlx::query_scalar(
        "SELECT attachment_url FROM messages WHERE channel_id = $1 AND attachment_url IS NOT NULL",
    )
    .bind(channel_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    sqlx::query("DELETE FROM channels WHERE id = $1")
        .bind(channel_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    crate::files::remove_stored_files(&files).await;

    let _ = db.message_tx.send(BroadcastMessage::to_users(
        "channel_deleted",
        serde_json::json!({ "id": channel_id, "server_id": server_id }),
        recipients,
    ));
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// GET /api/v1/channels/:channel_id/member-devices
///
/// Every registered device of every CURRENT member who can currently
/// VIEW this channel -- what a client needs before composing an encrypted
/// channel send (see `messages::create_message`'s `encrypted_for`
/// completeness check, which this list must match exactly: scoped the
/// same way, to `members_who_can_view`, not to raw server membership).
/// Mirrors `conversations::get_participant_devices`, but scoped to this
/// channel's current viewers rather than a fixed two-person conversation:
/// this recipient set can be large and changes continuously as members
/// join, leave, or gain/lose `VIEW_CHANNEL` on this specific channel,
/// unlike a DM's fixed pair.
///
/// A member who gains (or re-gains) `VIEW_CHANNEL` later simply has no
/// row for a message sent before they could see this channel -- there is
/// no backfill/re-share mechanism, by design (see the server-level E2EE
/// PR description). Scoping this to channel viewers, not just server
/// members, is what keeps a private channel's content keys from ever
/// reaching a member's device in the first place if they can't see that
/// channel -- see `create_message`'s doc comment for why that matters
/// more than just gating the API read path.
pub async fn get_channel_member_devices(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(channel_id): Path<Uuid>,
) -> Result<Json<Vec<ParticipantDevice>>, AppError> {
    let server_id = channel_server_id(&db, channel_id).await?;
    require_member(&db, server_id, user_id).await?;
    let mut viewer_ids = members_who_can_view(&db, server_id, channel_id).await?;
    if !viewer_ids.contains(&user_id) {
        viewer_ids.push(user_id);
    }

    let devices: Vec<ParticipantDevice> = sqlx::query_as(
        r#"
        SELECT dk.id AS device_id, dk.user_id, dk.public_key, dk.device_label, (dk.user_id = $1) AS is_me
        FROM device_keys dk
        WHERE dk.user_id = ANY($2)
        ORDER BY dk.created_at ASC
        "#,
    )
    .bind(user_id)
    .bind(&viewer_ids)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(devices))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> Database {
        dotenvy::dotenv().ok();
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is required for tests");
        Database::new(&database_url).await.expect("failed to connect to test database")
    }

    async fn create_test_user(db: &Database) -> Uuid {
        let unique = Uuid::new_v4();
        sqlx::query_scalar(
            "INSERT INTO users (username, email, password_hash, display_name) VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(format!("test_{unique}"))
        .bind(format!("test_{unique}@example.invalid"))
        .bind("not-a-real-hash")
        .bind(format!("Test User {unique}"))
        .fetch_one(&db.pool)
        .await
        .expect("failed to insert test user")
    }

    async fn create_test_server(db: &Database, owner_id: Uuid) -> Uuid {
        let server_id: Uuid = sqlx::query_scalar("INSERT INTO servers (name, owner_id) VALUES ($1, $2) RETURNING id")
            .bind(format!("Test Server {}", Uuid::new_v4()))
            .bind(owner_id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to insert test server");
        sqlx::query("INSERT INTO server_members (server_id, user_id, role) VALUES ($1, $2, 'owner')")
            .bind(server_id)
            .bind(owner_id)
            .execute(&db.pool)
            .await
            .expect("failed to insert owner membership");
        server_id
    }

    async fn add_server_member(db: &Database, server_id: Uuid, user_id: Uuid) {
        sqlx::query("INSERT INTO server_members (server_id, user_id, role) VALUES ($1, $2, 'member')")
            .bind(server_id)
            .bind(user_id)
            .execute(&db.pool)
            .await
            .expect("failed to insert member");
    }

    async fn create_test_channel(db: &Database, server_id: Uuid) -> Uuid {
        sqlx::query_scalar("INSERT INTO channels (server_id, name, type) VALUES ($1, $2, 'text') RETURNING id")
            .bind(server_id)
            .bind(format!("general-{}", Uuid::new_v4()))
            .fetch_one(&db.pool)
            .await
            .expect("failed to insert test channel")
    }

    async fn cleanup_test_server(db: &Database, server_id: Uuid) {
        let _ = sqlx::query("DELETE FROM servers WHERE id = $1").bind(server_id).execute(&db.pool).await;
    }

    async fn cleanup_test_user(db: &Database, user_id: Uuid) {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1").bind(user_id).execute(&db.pool).await;
    }

    async fn slowmode_of(db: &Database, channel_id: Uuid) -> i32 {
        sqlx::query_scalar("SELECT slowmode_seconds FROM channels WHERE id = $1")
            .bind(channel_id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to read slowmode_seconds")
    }

    #[tokio::test]
    async fn an_admin_can_set_and_clear_channel_slowmode() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;

        let _ = set_channel_slowmode(State(db.clone()), CurrentUser(owner), Path(channel), Json(SetSlowmodeRequest { seconds: 30 }))
            .await
            .expect("an owner should be able to set slowmode");
        assert_eq!(slowmode_of(&db, channel).await, 30);

        let _ = set_channel_slowmode(State(db.clone()), CurrentUser(owner), Path(channel), Json(SetSlowmodeRequest { seconds: 0 }))
            .await
            .expect("an owner should be able to turn slowmode back off");
        assert_eq!(slowmode_of(&db, channel).await, 0);

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    #[tokio::test]
    async fn an_ordinary_member_cannot_set_channel_slowmode() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let member = create_test_user(&db).await;
        add_server_member(&db, server, member).await;

        let result = set_channel_slowmode(State(db.clone()), CurrentUser(member), Path(channel), Json(SetSlowmodeRequest { seconds: 15 })).await;
        assert!(matches!(result, Err(AppError::Forbidden(_))), "an ordinary member must not be able to set slowmode, got {result:?}");
        assert_eq!(slowmode_of(&db, channel).await, 0, "the rejected attempt must not have changed anything");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, member).await;
    }

    #[tokio::test]
    async fn slowmode_seconds_out_of_range_is_rejected() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;

        let negative = set_channel_slowmode(State(db.clone()), CurrentUser(owner), Path(channel), Json(SetSlowmodeRequest { seconds: -1 })).await;
        assert!(matches!(negative, Err(AppError::BadRequest(_))), "a negative slowmode should be rejected, got {negative:?}");

        let too_large =
            set_channel_slowmode(State(db.clone()), CurrentUser(owner), Path(channel), Json(SetSlowmodeRequest { seconds: MAX_SLOWMODE_SECONDS + 1 })).await;
        assert!(matches!(too_large, Err(AppError::BadRequest(_))), "a slowmode above the max should be rejected, got {too_large:?}");

        assert_eq!(slowmode_of(&db, channel).await, 0, "neither rejected attempt should have changed anything");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    #[tokio::test]
    async fn get_server_channels_reports_the_current_slowmode() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let _ = set_channel_slowmode(State(db.clone()), CurrentUser(owner), Path(channel), Json(SetSlowmodeRequest { seconds: 45 }))
            .await
            .expect("setting slowmode should succeed");

        let channels = get_server_channels(State(db.clone()), CurrentUser(owner), Path(server))
            .await
            .expect("listing channels should succeed")
            .0;
        let listed = channels.iter().find(|c| c.id == channel).expect("the channel should be listed");
        assert_eq!(listed.slowmode_seconds, 45, "the channel list must reflect the current slowmode setting");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }
}

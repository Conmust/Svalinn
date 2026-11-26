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
        RETURNING id, server_id, name, COALESCE(type, 'text') AS channel_type, created_at, false AS has_unread
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
/// Every registered device of every CURRENT member of this channel's
/// server -- what a client needs before composing an encrypted channel
/// send (see `messages::create_message`'s `encrypted_for` completeness
/// check, which this list must match exactly). Mirrors
/// `conversations::get_participant_devices`, but scoped to server
/// membership (`server_members`) rather than a fixed two-person
/// conversation: this recipient set can be large and changes continuously
/// as members join or leave, unlike a DM's fixed pair.
///
/// A member who joins later simply has no row here for a message sent
/// before they joined -- there is no backfill/re-share mechanism, by
/// design (see the server-level E2EE PR description).
pub async fn get_channel_member_devices(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(channel_id): Path<Uuid>,
) -> Result<Json<Vec<ParticipantDevice>>, AppError> {
    let server_id = channel_server_id(&db, channel_id).await?;
    require_member(&db, server_id, user_id).await?;

    let devices: Vec<ParticipantDevice> = sqlx::query_as(
        r#"
        SELECT dk.id AS device_id, dk.user_id, dk.public_key, dk.device_label, (dk.user_id = $1) AS is_me
        FROM device_keys dk
        JOIN server_members sm ON sm.user_id = dk.user_id
        WHERE sm.server_id = $2
        ORDER BY dk.created_at ASC
        "#,
    )
    .bind(user_id)
    .bind(server_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(devices))
}

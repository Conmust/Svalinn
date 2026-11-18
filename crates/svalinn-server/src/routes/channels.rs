use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::access::{channel_server_id, member_rank, require_member};
use crate::models::message::BroadcastMessage;
use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;

#[derive(Serialize, FromRow)]
pub struct Channel {
    pub id: Uuid,
    pub server_id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub has_unread: bool,
}

#[derive(Deserialize)]
pub struct CreateChannelRequest {
    pub name: String,
}

/// GET /api/v1/servers/:server_id/channels
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
            c.id, c.server_id, c.name, c.created_at,
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

    Ok(Json(channels))
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

/// Renaming and deleting channels needs admin rank or above.
async fn require_channel_admin(db: &Database, server_id: Uuid, user_id: Uuid) -> Result<(), AppError> {
    match member_rank(db, server_id, user_id).await? {
        Some(rank) if rank >= 3 => Ok(()),
        Some(_) => Err(AppError::Forbidden("Only admins can rename or delete channels".into())),
        None => Err(AppError::Forbidden("You are not a member of this server".into())),
    }
}

pub async fn create_channel(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
    Json(payload): Json<CreateChannelRequest>,
) -> Result<Json<Channel>, AppError> {
    let name = clean_name(&payload.name)?;

    require_member(&db, server_id, user_id).await?;

    let channel: Channel = sqlx::query_as(
        r#"
        INSERT INTO channels (server_id, name) VALUES ($1, $2)
        RETURNING id, server_id, name, created_at, false AS has_unread
        "#,
    )
    .bind(server_id)
    .bind(name)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Everyone else's channel list updates straight away.
    let _ = db.message_tx.send(BroadcastMessage::to_server(
        "channel_created",
        serde_json::json!({ "id": channel.id, "server_id": server_id, "name": channel.name, "created_at": channel.created_at }),
        server_id,
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
    let _ = db.message_tx.send(BroadcastMessage::to_server("channel_updated", payload.clone(), server_id));
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

    let _ = db.message_tx.send(BroadcastMessage::to_server(
        "channel_deleted",
        serde_json::json!({ "id": channel_id, "server_id": server_id }),
        server_id,
    ));
    Ok(axum::http::StatusCode::NO_CONTENT)
}

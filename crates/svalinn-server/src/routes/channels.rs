use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::access::require_member;
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
pub async fn create_channel(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
    Json(payload): Json<CreateChannelRequest>,
) -> Result<Json<Channel>, AppError> {
    let name = payload.name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("Channel name cannot be empty".into()));
    }
    if name.chars().count() > 100 {
        return Err(AppError::BadRequest("Channel name must be at most 100 characters".into()));
    }

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

    Ok(Json(channel))
}

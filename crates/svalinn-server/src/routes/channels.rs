use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;

#[derive(Serialize, FromRow)]
pub struct Channel {
    pub id: Uuid,
    pub server_id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
pub struct CreateChannelRequest {
    pub name: String,
}

/// GET /api/v1/servers/:server_id/channels
pub async fn get_server_channels(
    State(db): State<Database>,
    CurrentUser(_user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
) -> Result<Json<Vec<Channel>>, AppError> {
    let channels: Vec<Channel> = sqlx::query_as(
        "SELECT id, server_id, name, created_at FROM channels WHERE server_id = $1 ORDER BY created_at ASC"
    )
    .bind(server_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(channels))
}

/// POST /api/v1/servers/:server_id/channels
pub async fn create_channel(
    State(db): State<Database>,
    CurrentUser(_user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
    Json(payload): Json<CreateChannelRequest>,
) -> Result<Json<Channel>, AppError> {
    // Basic validation
    let name = payload.name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("Channel name cannot be empty".into()));
    }

    let channel: Channel = sqlx::query_as(
        "INSERT INTO channels (server_id, name) VALUES ($1, $2) RETURNING id, server_id, name, created_at"
    )
    .bind(server_id)
    .bind(name)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(channel))
}
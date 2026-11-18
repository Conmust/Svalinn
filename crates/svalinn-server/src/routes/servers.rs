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

// ---------- REQUEST STRUCTS ----------

#[derive(Deserialize)]
pub struct CreateServerRequest {
    pub name: String,
}

#[derive(Deserialize)]
pub struct CreateChannelRequest {
    pub name: String,
}

#[derive(Deserialize)]
pub struct UpdateServerRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub icon_url: Option<String>,
}

// ---------- RESPONSE STRUCTS ----------

#[derive(Serialize, FromRow)]
pub struct Server {
    pub id: Uuid,
    pub name: String,
    pub owner_id: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub icon_url: Option<String>,
    pub description: Option<String>,
}

#[derive(Serialize, FromRow)]
pub struct Channel {
    pub id: Uuid,
    pub server_id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, FromRow)]
pub struct ChannelWithUnread {
    pub id: Uuid,
    pub server_id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub has_unread: bool,
}

// ---------- GET USER SERVERS ----------

pub async fn get_user_servers(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
) -> Result<Json<Vec<Server>>, AppError> {
    let servers: Vec<Server> = sqlx::query_as(
        r#"
        SELECT s.id, s.name, s.owner_id, s.created_at, s.icon_url, s.description
        FROM servers s
        JOIN server_members sm ON s.id = sm.server_id
        WHERE sm.user_id = $1
        ORDER BY s.created_at ASC
        "#,
    )
    .bind(user_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(servers))
}

// ---------- CREATE SERVER ----------

pub async fn create_server(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Json(payload): Json<CreateServerRequest>,
) -> Result<Json<Server>, AppError> {
    if payload.name.trim().is_empty() {
        return Err(AppError::BadRequest("Server name cannot be empty".into()));
    }

    let server_id = Uuid::new_v4();
    
    let mut tx = db.pool.begin().await.map_err(|e| AppError::Database(e.to_string()))?;

    sqlx::query(
        "INSERT INTO servers (id, name, owner_id) VALUES ($1, $2, $3)",
    )
    .bind(server_id)
    .bind(&payload.name)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    sqlx::query(
        "INSERT INTO server_members (server_id, user_id, role) VALUES ($1, $2, 'admin')",
    )
    .bind(server_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    tx.commit().await.map_err(|e| AppError::Database(e.to_string()))?;

    let server: Server = sqlx::query_as(
        "SELECT id, name, owner_id, created_at, icon_url, description FROM servers WHERE id = $1",
    )
    .bind(server_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(server))
}

// ---------- GET SERVER CHANNELS (with unread status) ----------

pub async fn get_server_channels(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
) -> Result<Json<Vec<ChannelWithUnread>>, AppError> {
    let channels: Vec<ChannelWithUnread> = sqlx::query_as(
        r#"
        SELECT 
            c.id, c.server_id, c.name, c.created_at,
            COALESCE(
                EXISTS(
                    SELECT 1 FROM messages m
                    WHERE m.channel_id = c.id
                    AND m.id != COALESCE(
                        (SELECT last_read_message_id FROM channel_reads WHERE user_id = $2 AND channel_id = c.id),
                        '00000000-0000-0000-0000-000000000000'::uuid
                    )
                    AND m.created_at > COALESCE(
                        (SELECT last_read_at FROM channel_reads WHERE user_id = $2 AND channel_id = c.id),
                        '1970-01-01'::timestamptz
                    )
                ),
                false
            ) as has_unread
        FROM channels c
        JOIN server_members sm ON c.server_id = sm.server_id
        WHERE c.server_id = $1 AND sm.user_id = $2
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

// ---------- CREATE CHANNEL ----------

pub async fn create_channel(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
    Json(payload): Json<CreateChannelRequest>,
) -> Result<Json<Channel>, AppError> {
    if payload.name.trim().is_empty() {
        return Err(AppError::BadRequest("Channel name cannot be empty".into()));
    }

    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM server_members WHERE server_id = $1 AND user_id = $2)",
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if !is_member {
        return Err(AppError::Forbidden("You are not a member of this server".into()));
    }

    let channel: Channel = sqlx::query_as(
        "INSERT INTO channels (server_id, name) VALUES ($1, $2) RETURNING id, server_id, name, created_at",
    )
    .bind(server_id)
    .bind(&payload.name)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(channel))
}

// ---------- UPDATE SERVER ----------

pub async fn update_server(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
    Json(payload): Json<UpdateServerRequest>,
) -> Result<Json<Server>, AppError> {
    // Check if user is admin/owner
    let role: Option<String> = sqlx::query_scalar(
        "SELECT role FROM server_members WHERE server_id = $1 AND user_id = $2",
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if !matches!(role.as_deref(), Some("admin" | "owner")) {
        return Err(AppError::Forbidden("Only admins can update server settings".into()));
    }

    // Use COALESCE to update only the provided fields, keeping existing values for None
    sqlx::query(
        "UPDATE servers SET name = COALESCE($1, name), description = COALESCE($2, description), icon_url = COALESCE($3, icon_url) WHERE id = $4",
    )
    .bind(&payload.name)
    .bind(&payload.description)
    .bind(&payload.icon_url)
    .bind(server_id)
    .execute(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Fetch the updated server
    let server: Server = sqlx::query_as(
        "SELECT id, name, owner_id, created_at, icon_url, description FROM servers WHERE id = $1",
    )
    .bind(server_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(server))
}
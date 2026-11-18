use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::access::{require_admin, require_member};
use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentSession;
use crate::files::{sign_opt, stored_path};

// ---------- REQUEST STRUCTS ----------

#[derive(Deserialize)]
pub struct CreateServerRequest {
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

// ---------- GET USER SERVERS ----------

pub async fn get_user_servers(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
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

    let mut servers = servers;
    for server in &mut servers {
        sign_opt(&mut server.icon_url, user_id, session_id);
    }
    Ok(Json(servers))
}

// ---------- CREATE SERVER ----------

pub async fn create_server(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
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

    let mut server = server;
    sign_opt(&mut server.icon_url, user_id, session_id);
    Ok(Json(server))
}

// ---------- GET SERVER ----------

pub async fn get_server(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
    Path(server_id): Path<Uuid>,
) -> Result<Json<Server>, AppError> {
    require_member(&db, server_id, user_id).await?;

    let server: Server = sqlx::query_as(
        "SELECT id, name, owner_id, created_at, icon_url, description FROM servers WHERE id = $1",
    )
    .bind(server_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut server = server;
    sign_opt(&mut server.icon_url, user_id, session_id);
    Ok(Json(server))
}

// ---------- UPDATE SERVER ----------

pub async fn update_server(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
    Path(server_id): Path<Uuid>,
    Json(payload): Json<UpdateServerRequest>,
) -> Result<Json<Server>, AppError> {
    require_admin(&db, server_id, user_id).await?;

    if let Some(name) = &payload.name {
        if name.trim().is_empty() {
            return Err(AppError::BadRequest("Server name cannot be empty".into()));
        }
    }

    // Use COALESCE to update only the provided fields, keeping existing values for None
    sqlx::query(
        "UPDATE servers SET name = COALESCE($1, name), description = COALESCE($2, description), icon_url = COALESCE($3, icon_url) WHERE id = $4",
    )
    .bind(payload.name.as_deref().map(str::trim))
    .bind(&payload.description)
    .bind(payload.icon_url.as_deref().map(stored_path))
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

    let mut server = server;
    sign_opt(&mut server.icon_url, user_id, session_id);
    Ok(Json(server))
}
#[derive(Deserialize)]
pub struct DeleteServerRequest {
    pub current_password: String,
}

/// DELETE /api/v1/servers/:server_id  `{ "current_password": "..." }`
///
/// Owner (or site owner) only. Deletes the server with its channels,
/// messages, emojis, invites and bans, and their uploaded files.
pub async fn delete_server(
    State(db): State<Database>,
    CurrentSession { user_id, .. }: CurrentSession,
    Path(server_id): Path<Uuid>,
    Json(payload): Json<DeleteServerRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    let db_err = |e: sqlx::Error| AppError::Database(e.to_string());

    let rank = crate::access::member_rank(&db, server_id, user_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("You are not a member of this server".into()))?;
    let (name, owner_id): (String, Uuid) = sqlx::query_as("SELECT name, owner_id FROM servers WHERE id = $1")
        .bind(server_id)
        .fetch_one(&db.pool)
        .await
        .map_err(db_err)?;
    if owner_id != user_id && rank < crate::access::SITE_OWNER_RANK {
        return Err(AppError::Forbidden("Only the owner can delete this server".into()));
    }

    crate::routes::users::verify_current_password(&db, user_id, &payload.current_password).await?;

    // Collect what the cascade won't clean up: members to notify and files on disk.
    let members: Vec<Uuid> = sqlx::query_scalar("SELECT user_id FROM server_members WHERE server_id = $1")
        .bind(server_id)
        .fetch_all(&db.pool)
        .await
        .map_err(db_err)?;
    let files: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT m.attachment_url FROM messages m JOIN channels c ON c.id = m.channel_id
        WHERE c.server_id = $1 AND m.attachment_url IS NOT NULL
        UNION ALL SELECT url FROM custom_emojis WHERE server_id = $1
        UNION ALL SELECT icon_url FROM servers WHERE id = $1 AND icon_url IS NOT NULL
        "#,
    )
    .bind(server_id)
    .fetch_all(&db.pool)
    .await
    .map_err(db_err)?;

    // Channels, messages, members, emojis, invites and bans cascade.
    sqlx::query("DELETE FROM servers WHERE id = $1")
        .bind(server_id)
        .execute(&db.pool)
        .await
        .map_err(db_err)?;

    crate::files::remove_stored_files(&files).await;

    for member in members {
        let _ = db.message_tx.send(crate::models::message::BroadcastMessage::to_user(
            "removed_from_server",
            serde_json::json!({ "server_id": server_id, "server_name": name, "reason": "deleted" }),
            member,
        ));
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

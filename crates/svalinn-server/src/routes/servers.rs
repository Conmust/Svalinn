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
use crate::extractors::auth::CurrentUser;

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

// ---------- GET SERVER ----------

pub async fn get_server(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
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

    Ok(Json(server))
}

// ---------- UPDATE SERVER ----------

pub async fn update_server(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
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
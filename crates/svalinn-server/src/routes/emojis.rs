use axum::{
    extract::{Multipart, Path, State},
    Json,
};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;

#[derive(Serialize, FromRow)]
pub struct Emoji {
    pub id: Uuid,
    pub server_id: Uuid,
    pub name: String,
    pub url: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// GET /api/v1/servers/:server_id/emojis
pub async fn get_server_emojis(
    State(db): State<Database>,
    CurrentUser(_user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
) -> Result<Json<Vec<Emoji>>, AppError> {
    let emojis: Vec<Emoji> = sqlx::query_as(
        "SELECT id, server_id, name, url, created_at FROM emojis WHERE server_id = $1 ORDER BY name ASC"
    )
    .bind(server_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(emojis))
}

/// POST /api/v1/servers/:server_id/emojis
pub async fn upload_emoji(
    State(db): State<Database>,
    CurrentUser(_user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<Json<Emoji>, AppError> {
    let mut name = String::new();
    let mut url = String::new();

    while let Some(field) = multipart.next_field().await.map_err(|e| AppError::BadRequest(e.to_string()))? {
        let field_name = field.name().unwrap_or("").to_string();
        
        if field_name == "name" {
            name = field.text().await.unwrap_or_default();
        } else if field_name == "file" {
            let filename = field.file_name().unwrap_or("emoji.png").to_string();
            let bytes = field.bytes().await.map_err(|e| AppError::BadRequest(e.to_string()))?.to_vec();

            let file_ext = filename.split('.').last().unwrap_or("png");
            let new_filename = format!("emoji_{}_{}.{}", Uuid::new_v4(), server_id, file_ext);
            let file_path = format!("uploads/{}", new_filename);
            
            std::fs::create_dir_all("uploads").map_err(|e| AppError::Database(e.to_string()))?;
            std::fs::write(&file_path, bytes).map_err(|e| AppError::Database(e.to_string()))?;

            url = format!("/uploads/{}", new_filename);
        }
    }

    if name.trim().is_empty() {
        return Err(AppError::BadRequest("Emoji name cannot be empty".into()));
    }

    let emoji: Emoji = sqlx::query_as(
        "INSERT INTO emojis (server_id, name, url) VALUES ($1, $2, $3) RETURNING id, server_id, name, url, created_at"
    )
    .bind(server_id)
    .bind(name.trim())
    .bind(url)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(emoji))
}

/// DELETE /api/v1/servers/:server_id/emojis/:emoji_id
pub async fn delete_emoji(
    State(db): State<Database>,
    CurrentUser(_user_id): CurrentUser,
    Path((server_id, emoji_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<()>, AppError> {
    let url: Option<String> = sqlx::query_scalar("SELECT url FROM emojis WHERE id = $1 AND server_id = $2")
        .bind(emoji_id)
        .bind(server_id)
        .fetch_optional(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if let Some(emoji_url) = url {
        let file_path = emoji_url.trim_start_matches('/');
        let _ = std::fs::remove_file(file_path);
    }

    sqlx::query("DELETE FROM emojis WHERE id = $1 AND server_id = $2")
        .bind(emoji_id)
        .bind(server_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(()))
}
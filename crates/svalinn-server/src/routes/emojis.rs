use axum::{
    extract::{Multipart, Path, State},
    Json,
};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

use crate::access::{multipart_error, require_admin, require_member, safe_extension, MAX_EMOJI_BYTES};
use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;

#[derive(Serialize, FromRow)]
pub struct Emoji {
    pub id: Uuid,
    pub server_id: Uuid,
    pub name: String,
    pub url: String,
    pub created_by: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// GET /api/v1/servers/:server_id/emojis
pub async fn get_server_emojis(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
) -> Result<Json<Vec<Emoji>>, AppError> {
    require_member(&db, server_id, user_id).await?;

    let emojis: Vec<Emoji> = sqlx::query_as(
        "SELECT id, server_id, name, url, created_by, created_at FROM custom_emojis WHERE server_id = $1 ORDER BY name ASC"
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
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<Json<Emoji>, AppError> {
    require_admin(&db, server_id, user_id).await?;

    let mut name = String::new();
    let mut url = String::new();

    while let Some(field) = multipart.next_field().await.map_err(|e| multipart_error(e, MAX_EMOJI_BYTES))? {
        let field_name = field.name().unwrap_or("").to_string();
        
        if field_name == "name" {
            name = field.text().await.unwrap_or_default();
        } else if field_name == "file" {
            let filename = field.file_name().unwrap_or("emoji.png").to_string();
            let bytes = field.bytes().await.map_err(|e| multipart_error(e, MAX_EMOJI_BYTES))?.to_vec();

            let file_ext = safe_extension(&filename, "png");
            let new_filename = format!("emoji_{}_{}.{}", Uuid::new_v4(), server_id, file_ext);
            let file_path = format!("uploads/{}", new_filename);
            
            tokio::fs::create_dir_all("uploads").await.map_err(|e| AppError::Internal(e.to_string()))?;
            tokio::fs::write(&file_path, bytes).await.map_err(|e| AppError::Internal(e.to_string()))?;

            url = format!("/uploads/{}", new_filename);
        }
    }

    let name = name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("Emoji name cannot be empty".into()));
    }
    if url.is_empty() {
        return Err(AppError::BadRequest("Emoji image file is required".into()));
    }

    let emoji: Emoji = sqlx::query_as(
        "INSERT INTO custom_emojis (server_id, name, url, created_by) VALUES ($1, $2, $3, $4) RETURNING id, server_id, name, url, created_by, created_at"
    )
    .bind(server_id)
    .bind(name)
    .bind(&url)
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| {
        // Don't leave an orphaned file behind if the insert fails.
        let _ = std::fs::remove_file(url.trim_start_matches('/'));
        match e {
            sqlx::Error::Database(db_err) if db_err.is_unique_violation() => {
                AppError::BadRequest("An emoji with that name already exists".into())
            }
            e => AppError::Database(e.to_string()),
        }
    })?;

    Ok(Json(emoji))
}

/// DELETE /api/v1/servers/:server_id/emojis/:emoji_id
pub async fn delete_emoji(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path((server_id, emoji_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<()>, AppError> {
    require_admin(&db, server_id, user_id).await?;

    let url: Option<String> = sqlx::query_scalar("SELECT url FROM custom_emojis WHERE id = $1 AND server_id = $2")
        .bind(emoji_id)
        .bind(server_id)
        .fetch_optional(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let Some(emoji_url) = url else {
        return Err(AppError::NotFound("Emoji not found".into()));
    };
    let _ = std::fs::remove_file(emoji_url.trim_start_matches('/'));

    sqlx::query("DELETE FROM custom_emojis WHERE id = $1 AND server_id = $2")
        .bind(emoji_id)
        .bind(server_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(()))
}
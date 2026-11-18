use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;

#[derive(Serialize, FromRow)]
pub struct Conversation {
    pub id: Uuid,
    pub user_id: Uuid,
    pub other_user_id: Uuid,
    pub other_username: String,
    pub last_message_content: Option<String>,
    pub last_message_at: Option<chrono::DateTime<chrono::Utc>>,
    pub unread_count: i64,
}

/// GET /api/v1/conversations
pub async fn get_user_conversations(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
) -> Result<Json<Vec<Conversation>>, AppError> {
    let conversations: Vec<Conversation> = sqlx::query_as(
        r#"
        SELECT 
            c.id,
            c.user_id,
            c.other_user_id,
            u.username AS other_username,
            c.last_message_content,
            c.last_message_at,
            c.unread_count
        FROM conversations c
        JOIN users u ON c.other_user_id = u.id
        WHERE c.user_id = $1
        ORDER BY c.last_message_at DESC NULLS LAST
        "#
    )
    .bind(user_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(conversations))
}

/// POST /api/v1/conversations/:other_user_id
pub async fn create_or_get_conversation(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(other_user_id): Path<Uuid>,
) -> Result<Json<Conversation>, AppError> {
    if user_id == other_user_id {
        return Err(AppError::BadRequest("Cannot create a conversation with yourself".into()));
    }

    // Check if conversation already exists
    let existing: Option<Conversation> = sqlx::query_as(
        r#"
        SELECT 
            c.id, c.user_id, c.other_user_id, u.username AS other_username,
            c.last_message_content, c.last_message_at, c.unread_count
        FROM conversations c
        JOIN users u ON c.other_user_id = u.id
        WHERE c.user_id = $1 AND c.other_user_id = $2
        "#
    )
    .bind(user_id)
    .bind(other_user_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if let Some(conv) = existing {
        return Ok(Json(conv));
    }

    // Create new conversation
    let new_conv: Conversation = sqlx::query_as(
        r#"
        INSERT INTO conversations (user_id, other_user_id, unread_count)
        VALUES ($1, $2, 0)
        RETURNING 
            id, user_id, other_user_id, 
            (SELECT username FROM users WHERE id = $2) AS other_username,
            last_message_content, last_message_at, unread_count
        "#
    )
    .bind(user_id)
    .bind(other_user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(new_conv))
}
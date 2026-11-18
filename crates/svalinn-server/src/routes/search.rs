use axum::{
    extract::{Query, State},
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;
use crate::routes::messages::Message;

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: String,
    pub channel_id: Option<Uuid>,
    pub conversation_id: Option<Uuid>,
    pub limit: Option<i64>,
}

pub async fn search_messages(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Query(query): Query<SearchQuery>,
) -> Result<Json<Vec<Message>>, AppError> {
    let q = query.q.trim();
    if q.is_empty() {
        return Err(AppError::BadRequest("Search query cannot be empty".into()));
    }

    if q.len() < 2 {
        return Err(AppError::BadRequest(
            "Search query must be at least 2 characters".into(),
        ));
    }

    let limit = query.limit.unwrap_or(50).min(100);
    let pattern = format!("%{}%", q);

    let messages: Vec<Message> = if let Some(channel_id) = query.channel_id {
        sqlx::query_as(
            r#"
            SELECT 
                m.id, m.channel_id, m.conversation_id, m.user_id, u.username, u.patron_tier,
                m.content, m.created_at, m.is_edited, m.updated_at, m.is_locked, m.locked_by
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.channel_id = $1
              AND m.content ILIKE $2
              AND m.id NOT IN (SELECT message_id FROM hidden_messages WHERE user_id = $3)
            ORDER BY m.created_at DESC
            LIMIT $4
            "#,
        )
        .bind(channel_id)
        .bind(&pattern)
        .bind(user_id)
        .bind(limit)
        .fetch_all(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
    } else if let Some(conversation_id) = query.conversation_id {
        sqlx::query_as(
            r#"
            SELECT 
              m.id, m.channel_id, m.conversation_id, m.user_id, u.username, u.patron_tier,
              m.content, m.created_at, m.is_edited, m.updated_at, m.is_locked, m.locked_by,
              m.is_pinned, m.pinned_by,
              m.attachment_url, m.attachment_filename, m.attachment_size, m.attachment_mime_type
              FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.conversation_id = $1
              AND m.content ILIKE $2
              AND m.id NOT IN (SELECT message_id FROM hidden_messages WHERE user_id = $3)
            ORDER BY m.created_at DESC
            LIMIT $4
            "#,
        )
        .bind(conversation_id)
        .bind(&pattern)
        .bind(user_id)
        .bind(limit)
        .fetch_all(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
    } else {
        return Err(AppError::BadRequest(
            "Must specify channel_id or conversation_id".into(),
        ));
    };

    Ok(Json(messages))
}
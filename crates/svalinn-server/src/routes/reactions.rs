use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;
use crate::routes::messages::{broadcast_reactions, reaction_context};

#[derive(Deserialize)]
pub struct AddReactionRequest {
    pub emoji: String,
}

/// POST /api/v1/messages/:message_id/reactions
///
/// Responds with `{ id, reactions }`, the message's full reaction list.
pub async fn add_reaction(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(message_id): Path<Uuid>,
    Json(payload): Json<AddReactionRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let emoji = payload.emoji.trim();
    // The column is VARCHAR(32).
    if emoji.is_empty() || emoji.chars().count() > 32 {
        return Err(AppError::BadRequest("Invalid emoji".into()));
    }

    let server_id = reaction_context(&db, message_id, user_id).await?;

    sqlx::query(
        r#"
        INSERT INTO message_reactions (message_id, user_id, emoji)
        VALUES ($1, $2, $3)
        ON CONFLICT (message_id, user_id, emoji) DO NOTHING
        "#,
    )
    .bind(message_id)
    .bind(user_id)
    .bind(emoji)
    .execute(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(broadcast_reactions(&db, message_id, user_id, server_id).await?))
}

/// DELETE /api/v1/messages/:message_id/reactions/:emoji
pub async fn remove_reaction(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path((message_id, emoji)): Path<(Uuid, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let server_id = reaction_context(&db, message_id, user_id).await?;

    sqlx::query("DELETE FROM message_reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3")
        .bind(message_id)
        .bind(user_id)
        .bind(&emoji)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(broadcast_reactions(&db, message_id, user_id, server_id).await?))
}

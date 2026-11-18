use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;
use crate::models::message::Reaction;

#[derive(Deserialize)]
pub struct AddReactionRequest {
    pub emoji: String,
}

/// POST /api/v1/messages/:message_id/reactions
pub async fn add_reaction(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(message_id): Path<Uuid>,
    Json(payload): Json<AddReactionRequest>,
) -> Result<Json<Reaction>, AppError> {
    // 1. Try to insert the reaction. 
    // We use fetch_optional because ON CONFLICT DO NOTHING might return no rows if it already existed.
    let new_reaction_row: Option<(Uuid, Uuid, Uuid, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        r#"
        INSERT INTO reactions (message_id, user_id, emoji)
        VALUES ($1, $2, $3)
        ON CONFLICT (message_id, user_id, emoji) DO NOTHING
        RETURNING id, message_id, user_id, emoji, created_at
        "#
    )
    .bind(message_id)
    .bind(user_id)
    .bind(&payload.emoji)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // 2. Get the actual row (either the newly inserted one, or fetch the existing one)
    let reaction_row: (Uuid, Uuid, Uuid, String, chrono::DateTime<chrono::Utc>) = if let Some(row) = new_reaction_row {
        row
    } else {
        sqlx::query_as(
            "SELECT id, message_id, user_id, emoji, created_at FROM reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3"
        )
        .bind(message_id)
        .bind(user_id)
        .bind(&payload.emoji)
        .fetch_one(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
    };

    // 3. Get aggregated data for this specific emoji on this message
    let agg_data: (i64, Option<Vec<Uuid>>) = sqlx::query_as(
        r#"
        SELECT COUNT(*) as count, ARRAY_AGG(user_id) as user_ids
        FROM reactions
        WHERE message_id = $1 AND emoji = $2
        "#
    )
    .bind(message_id)
    .bind(&payload.emoji)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // 4. Construct the Reaction struct manually with all fields
    let reaction = Reaction {
        id: reaction_row.0,
        message_id: reaction_row.1,
        user_id: reaction_row.2,
        emoji: reaction_row.3,
        created_at: reaction_row.4,
        count: agg_data.0,
        user_ids: agg_data.1.unwrap_or_default(),
        current_user_reacted: true,
    };

    // 5. Broadcast the reaction update to all connected clients
    let broadcast_msg = crate::models::message::BroadcastMessage {
        event_type: "reaction_added".to_string(),
        payload: serde_json::to_value(&reaction).map_err(|e| AppError::Database(e.to_string()))?,
        server_id: None,
    };
    let _ = db.message_tx.send(broadcast_msg);

    Ok(Json(reaction))
}

/// DELETE /api/v1/messages/:message_id/reactions/:emoji
pub async fn remove_reaction(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path((message_id, emoji)): Path<(Uuid, String)>,
) -> Result<Json<()>, AppError> {
    sqlx::query(
        "DELETE FROM reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3"
    )
    .bind(message_id)
    .bind(user_id)
    .bind(&emoji)
    .execute(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Broadcast the removal to all connected clients
    let broadcast_msg = crate::models::message::BroadcastMessage {
        event_type: "reaction_removed".to_string(),
        payload: serde_json::json!({
            "message_id": message_id,
            "user_id": user_id,
            "emoji": emoji
        }),
        server_id: None,
    };
    let _ = db.message_tx.send(broadcast_msg);

    Ok(Json(()))
}
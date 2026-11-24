use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;

use crate::access::require_member;
use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;
use crate::permissions::{require_channel_permission, Permission};
use crate::voice;

/// POST /api/v1/channels/:channel_id/voice/join
///
/// Marks the current user as present in this voice channel and tells the
/// rest of the server. Gated on the same permission as viewing the channel
/// at all -- there's no separate "connect" permission yet (see the module
/// docs in `voice.rs`); add one later if finer-grained control turns out
/// to be needed.
pub async fn join_voice_channel(
    Path(channel_id): Path<Uuid>,
    CurrentUser(user_id): CurrentUser,
    State(db): State<Database>,
) -> Result<Json<serde_json::Value>, AppError> {
    require_channel_permission(&db, channel_id, user_id, Permission::VIEW_CHANNEL).await?;
    let participants = voice::join(&db, channel_id, user_id).await?;
    Ok(Json(serde_json::json!({ "participants": participants })))
}

/// POST /api/v1/channels/:channel_id/voice/leave
pub async fn leave_voice_channel(
    Path(channel_id): Path<Uuid>,
    CurrentUser(user_id): CurrentUser,
    State(db): State<Database>,
) -> Result<Json<serde_json::Value>, AppError> {
    voice::leave(&db, channel_id, user_id).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET /api/v1/servers/:server_id/voice-participants
///
/// Every voice channel in the server, mapped to who's currently in it.
/// Lets the client populate the UI on opening a server; after that, the
/// `voice_channel_joined`/`voice_channel_left` WS broadcasts keep it live.
pub async fn get_server_voice_participants(
    Path(server_id): Path<Uuid>,
    CurrentUser(user_id): CurrentUser,
    State(db): State<Database>,
) -> Result<Json<std::collections::HashMap<Uuid, Vec<Uuid>>>, AppError> {
    require_member(&db, server_id, user_id).await?;

    let channel_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM channels WHERE server_id = $1 AND COALESCE(type, 'text') = 'voice'",
    )
    .bind(server_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(voice::participants_for(&db, &channel_ids).await))
}

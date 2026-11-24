//! Joining/leaving a server's voice channels, and the roster of who's in
//! each one. The signaling for the actual WebRTC mesh those participants
//! form still rides the WebSocket, same as the 1:1 calls in `routes/ws.rs`
//! -- these are just the REST endpoints that join/leave the in-memory
//! roster (`crate::voice::VoiceChannels`) and tell the client who else to
//! connect to.
//!
//! Unlike `routes/calls.rs`'s 1:1 calls, which are a plain mesh of exactly
//! two peers, a voice channel is a full mesh of everyone currently in it.
//! That stops scaling past a handful of participants (same caveat as the
//! comment at the top of the client's `lib/calls.ts`) -- fine for the
//! small-server case this app targets today, but a bigger channel would
//! need a real SFU instead of this.

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use crate::access::{channel_server_id, require_member};
use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;
use crate::models::message::BroadcastMessage;
use crate::voice::VoiceParticipant;

/// A channel must actually be a voice channel to be joined -- joining a
/// text channel's "voice session" wouldn't mean anything, and would let a
/// client ring every member of the server under an event type nothing else
/// expects.
async fn require_voice_channel(db: &Database, channel_id: Uuid) -> Result<Uuid, AppError> {
    let channel_type: Option<Option<String>> =
        sqlx::query_scalar("SELECT type FROM channels WHERE id = $1")
            .bind(channel_id)
            .fetch_optional(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    match channel_type.flatten().as_deref() {
        Some("voice") => Ok(channel_server_id(db, channel_id).await?),
        Some(_) => Err(AppError::BadRequest("That channel isn't a voice channel".into())),
        None => Err(AppError::NotFound("Channel not found".into())),
    }
}

/// POST /api/v1/channels/:channel_id/voice/join
///
/// Adds the caller to the channel's roster and returns who else is
/// already there -- the joining client offers a WebRTC connection to each
/// of them (see `initVoiceSignaling` in `lib/voiceChannel.ts`); everyone
/// already in the channel just waits for that offer, so there's no
/// glare from both sides offering at once.
pub async fn join_voice_channel(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(channel_id): Path<Uuid>,
) -> Result<Json<Vec<VoiceParticipant>>, AppError> {
    let server_id = require_voice_channel(&db, channel_id).await?;
    require_member(&db, server_id, user_id).await?;

    let username: String = sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let existing = db.voice.join(channel_id, user_id, username.clone()).await;

    let _ = db.message_tx.send(BroadcastMessage::to_server(
        "voice_participant_joined",
        serde_json::json!({ "channel_id": channel_id, "user_id": user_id, "username": username, "muted": false }),
        server_id,
    ));

    Ok(Json(existing))
}

/// POST /api/v1/channels/:channel_id/voice/leave
pub async fn leave_voice_channel(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(channel_id): Path<Uuid>,
) -> Result<axum::http::StatusCode, AppError> {
    // Not `require_voice_channel`/`require_member`: leaving must still work
    // even if the channel was deleted, or the caller was kicked, while they
    // were connected to it.
    let was_present = db.voice.leave(channel_id, user_id).await;
    if was_present {
        if let Ok(server_id) = channel_server_id(&db, channel_id).await {
            let _ = db.message_tx.send(BroadcastMessage::to_server(
                "voice_participant_left",
                serde_json::json!({ "channel_id": channel_id, "user_id": user_id }),
                server_id,
            ));
        }
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct SetVoiceStateRequest {
    pub muted: bool,
}

/// PATCH /api/v1/channels/:channel_id/voice/state  `{ "muted": bool }`
pub async fn set_voice_state(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(channel_id): Path<Uuid>,
    Json(payload): Json<SetVoiceStateRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    let updated = db.voice.set_muted(channel_id, user_id, payload.muted).await;
    if updated {
        if let Ok(server_id) = channel_server_id(&db, channel_id).await {
            let _ = db.message_tx.send(BroadcastMessage::to_server(
                "voice_state_updated",
                serde_json::json!({ "channel_id": channel_id, "user_id": user_id, "muted": payload.muted }),
                server_id,
            ));
        }
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// GET /api/v1/servers/:server_id/voice-rosters
///
/// Who's in each of this server's voice channels right now, keyed by
/// channel id (a channel with nobody in it is simply absent). Used to
/// paint the channel list's participant previews on load, and after a
/// reconnect -- the WS events alone would otherwise leave a client that
/// missed some of them with a stale picture.
pub async fn get_server_voice_rosters(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
) -> Result<Json<std::collections::HashMap<Uuid, Vec<VoiceParticipant>>>, AppError> {
    require_member(&db, server_id, user_id).await?;

    let voice_channel_ids: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM channels WHERE server_id = $1 AND type = 'voice'")
            .bind(server_id)
            .fetch_all(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(db.voice.rosters(&voice_channel_ids).await))
}

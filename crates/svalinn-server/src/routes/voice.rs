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
use crate::permissions::{require_channel_permission, resolve_channel, Permission};
use crate::voice::VoiceParticipant;

/// Sends a voice-roster event only to members who can currently view the
/// channel it's about -- exactly like `routes/messages.rs`'s `broadcast`
/// helper, and for the identical reason. `get_server_voice_rosters` already
/// filters a private voice channel's roster out of the REST response for
/// anyone denied `VIEW_CHANNEL`; without this, a member in that situation
/// would still see it live the moment someone joined, left, or muted,
/// straight over the WebSocket, with nothing more than an open connection.
/// A roster entry carries a username and a mute flag rather than ciphertext,
/// so the blast radius is smaller than the message case this mirrors -- but
/// it's still exactly the kind of "private channel" leak this app is
/// supposed to prevent, and it's the same bypass of the same permission.
async fn broadcast_to_channel_viewers(db: &Database, event_type: &str, payload: serde_json::Value, server_id: Uuid, channel_id: Uuid) {
    let recipients = match crate::routes::channels::members_who_can_view(db, server_id, channel_id).await {
        Ok(recipients) => recipients,
        Err(e) => {
            eprintln!("Failed to compute channel viewers for a {event_type} broadcast: {e}");
            return;
        }
    };
    let _ = db.message_tx.send(BroadcastMessage::to_users(event_type, payload, recipients));
}

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
    require_channel_permission(&db, channel_id, user_id, Permission::VIEW_CHANNEL).await?;

    let username: String = sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let existing = db.voice.join(channel_id, user_id, username.clone()).await;

    broadcast_to_channel_viewers(
        &db,
        "voice_participant_joined",
        serde_json::json!({ "channel_id": channel_id, "user_id": user_id, "username": username, "muted": false }),
        server_id,
        channel_id,
    )
    .await;

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
            broadcast_to_channel_viewers(
                &db,
                "voice_participant_left",
                serde_json::json!({ "channel_id": channel_id, "user_id": user_id }),
                server_id,
                channel_id,
            )
            .await;
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
            broadcast_to_channel_viewers(
                &db,
                "voice_state_updated",
                serde_json::json!({ "channel_id": channel_id, "user_id": user_id, "muted": payload.muted }),
                server_id,
                channel_id,
            )
            .await;
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

    // Don't leak who's in a voice channel the caller can't even view --
    // same private-channel overwrites that gate reading messages.
    let mut visible_ids = Vec::with_capacity(voice_channel_ids.len());
    for channel_id in voice_channel_ids {
        if resolve_channel(&db, channel_id, user_id).await?.has(Permission::VIEW_CHANNEL) {
            visible_ids.push(channel_id);
        }
    }

    Ok(Json(db.voice.rosters(&visible_ids).await))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> Database {
        dotenvy::dotenv().ok();
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is required for tests");
        Database::new(&database_url).await.expect("failed to connect to test database")
    }

    async fn create_test_user(db: &Database) -> Uuid {
        let unique = Uuid::new_v4();
        sqlx::query_scalar(
            "INSERT INTO users (username, email, password_hash, display_name) VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(format!("test_{unique}"))
        .bind(format!("test_{unique}@example.invalid"))
        .bind("not-a-real-hash")
        .bind(format!("Test User {unique}"))
        .fetch_one(&db.pool)
        .await
        .expect("failed to insert test user")
    }

    async fn create_test_server(db: &Database, owner_id: Uuid) -> Uuid {
        let server_id: Uuid = sqlx::query_scalar("INSERT INTO servers (name, owner_id) VALUES ($1, $2) RETURNING id")
            .bind(format!("Test Server {}", Uuid::new_v4()))
            .bind(owner_id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to insert test server");
        sqlx::query("INSERT INTO server_members (server_id, user_id, role) VALUES ($1, $2, 'owner')")
            .bind(server_id)
            .bind(owner_id)
            .execute(&db.pool)
            .await
            .expect("failed to insert owner membership");
        server_id
    }

    async fn add_server_member(db: &Database, server_id: Uuid, user_id: Uuid) {
        sqlx::query("INSERT INTO server_members (server_id, user_id, role) VALUES ($1, $2, 'member')")
            .bind(server_id)
            .bind(user_id)
            .execute(&db.pool)
            .await
            .expect("failed to insert member");
    }

    async fn create_test_voice_channel(db: &Database, server_id: Uuid) -> Uuid {
        sqlx::query_scalar("INSERT INTO channels (server_id, name, type) VALUES ($1, $2, 'voice') RETURNING id")
            .bind(server_id)
            .bind(format!("voice-{}", Uuid::new_v4()))
            .fetch_one(&db.pool)
            .await
            .expect("failed to insert test voice channel")
    }

    async fn cleanup_test_server(db: &Database, server_id: Uuid) {
        let _ = sqlx::query("DELETE FROM servers WHERE id = $1").bind(server_id).execute(&db.pool).await;
    }

    async fn cleanup_test_user(db: &Database, user_id: Uuid) {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1").bind(user_id).execute(&db.pool).await;
    }

    /// Mirrors `routes::messages`'s
    /// `new_message_broadcast_excludes_a_member_denied_view_channel`: a
    /// member denied `VIEW_CHANNEL` on a voice channel must not receive the
    /// live `voice_participant_joined`/`left`/`voice_state_updated` events
    /// for it, even though they're still a server member and the roster
    /// lives in one process-wide, non-permission-aware registry.
    #[tokio::test]
    async fn voice_broadcasts_exclude_a_member_denied_view_channel() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_voice_channel(&db, server).await;

        let viewer = create_test_user(&db).await;
        add_server_member(&db, server, viewer).await;
        let blocked = create_test_user(&db).await;
        add_server_member(&db, server, blocked).await;

        sqlx::query("INSERT INTO channel_member_overwrites (channel_id, user_id, allow, deny) VALUES ($1, $2, 0, $3)")
            .bind(channel)
            .bind(blocked)
            .bind(crate::permissions::Permission::VIEW_CHANNEL.0)
            .execute(&db.pool)
            .await
            .expect("inserting the member overwrite should succeed");

        let mut rx = db.message_tx.subscribe();

        // owner joins
        let _ = join_voice_channel(State(db.clone()), CurrentUser(owner), Path(channel))
            .await
            .expect("owner should be able to join the voice channel");
        let joined = rx.try_recv().expect("a voice_participant_joined event should have been broadcast");
        assert_eq!(joined.event_type, "voice_participant_joined");
        let recipients = joined.to_users.expect("voice_participant_joined must be scoped with to_users, not sent to the whole server");
        assert!(recipients.contains(&owner));
        assert!(recipients.contains(&viewer), "a member with VIEW_CHANNEL must still see who joins live");
        assert!(!recipients.contains(&blocked), "a member denied VIEW_CHANNEL must not see who joins a private voice channel");

        // owner mutes
        let _ = set_voice_state(State(db.clone()), CurrentUser(owner), Path(channel), Json(SetVoiceStateRequest { muted: true }))
            .await
            .expect("muting should succeed");
        let muted = rx.try_recv().expect("a voice_state_updated event should have been broadcast");
        assert_eq!(muted.event_type, "voice_state_updated");
        let recipients = muted.to_users.expect("voice_state_updated must be scoped with to_users, not sent to the whole server");
        assert!(recipients.contains(&viewer));
        assert!(!recipients.contains(&blocked), "a member denied VIEW_CHANNEL must not see mute state in a private voice channel");

        // owner leaves
        let _ = leave_voice_channel(State(db.clone()), CurrentUser(owner), Path(channel))
            .await
            .expect("leaving should succeed");
        let left = rx.try_recv().expect("a voice_participant_left event should have been broadcast");
        assert_eq!(left.event_type, "voice_participant_left");
        let recipients = left.to_users.expect("voice_participant_left must be scoped with to_users, not sent to the whole server");
        assert!(recipients.contains(&viewer));
        assert!(!recipients.contains(&blocked), "a member denied VIEW_CHANNEL must not see who leaves a private voice channel");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, viewer).await;
        cleanup_test_user(&db, blocked).await;
    }
}

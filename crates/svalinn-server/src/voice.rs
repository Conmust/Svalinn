//! Live, in-memory tracking of who's "in" each voice channel.
//!
//! This is deliberately just presence for voice rooms -- the same kind of
//! ephemeral state `presence.rs` tracks for online/offline -- and NOT the
//! media layer. Nothing here moves audio or video; it only tracks
//! membership and tells everyone else in the server when it changes, so the
//! UI can show who's in a voice channel. Whatever actually carries the call
//! media (a P2P mesh or an SFU, still an open decision -- see the project
//! README) plugs in on top of these join/leave events rather than replacing
//! them.
//!
//! State lives in memory, not the database: like an open WebSocket, "being
//! in a voice channel" doesn't need to survive a server restart, and a
//! restart naturally clears everyone back out, which is the right behavior
//! (nobody's still "connected" to a channel after the process that was
//! tracking it is gone).

use std::collections::{HashMap, HashSet};

use tokio::sync::Mutex;
use uuid::Uuid;

use crate::access::channel_server_id;
use crate::db::Database;
use crate::errors::AppError;
use crate::models::message::BroadcastMessage;

#[derive(Default)]
pub struct VoiceChannels {
    /// channel_id -> the set of users currently "in" that voice channel.
    participants: Mutex<HashMap<Uuid, HashSet<Uuid>>>,
}

/// Adds `user_id` to `channel_id`'s voice participants and tells every
/// member of the channel's server. Idempotent: joining twice in a row (a
/// duplicate click, a retried request) changes nothing past the first time
/// and doesn't re-broadcast.
pub async fn join(db: &Database, channel_id: Uuid, user_id: Uuid) -> Result<Vec<Uuid>, AppError> {
    let server_id = channel_server_id(db, channel_id).await?;

    let (participant_ids, joined) = {
        let mut participants = db.voice_channels.participants.lock().await;
        let set = participants.entry(channel_id).or_default();
        let joined = set.insert(user_id);
        (set.iter().copied().collect::<Vec<_>>(), joined)
    };

    if joined {
        let _ = db.message_tx.send(BroadcastMessage::to_server(
            "voice_channel_joined",
            serde_json::json!({ "channel_id": channel_id, "user_id": user_id, "participants": participant_ids }),
            server_id,
        ));
    }

    Ok(participant_ids)
}

/// Removes `user_id` from `channel_id`'s voice participants, if present, and
/// tells every member of the channel's server.
pub async fn leave(db: &Database, channel_id: Uuid, user_id: Uuid) -> Result<(), AppError> {
    let server_id = channel_server_id(db, channel_id).await?;
    remove_and_broadcast(db, channel_id, user_id, server_id).await;
    Ok(())
}

async fn remove_and_broadcast(db: &Database, channel_id: Uuid, user_id: Uuid, server_id: Uuid) {
    let removed = {
        let mut participants = db.voice_channels.participants.lock().await;
        match participants.get_mut(&channel_id) {
            Some(set) => {
                let removed = set.remove(&user_id);
                if set.is_empty() {
                    participants.remove(&channel_id);
                }
                removed
            }
            None => false,
        }
    };

    if removed {
        let _ = db.message_tx.send(BroadcastMessage::to_server(
            "voice_channel_left",
            serde_json::json!({ "channel_id": channel_id, "user_id": user_id }),
            server_id,
        ));
    }
}

/// Called when a user's WebSocket disconnects (see `routes/ws.rs`): leaves
/// every voice channel they were in, so closing the app/tab doesn't strand
/// a "ghost" participant there forever.
///
/// Simplification: this fires on ANY connection closing for that user, even
/// if they still have another tab/window open elsewhere (unlike
/// `presence.rs`, which ref-counts connections before marking someone
/// offline). Fine while nothing actually depends on this for live media,
/// but worth revisiting -- probably by ref-counting the same way presence
/// does -- once real calls ride on these join/leave events.
pub async fn leave_all_for_user(db: &Database, user_id: Uuid) {
    let channel_ids: Vec<Uuid> = {
        let participants = db.voice_channels.participants.lock().await;
        participants
            .iter()
            .filter(|(_, set)| set.contains(&user_id))
            .map(|(channel_id, _)| *channel_id)
            .collect()
    };

    for channel_id in channel_ids {
        if let Ok(server_id) = channel_server_id(db, channel_id).await {
            remove_and_broadcast(db, channel_id, user_id, server_id).await;
        }
    }
}

/// Current participants for each of the given voice channel ids. Used to
/// populate the UI when a client opens a server -- the join/leave
/// broadcasts above only cover what changes *after* that.
pub async fn participants_for(db: &Database, channel_ids: &[Uuid]) -> HashMap<Uuid, Vec<Uuid>> {
    let participants = db.voice_channels.participants.lock().await;
    channel_ids
        .iter()
        .filter_map(|id| participants.get(id).map(|set| (*id, set.iter().copied().collect())))
        .collect()
}

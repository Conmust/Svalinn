//! Online/offline tracking based on open WebSocket connections.
//!
//! A user is online while they have at least one connection open (the app can
//! be open in several windows). The status a user picked, like "busy", is kept
//! in `users.status`; `users.is_online` says whether they're connected.

use std::collections::HashMap;

use tokio::sync::Mutex;
use uuid::Uuid;

use crate::db::Database;
use crate::models::message::BroadcastMessage;

#[derive(Default)]
pub struct Presence {
    /// Open connections per user. The lock is held across the database update
    /// so a quick disconnect + reconnect can't be applied out of order.
    connections: Mutex<HashMap<Uuid, usize>>,
}

/// SQL for the status other people should see: the chosen status while
/// connected, otherwise "offline". "invisible" users appear offline.
pub const VISIBLE_STATUS_SQL: &str =
    "CASE WHEN COALESCE(u.is_online, false) THEN COALESCE(u.status, 'online') ELSE 'offline' END";

pub async fn connected(db: &Database, user_id: Uuid) {
    let mut connections = db.presence.connections.lock().await;
    let count = connections.entry(user_id).or_insert(0);
    *count += 1;
    if *count > 1 {
        return; // already online from another window
    }

    // Someone who was "offline" comes back as "online"; a chosen status like
    // "busy" is kept. "invisible" users stay hidden.
    let status: Result<String, _> = sqlx::query_scalar(&format!(
        r#"
        UPDATE users u
        SET status = CASE WHEN u.status IS NULL OR u.status = 'offline' THEN 'online' ELSE u.status END,
            is_online = (COALESCE(u.status, 'offline') <> 'invisible'),
            last_activity = NOW()
        WHERE u.id = $1
        RETURNING {VISIBLE_STATUS_SQL}
        "#
    ))
    .bind(user_id)
    .fetch_one(&db.pool)
    .await;

    if let Ok(status) = status {
        broadcast_status(db, user_id, &status).await;
    }
}

pub async fn disconnected(db: &Database, user_id: Uuid) {
    let mut connections = db.presence.connections.lock().await;
    match connections.get_mut(&user_id) {
        Some(count) if *count > 1 => {
            *count -= 1;
            return; // still connected from another window
        }
        _ => {
            connections.remove(&user_id);
        }
    }

    let updated = sqlx::query("UPDATE users SET is_online = false WHERE id = $1")
        .bind(user_id)
        .execute(&db.pool)
        .await;

    if updated.is_ok() {
        broadcast_status(db, user_id, "offline").await;
    }
}

/// Tells members of every server the user is in about their new status.
pub async fn broadcast_status(db: &Database, user_id: Uuid, status: &str) {
    let server_ids: Vec<Uuid> = sqlx::query_scalar("SELECT server_id FROM server_members WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(&db.pool)
        .await
        .unwrap_or_default();

    for server_id in server_ids {
        let _ = db.message_tx.send(BroadcastMessage {
            event_type: "presence_updated".to_string(),
            payload: serde_json::json!({ "user_id": user_id, "status": status }),
            server_id: Some(server_id),
        });
    }
}

/// Called at startup: nobody is connected yet, whatever the database says
/// (for example after a crash).
pub async fn reset(db: &Database) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET is_online = false WHERE is_online")
        .execute(&db.pool)
        .await
        .map(|_| ())
}

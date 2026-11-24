use axum::{
    extract::{Query, State, WebSocketUpgrade, ws::{CloseFrame, Message, WebSocket}},
    response::{Response, IntoResponse},
    http::StatusCode,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::db::Database;
use crate::models::message::BroadcastMessage;
use crate::sessions::{check_access, AccessDenied};

/// Client-to-server event types the WS forwards to another user, for call
/// signaling. Everything else a client sends is ignored (see
/// `handle_client_message`) -- this is deliberately an allow-list, not a
/// general relay, so the socket can't be used to message arbitrary payloads
/// to arbitrary users under other event names.
const RELAYABLE_EVENT_TYPES: &[&str] = &[
    "call-invite",
    "call-accept",
    "call-reject",
    "call-busy",
    "call-cancel",
    "call-hangup",
    "webrtc-offer",
    "webrtc-answer",
    "ice-candidate",
];

#[derive(Deserialize)]
struct ClientEvent {
    #[serde(rename = "type")]
    event_type: String,
    // The client's `wsClient.send(type, payload)` wraps everything as
    // `{ type, payload }`, so `to_user` -- set by `sendSignal` in
    // `lib/calls.ts` -- arrives nested inside `payload`, not as a sibling
    // of `type`.
    #[serde(default)]
    payload: serde_json::Value,
}

#[derive(Deserialize)]
pub struct WsQuery {
    token: Option<String>,
}

pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsQuery>,
    State(db): State<Database>,
) -> Response {
    // 1. Validate the token from the query string
    let claims = match query.token.as_deref().map(crate::extractors::auth::decode_access_token) {
        Some(Ok(claims)) => claims,
        Some(Err(e)) => {
            eprintln!("❌ WebSocket JWT decode error: {:?}", e);
            return StatusCode::UNAUTHORIZED.into_response();
        }
        None => {
            eprintln!("❌ WebSocket connection rejected: No token provided in query string");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };

    // 2. Upgrade first, then check access, so a refusal can be sent as a close
    //    code the app understands (browsers can't see an HTTP refusal here).
    ws.on_upgrade(move |socket| async move {
        handle_socket_connection(socket, claims.sub, claims.sid, db).await;
    })
}

// CodeQL flags the three log lines in this function ("connected", "Closing
// WebSocket", "disconnected") as "cleartext logging of sensitive
// information" because they interpolate `user_id`. False positive: `user_id`
// is an opaque `Uuid`, not a credential, and `AccessDenied::message()`
// (sessions.rs) returns only a fixed string or an admin-entered ban reason
// -- never a secret value.
async fn handle_socket_connection(
    socket: WebSocket,
    user_id: Uuid,
    session_id: Option<Uuid>,
    db: Database,
) {
    let (mut sender, mut receiver) = socket.split();

    // Register before checking access, so a ban landing in between still
    // reaches this connection.
    let session_id = session_id.unwrap_or_else(Uuid::nil);
    let (conn_id, mut kicked) = db.connections.register(user_id, session_id);

    if let Err(denied) = check_access(&db, user_id, session_id).await {
        db.connections.unregister(conn_id);
        let _ = sender.send(close_message(&denied)).await;
        return;
    }

    println!("🔌 User {} connected to WebSocket", user_id);
    crate::presence::connected(&db, user_id).await;

    // Outgoing messages go through one channel and one sending task.
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let closing = matches!(msg, Message::Close(_));
            if sender.send(msg).await.is_err() || closing {
                break; // client disconnected, or we just closed the connection
            }
        }
    });

    // Forward broadcast events. Events tied to a server only go to its members.
    let mut broadcast_rx = db.message_tx.subscribe();
    let pool = db.pool.clone();
    let broadcast_tx = tx.clone();
    let broadcast_task = tokio::spawn(async move {
        loop {
            let broadcast_msg = match broadcast_rx.recv().await {
                Ok(msg) => msg,
                // Slow client fell behind: skip the missed events, keep going.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };

            if let Some(target) = broadcast_msg.to_user {
                if target != user_id {
                    continue;
                }
            } else if let Some(server_id) = broadcast_msg.server_id {
                let is_member: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM server_members WHERE server_id = $1 AND user_id = $2)",
                )
                .bind(server_id)
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .unwrap_or(false);

                if !is_member {
                    continue;
                }
            }

            // File links in events are signed for this recipient's session.
            let mut broadcast_msg = broadcast_msg;
            crate::files::sign_json(&mut broadcast_msg.payload, user_id, session_id);

            if let Ok(json_str) = serde_json::to_string(&broadcast_msg) {
                if broadcast_tx.send(Message::Text(json_str)).is_err() {
                    break;
                }
            }
        }
    });

    // Run until the client leaves or access is revoked.
    loop {
        tokio::select! {
            incoming = receiver.next() => match incoming {
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(Message::Text(text))) => {
                    handle_client_message(&db, user_id, &text).await;
                }
                Some(Ok(_)) => {} // binary/ping/pong frames: nothing to act on
            },
            Some(denied) = kicked.recv() => {
                // Stop delivering events first, then tell the client why.
                broadcast_task.abort();
                println!("⛔ Closing WebSocket for user {}: {}", user_id, denied.message());
                let _ = tx.send(close_message(&denied));
                break;
            }
        }
    }

    // Clean up when the client disconnects or is kicked.
    broadcast_task.abort();
    drop(tx);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), send_task).await;
    db.connections.unregister(conn_id);
    crate::presence::disconnected(&db, user_id).await;
    crate::voice::leave_all_for_user(&db, user_id).await;
    println!("🔌 User {} disconnected from WebSocket", user_id);
}

/// Relays an allow-listed client event (call signaling) to its target user,
/// after checking the sender and target actually share a DM conversation --
/// without that, the WS could otherwise be used to ring or message any
/// user id a client cares to send, not just people already in your DMs.
async fn handle_client_message(db: &Database, from_user: Uuid, text: &str) {
    let Ok(mut event) = serde_json::from_str::<ClientEvent>(text) else { return };
    if !RELAYABLE_EVENT_TYPES.contains(&event.event_type.as_str()) {
        return;
    }

    let Some(payload_map) = event.payload.as_object_mut() else { return };
    // `to_user` rides inside the payload (see the `ClientEvent` comment
    // above); pull it out here and don't forward it, since it'd otherwise
    // land verbatim in the recipient's own `payload.to_user`, holding
    // their own id right back at them.
    let Some(to_user) = payload_map.remove("to_user").and_then(|v| v.as_str().and_then(|s| Uuid::parse_str(s).ok())) else {
        return;
    };
    if to_user == from_user {
        return;
    }

    let shares_conversation: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM conversation_participants a
            JOIN conversation_participants b ON a.conversation_id = b.conversation_id
            WHERE a.user_id = $1 AND b.user_id = $2
        )
        "#,
    )
    .bind(from_user)
    .bind(to_user)
    .fetch_one(&db.pool)
    .await
    .unwrap_or(false);

    if !shares_conversation {
        return;
    }

    // The recipient needs to know who's calling/signaling -- stamp it in
    // server-side rather than trusting a client-supplied `from_user`.
    payload_map.insert("from_user".to_string(), serde_json::Value::String(from_user.to_string()));

    let _ = db.message_tx.send(BroadcastMessage::to_user(&event.event_type, event.payload, to_user));
}

fn close_message(denied: &AccessDenied) -> Message {
    // Close reasons are limited to 123 bytes.
    let mut reason = denied.message();
    while reason.len() > 123 {
        reason.pop();
    }
    Message::Close(Some(CloseFrame { code: denied.close_code(), reason: reason.into() }))
}

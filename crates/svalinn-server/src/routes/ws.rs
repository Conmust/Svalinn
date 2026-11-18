use axum::{
    extract::{Query, State, WebSocketUpgrade, ws::{Message, WebSocket}},
    response::{Response, IntoResponse},
    http::StatusCode,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::db::Database;

#[derive(Deserialize)]
pub struct WsQuery {
    token: Option<String>,
}

pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsQuery>,
    State(db): State<Database>,
) -> Response {
    // 1. Extract and validate the token from the query string
    let user_id = match query.token {
        Some(token) => {
            match crate::extractors::auth::decode_access_token(&token) {
                Ok(claims) => claims.sub,
                Err(e) => {
                    eprintln!("❌ WebSocket JWT decode error: {:?}", e);
                    return StatusCode::UNAUTHORIZED.into_response();
                }
            }
        }
        None => {
            eprintln!("❌ WebSocket connection rejected: No token provided in query string");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };

    // 2. Upgrade the connection and pass the user_id and db to the handler
    ws.on_upgrade(move |socket| async move {
        handle_socket_connection(socket, user_id, db).await;
    })
}

async fn handle_socket_connection(
    socket: WebSocket,
    user_id: Uuid,
    db: Database,
) {
    println!("🔌 User {} connected to WebSocket", user_id);
    crate::presence::connected(&db, user_id).await;

    // 1. Split the socket into a sender and receiver
    let (mut sender, mut receiver) = socket.split();

    // 2. Create an mpsc channel for outgoing messages
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    // 3. Spawn a dedicated task to handle ALL sending to the client
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender.send(msg).await.is_err() {
                break; // Client disconnected
            }
        }
    });

    // 4. Subscribe to the global broadcast channel
    let mut broadcast_rx = db.message_tx.subscribe();

    // 5. Spawn a task to forward broadcast messages to the client's mpsc channel.
    //    Events tied to a server are only forwarded to members of that server.
    let pool = db.pool.clone();
    let broadcast_task = tokio::spawn(async move {
        loop {
            let broadcast_msg = match broadcast_rx.recv().await {
                Ok(msg) => msg,
                // Slow client fell behind: skip the missed events, keep going.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };

            if let Some(server_id) = broadcast_msg.server_id {
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

            if let Ok(json_str) = serde_json::to_string(&broadcast_msg) {
                // If send fails, the client disconnected, so we break
                if tx.send(Message::Text(json_str)).is_err() {
                    break;
                }
            }
        }
    });

    // 6. Main loop to receive messages from the client
    // Note: tokio-tungstenite automatically handles Ping/Pong frames at the protocol level!
    while let Some(Ok(msg)) = receiver.next().await {
        match msg {
            Message::Text(text) => {
                println!("📨 Received WS message from user {}: {}", user_id, text);
            }
            Message::Close(_) => {
                break;
            }
            _ => {}
        }
    }

    // 7. Clean up tasks when the client disconnects
    send_task.abort();
    broadcast_task.abort();
    crate::presence::disconnected(&db, user_id).await;
    println!("🔌 User {} disconnected from WebSocket", user_id);
}
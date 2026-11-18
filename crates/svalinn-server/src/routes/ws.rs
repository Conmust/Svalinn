use axum::{
    extract::{Query, State, WebSocketUpgrade, ws::{Message, WebSocket}},
    response::{Response, IntoResponse},
    http::StatusCode,
};
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::Deserialize;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::db::Database;
use crate::models::user::Claims; 

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
            let secret = std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "dev-secret-change-me-in-production".into());
            
            match decode::<Claims>(
                &token,
                &DecodingKey::from_secret(secret.as_bytes()),
                &Validation::new(Algorithm::HS256),
            ) {
                Ok(token_data) => {
                    println!("✅ WebSocket JWT validated for user: {}", token_data.claims.sub);
                    token_data.claims.sub
                },
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

    // 5. Spawn a task to forward broadcast messages to the client's mpsc channel
    let broadcast_task = tokio::spawn(async move {
        while let Ok(broadcast_msg) = broadcast_rx.recv().await {
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
    println!("🔌 User {} disconnected from WebSocket", user_id);
}
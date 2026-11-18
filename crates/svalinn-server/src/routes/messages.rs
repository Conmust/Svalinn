use axum::{
    extract::{Multipart, Path, State},
    Json,
};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct Message {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub content: String,
    pub attachment_url: Option<String>,
    pub attachment_filename: Option<String>,
    pub attachment_mime_type: Option<String>,
    pub attachment_size: Option<i64>,
    pub is_edited: bool,
    pub is_locked: bool,
    pub is_pinned: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// GET /api/v1/channels/:channel_id/messages
pub async fn get_channel_messages(
    State(db): State<Database>,
    CurrentUser(_user_id): CurrentUser,
    Path(channel_id): Path<Uuid>,
) -> Result<Json<Vec<Message>>, AppError> {
    let messages: Vec<Message> = sqlx::query_as(
        r#"
        SELECT 
            m.id, m.channel_id, m.user_id, u.username, m.content,
            m.attachment_url, m.attachment_filename, m.attachment_mime_type, m.attachment_size,
            m.is_edited, m.is_locked, m.is_pinned, m.created_at
        FROM messages m
        JOIN users u ON m.user_id = u.id
        WHERE m.channel_id = $1
        ORDER BY m.created_at ASC
        LIMIT 100
        "#,
    )
    .bind(channel_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(messages))
}

/// POST /api/v1/channels/:channel_id/messages
pub async fn create_message(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(channel_id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<Json<Message>, AppError> {
    let mut content = String::new();
    let mut attachment_url: Option<String> = None;
    let mut attachment_filename: Option<String> = None;
    let mut attachment_mime_type: Option<String> = None;
    let mut attachment_size: Option<i64> = None;

    // Parse multipart form data
    while let Some(field) = multipart.next_field().await.map_err(|e| AppError::BadRequest(e.to_string()))? {
        let name = field.name().unwrap_or("").to_string();
        
        if name == "content" {
            content = field.text().await.unwrap_or_default();
        } else if name == "file" {
            let filename = field.file_name().unwrap_or("file").to_string();
            let mime_type = field.content_type().unwrap_or("application/octet-stream").to_string();
            let bytes = field.bytes().await.map_err(|e| AppError::BadRequest(e.to_string()))?.to_vec();
            let size = bytes.len() as i64;

            // Save file locally
            let file_ext = filename.split('.').last().unwrap_or("bin");
            let new_filename = format!("msg_{}_{}.{}", Uuid::new_v4(), user_id, file_ext);
            let file_path = format!("uploads/{}", new_filename);
            
            std::fs::create_dir_all("uploads").map_err(|e| AppError::Database(e.to_string()))?;
            std::fs::write(&file_path, bytes).map_err(|e| AppError::Database(e.to_string()))?;

            attachment_url = Some(format!("/uploads/{}", new_filename));
            attachment_filename = Some(filename);
            attachment_mime_type = Some(mime_type);
            attachment_size = Some(size);
        }
    }

    if content.trim().is_empty() && attachment_url.is_none() {
        return Err(AppError::BadRequest("Message cannot be empty".into()));
    }

    // 1. Insert message into database
    let msg_id: Uuid = sqlx::query_scalar(
        "INSERT INTO messages (channel_id, user_id, content, attachment_url, attachment_filename, attachment_mime_type, attachment_size) 
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id"
    )
    .bind(channel_id)
    .bind(user_id)
    .bind(&content)
    .bind(&attachment_url)
    .bind(&attachment_filename)
    .bind(&attachment_mime_type)
    .bind(attachment_size)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // 2. Fetch the full message object with the username joined
    let message: Message = sqlx::query_as(
        "SELECT m.id, m.channel_id, m.user_id, u.username, m.content, m.attachment_url, m.attachment_filename, m.attachment_mime_type, m.attachment_size, m.is_edited, m.is_locked, m.is_pinned, m.created_at 
         FROM messages m JOIN users u ON m.user_id = u.id WHERE m.id = $1"
    )
    .bind(msg_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // 3. Broadcast the new message to all connected WebSocket clients!
    let broadcast_msg = crate::models::message::BroadcastMessage {
        event_type: "new_message".to_string(),
        payload: serde_json::to_value(&message).map_err(|e| AppError::Database(e.to_string()))?,
    };
    
    // Send to broadcast channel (ignore error if no receivers)
    let _ = db.message_tx.send(broadcast_msg);

    Ok(Json(message))
}

/// DELETE /api/v1/messages/:message_id
pub async fn delete_message(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(message_id): Path<Uuid>,
) -> Result<Json<()>, AppError> {
    // 1. Get message owner and server_id to check permissions
    let msg_data: Option<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT m.user_id, c.server_id FROM messages m JOIN channels c ON m.channel_id = c.id WHERE m.id = $1"
    )
    .bind(message_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let (msg_user_id, server_id) = match msg_data {
        Some(data) => data,
        None => return Err(AppError::NotFound("Message not found".into())),
    };

    // 2. Check permissions (Owner of message OR Admin/Mod of server)
    if msg_user_id != user_id {
        let role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM server_members WHERE server_id = $1 AND user_id = $2"
        )
        .bind(server_id)
        .bind(user_id)
        .fetch_optional(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if !matches!(role.as_deref(), Some("admin" | "owner" | "moderator")) {
            return Err(AppError::Forbidden("You do not have permission to delete this message".into()));
        }
    }

    // 3. Delete attachment file if it exists
    let attachment_url: Option<String> = sqlx::query_scalar("SELECT attachment_url FROM messages WHERE id = $1")
        .bind(message_id)
        .fetch_optional(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if let Some(url) = attachment_url {
        let file_path = url.trim_start_matches('/');
        let _ = std::fs::remove_file(file_path); // Ignore error if file already gone
    }

    // 4. Delete from database
    sqlx::query("DELETE FROM messages WHERE id = $1")
        .bind(message_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    // 5. Broadcast the deletion to WebSocket clients
    let broadcast_msg = crate::models::message::BroadcastMessage {
        event_type: "message_deleted".to_string(),
        payload: serde_json::json!({ "message_id": message_id }),
    };
    let _ = db.message_tx.send(broadcast_msg);

    Ok(Json(()))
}
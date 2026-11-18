use axum::{
    extract::{Multipart, Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::access::{
    channel_server_id, is_moderator, multipart_error, require_member, safe_extension, MAX_ATTACHMENT_BYTES,
};
use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::{CurrentSession, CurrentUser};
use crate::files::sign_opt;
use crate::models::message::BroadcastMessage;

/// One emoji's reactions on a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionSummary {
    pub emoji: String,
    pub count: i64,
    pub user_ids: Vec<Uuid>,
}

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
    /// Whether the *requesting* user has hidden this message.
    pub is_hidden: bool,
    pub reactions: sqlx::types::Json<Vec<ReactionSummary>>,
}

/// Columns for `Message`. `$1` must be the requesting user's id.
const MESSAGE_COLUMNS: &str = r#"
    m.id, m.channel_id, m.user_id, u.username, m.content,
    m.attachment_url, m.attachment_filename, m.attachment_mime_type, m.attachment_size,
    COALESCE(m.is_edited, false) AS is_edited,
    COALESCE(m.is_locked, false) AS is_locked,
    COALESCE(m.is_pinned, false) AS is_pinned,
    m.created_at,
    EXISTS(
        SELECT 1 FROM hidden_messages h WHERE h.message_id = m.id AND h.user_id = $1
    ) AS is_hidden,
    COALESCE((
        SELECT json_agg(json_build_object('emoji', r.emoji, 'count', r.cnt, 'user_ids', r.user_ids)
                        ORDER BY r.first_at)
        FROM (
            SELECT emoji, COUNT(*) AS cnt,
                   array_agg(user_id ORDER BY created_at) AS user_ids,
                   MIN(created_at) AS first_at
            FROM message_reactions
            WHERE message_id = m.id
            GROUP BY emoji
        ) r
    ), '[]'::json) AS reactions
"#;

async fn fetch_message(db: &Database, message_id: Uuid, viewer_id: Uuid) -> Result<Message, AppError> {
    sqlx::query_as(&format!(
        "SELECT {MESSAGE_COLUMNS} FROM messages m JOIN users u ON m.user_id = u.id WHERE m.id = $2"
    ))
    .bind(viewer_id)
    .bind(message_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Message not found".into()))
}

/// Author, server, lock state and the current user's role for a channel message.
/// Fails with NotFound if the message doesn't exist, Forbidden if the user isn't
/// in the message's server.
struct MessageContext {
    author_id: Uuid,
    server_id: Uuid,
    is_locked: bool,
    role: String,
}

async fn message_context(db: &Database, message_id: Uuid, user_id: Uuid) -> Result<MessageContext, AppError> {
    let row: Option<(Uuid, Uuid, bool)> = sqlx::query_as(
        r#"
        SELECT m.user_id, c.server_id, COALESCE(m.is_locked, false)
        FROM messages m JOIN channels c ON m.channel_id = c.id
        WHERE m.id = $1 AND c.server_id IS NOT NULL
        "#,
    )
    .bind(message_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let (author_id, server_id, is_locked) =
        row.ok_or_else(|| AppError::NotFound("Message not found".into()))?;
    let role = require_member(db, server_id, user_id).await?;

    Ok(MessageContext { author_id, server_id, is_locked, role })
}

fn require_moderator(ctx: &MessageContext) -> Result<(), AppError> {
    if is_moderator(&ctx.role) {
        Ok(())
    } else {
        Err(AppError::Forbidden("Only moderators can do this".into()))
    }
}

fn broadcast(db: &Database, event_type: &str, payload: serde_json::Value, server_id: Uuid) {
    // Ignore the error: it only means nobody is connected.
    let _ = db.message_tx.send(BroadcastMessage::to_server(event_type, payload, server_id));
}

/// Longest message content accepted.
const MAX_CONTENT_CHARS: usize = 4000;
/// Messages per page when loading history.
const PAGE_SIZE: i64 = 50;
const MAX_PAGE_SIZE: i64 = 100;

#[derive(Deserialize)]
pub struct HistoryQuery {
    /// Load messages older than this message. Omit for the latest page.
    pub before: Option<Uuid>,
    pub limit: Option<i64>,
}

/// GET /api/v1/channels/:channel_id/messages?before=<message_id>&limit=50
///
/// Returns a page of messages, oldest first: the latest ones, or with
/// `before`, the ones just older than that message. Fewer than `limit`
/// messages means there's no more history. Loading the latest page marks the
/// channel as read.
pub async fn get_channel_messages(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
    Path(channel_id): Path<Uuid>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<Vec<Message>>, AppError> {
    let server_id = channel_server_id(&db, channel_id).await?;
    require_member(&db, server_id, user_id).await?;
    let limit = query.limit.unwrap_or(PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);

    // Page by (created_at, id) so messages with the same timestamp are
    // neither skipped nor repeated.
    let messages: Vec<Message> = if let Some(before) = query.before {
        let cursor: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT created_at FROM messages WHERE id = $1 AND channel_id = $2")
                .bind(before)
                .bind(channel_id)
                .fetch_optional(&db.pool)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        let cursor = cursor.ok_or_else(|| AppError::NotFound("Message not found in this channel".into()))?;

        sqlx::query_as(&format!(
            r#"
            SELECT * FROM (
                SELECT {MESSAGE_COLUMNS}
                FROM messages m
                JOIN users u ON m.user_id = u.id
                WHERE m.channel_id = $2 AND (m.created_at, m.id) < ($3, $4)
                ORDER BY m.created_at DESC, m.id DESC
                LIMIT $5
            ) older
            ORDER BY created_at ASC, id ASC
            "#
        ))
        .bind(user_id)
        .bind(channel_id)
        .bind(cursor)
        .bind(before)
        .bind(limit)
        .fetch_all(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
    } else {
        sqlx::query_as(&format!(
            r#"
            SELECT * FROM (
                SELECT {MESSAGE_COLUMNS}
                FROM messages m
                JOIN users u ON m.user_id = u.id
                WHERE m.channel_id = $2
                ORDER BY m.created_at DESC, m.id DESC
                LIMIT $3
            ) latest
            ORDER BY created_at ASC, id ASC
            "#
        ))
        .bind(user_id)
        .bind(channel_id)
        .bind(limit)
        .fetch_all(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
    };

    if query.before.is_some() {
        let mut messages = messages;
        for m in &mut messages {
            sign_opt(&mut m.attachment_url, user_id, session_id);
        }
        return Ok(Json(messages));
    }

    // Opening a channel marks it as read, so `has_unread` clears.
    sqlx::query(
        r#"
        INSERT INTO channel_reads (user_id, channel_id, last_read_message_id, last_read_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (user_id, channel_id)
        DO UPDATE SET last_read_message_id = EXCLUDED.last_read_message_id, last_read_at = NOW()
        "#,
    )
    .bind(user_id)
    .bind(channel_id)
    .bind(messages.last().map(|m| m.id))
    .execute(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut messages = messages;
    for m in &mut messages {
        sign_opt(&mut m.attachment_url, user_id, session_id);
    }
    Ok(Json(messages))
}

/// POST /api/v1/channels/:channel_id/messages
pub async fn create_message(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
    Path(channel_id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<Json<Message>, AppError> {
    let server_id = channel_server_id(&db, channel_id).await?;
    require_member(&db, server_id, user_id).await?;

    let mut content = String::new();
    let mut attachment_url: Option<String> = None;
    let mut attachment_filename: Option<String> = None;
    let mut attachment_mime_type: Option<String> = None;
    let mut attachment_size: Option<i64> = None;

    // Parse multipart form data
    while let Some(field) = multipart.next_field().await.map_err(|e| multipart_error(e, MAX_ATTACHMENT_BYTES))? {
        let name = field.name().unwrap_or("").to_string();

        if name == "content" {
            content = field.text().await.unwrap_or_default();
        } else if name == "file" {
            let filename = field.file_name().unwrap_or("file").to_string();
            let mime_type = field.content_type().unwrap_or("application/octet-stream").to_string();
            let bytes = field.bytes().await.map_err(|e| multipart_error(e, MAX_ATTACHMENT_BYTES))?.to_vec();
            let size = bytes.len() as i64;

            // Save file locally
            let file_ext = safe_extension(&filename, "bin");
            let new_filename = format!("msg_{}_{}.{}", Uuid::new_v4(), user_id, file_ext);
            let file_path = format!("uploads/{}", new_filename);

            tokio::fs::create_dir_all("uploads").await.map_err(|e| AppError::Internal(e.to_string()))?;
            tokio::fs::write(&file_path, bytes).await.map_err(|e| AppError::Internal(e.to_string()))?;

            attachment_url = Some(format!("/uploads/{}", new_filename));
            attachment_filename = Some(filename);
            attachment_mime_type = Some(mime_type);
            attachment_size = Some(size);
        }
    }

    if content.chars().count() > MAX_CONTENT_CHARS {
        return Err(AppError::BadRequest(format!("Messages can be at most {MAX_CONTENT_CHARS} characters")));
    }
    if content.trim().is_empty() && attachment_url.is_none() {
        return Err(AppError::BadRequest("Message cannot be empty".into()));
    }

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

    let mut message = fetch_message(&db, msg_id, user_id).await?;

    // Broadcast the stored path; each recipient's connection signs it for them.
    let payload = serde_json::to_value(&message).map_err(|e| AppError::Internal(e.to_string()))?;
    broadcast(&db, "new_message", payload, server_id);

    sign_opt(&mut message.attachment_url, user_id, session_id);
    Ok(Json(message))
}

/// DELETE /api/v1/messages/:message_id
///
/// The author or a moderator can delete a message, unless it is locked.
pub async fn delete_message(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(message_id): Path<Uuid>,
) -> Result<Json<()>, AppError> {
    let ctx = message_context(&db, message_id, user_id).await?;

    if ctx.author_id != user_id && !is_moderator(&ctx.role) {
        return Err(AppError::Forbidden("You do not have permission to delete this message".into()));
    }
    if ctx.is_locked {
        return Err(AppError::Forbidden("This message is locked. Unlock it before deleting.".into()));
    }

    let attachment_url: Option<String> = sqlx::query_scalar(
        "DELETE FROM messages WHERE id = $1 RETURNING attachment_url",
    )
    .bind(message_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if let Some(url) = attachment_url {
        let _ = tokio::fs::remove_file(url.trim_start_matches('/')).await; // already gone is fine
    }

    broadcast(&db, "message_deleted", serde_json::json!({ "message_id": message_id }), ctx.server_id);

    Ok(Json(()))
}

/// POST/DELETE /api/v1/messages/:message_id/lock
///
/// Locked messages can't be deleted by anyone until a moderator unlocks them.
pub async fn lock_message(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(message_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    set_locked(db, user_id, message_id, true).await
}

pub async fn unlock_message(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(message_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    set_locked(db, user_id, message_id, false).await
}

async fn set_locked(db: Database, user_id: Uuid, message_id: Uuid, locked: bool) -> Result<Json<serde_json::Value>, AppError> {
    let ctx = message_context(&db, message_id, user_id).await?;
    require_moderator(&ctx)?;

    sqlx::query("UPDATE messages SET is_locked = $1, locked_by = $2 WHERE id = $3")
        .bind(locked)
        .bind(if locked { Some(user_id) } else { None })
        .bind(message_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let payload = serde_json::json!({ "id": message_id, "is_locked": locked });
    broadcast(&db, "message_updated", payload.clone(), ctx.server_id);
    Ok(Json(payload))
}

/// POST/DELETE /api/v1/messages/:message_id/pin
pub async fn pin_message(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(message_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    set_pinned(db, user_id, message_id, true).await
}

pub async fn unpin_message(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(message_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    set_pinned(db, user_id, message_id, false).await
}

async fn set_pinned(db: Database, user_id: Uuid, message_id: Uuid, pinned: bool) -> Result<Json<serde_json::Value>, AppError> {
    let ctx = message_context(&db, message_id, user_id).await?;
    require_moderator(&ctx)?;

    sqlx::query("UPDATE messages SET is_pinned = $1, pinned_by = $2 WHERE id = $3")
        .bind(pinned)
        .bind(if pinned { Some(user_id) } else { None })
        .bind(message_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let payload = serde_json::json!({ "id": message_id, "is_pinned": pinned });
    broadcast(&db, "message_updated", payload.clone(), ctx.server_id);
    Ok(Json(payload))
}

/// POST/DELETE /api/v1/messages/:message_id/hide
///
/// Hiding only affects the current user's view, so nothing is broadcast.
pub async fn hide_message(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(message_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    message_context(&db, message_id, user_id).await?;

    sqlx::query(
        "INSERT INTO hidden_messages (user_id, message_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(user_id)
    .bind(message_id)
    .execute(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({ "id": message_id, "is_hidden": true })))
}

pub async fn unhide_message(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(message_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    sqlx::query("DELETE FROM hidden_messages WHERE user_id = $1 AND message_id = $2")
        .bind(user_id)
        .bind(message_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({ "id": message_id, "is_hidden": false })))
}

/// Current reactions on a message, broadcast after every change.
pub(crate) async fn broadcast_reactions(db: &Database, message_id: Uuid, user_id: Uuid, server_id: Uuid) -> Result<serde_json::Value, AppError> {
    let message = fetch_message(db, message_id, user_id).await?;
    let payload = serde_json::json!({ "id": message_id, "reactions": message.reactions });
    broadcast(db, "message_updated", payload.clone(), server_id);
    Ok(payload)
}

/// Exposed for the reactions routes.
pub(crate) async fn reaction_context(db: &Database, message_id: Uuid, user_id: Uuid) -> Result<Uuid, AppError> {
    Ok(message_context(db, message_id, user_id).await?.server_id)
}

#[derive(Deserialize)]
pub struct EditMessageRequest {
    pub content: String,
}

/// PATCH /api/v1/messages/:message_id  `{ "content": "..." }` — authors only.
pub async fn edit_message(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(message_id): Path<Uuid>,
    Json(payload): Json<EditMessageRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let ctx = message_context(&db, message_id, user_id).await?;
    if ctx.author_id != user_id {
        return Err(AppError::Forbidden("You can only edit your own messages".into()));
    }
    if payload.content.chars().count() > MAX_CONTENT_CHARS {
        return Err(AppError::BadRequest(format!("Messages can be at most {MAX_CONTENT_CHARS} characters")));
    }

    let has_attachment: bool = sqlx::query_scalar("SELECT attachment_url IS NOT NULL FROM messages WHERE id = $1")
        .bind(message_id)
        .fetch_one(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    if payload.content.trim().is_empty() && !has_attachment {
        return Err(AppError::BadRequest("Message cannot be empty. Delete it instead.".into()));
    }

    sqlx::query("UPDATE messages SET content = $1, is_edited = true, updated_at = NOW() WHERE id = $2")
        .bind(&payload.content)
        .bind(message_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let update = serde_json::json!({ "id": message_id, "content": payload.content, "is_edited": true });
    broadcast(&db, "message_updated", update.clone(), ctx.server_id);
    Ok(Json(update))
}

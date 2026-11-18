use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;
use crate::models::conversation::ConversationWithParticipant;
use crate::models::message::BroadcastMessage;

/// Columns for `ConversationWithParticipant`: the conversation plus the
/// *other* participant's identity and online status. `$1` must be the
/// requesting user's id.
const CONVERSATION_COLUMNS: &str = r#"
    c.id, c.created_at,
    other.user_id AS participant_id,
    u.username AS participant_username,
    COALESCE(u.is_online, false) AS participant_is_online
"#;

/// Joins a conversation to its other participant (and that user's row), for
/// the requesting user `$1`. Callers add their own WHERE/ORDER BY.
const CONVERSATION_JOIN: &str = r#"
    FROM conversations c
    JOIN conversation_participants me ON me.conversation_id = c.id AND me.user_id = $1
    JOIN conversation_participants other ON other.conversation_id = c.id AND other.user_id != $1
    JOIN users u ON u.id = other.user_id
"#;

async fn fetch_conversation(db: &Database, conversation_id: Uuid, user_id: Uuid) -> Result<ConversationWithParticipant, AppError> {
    sqlx::query_as(&format!(
        "SELECT {CONVERSATION_COLUMNS} {CONVERSATION_JOIN} WHERE c.id = $2"
    ))
    .bind(user_id)
    .bind(conversation_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Conversation not found".into()))
}

/// Fails with NotFound/Forbidden unless `user_id` is a participant of
/// `conversation_id`.
async fn require_participant(db: &Database, conversation_id: Uuid, user_id: Uuid) -> Result<(), AppError> {
    let is_participant: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM conversation_participants WHERE conversation_id = $1 AND user_id = $2)",
    )
    .bind(conversation_id)
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if is_participant {
        Ok(())
    } else {
        Err(AppError::Forbidden("You are not a participant in this conversation".into()))
    }
}

/// GET /api/v1/conversations
///
/// Lists the current user's conversations, most recently active first
/// (conversations with no messages yet sort last).
pub async fn get_user_conversations(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
) -> Result<Json<Vec<ConversationWithParticipant>>, AppError> {
    let conversations: Vec<ConversationWithParticipant> = sqlx::query_as(&format!(
        r#"
        SELECT {CONVERSATION_COLUMNS}
        {CONVERSATION_JOIN}
        LEFT JOIN (
            SELECT conversation_id, MAX(created_at) AS last_message_at
            FROM messages
            WHERE conversation_id IS NOT NULL
            GROUP BY conversation_id
        ) lm ON lm.conversation_id = c.id
        ORDER BY lm.last_message_at DESC NULLS LAST, c.created_at DESC
        "#
    ))
    .bind(user_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(conversations))
}

#[derive(Deserialize)]
pub struct CreateConversationRequest {
    pub participant_id: Uuid,
}

/// POST /api/v1/conversations  `{ "participant_id": "..." }`
///
/// Creates (or returns the existing) conversation between the current user
/// and `participant_id`.
pub async fn create_or_get_conversation(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Json(payload): Json<CreateConversationRequest>,
) -> Result<Json<ConversationWithParticipant>, AppError> {
    let other_user_id = payload.participant_id;
    if user_id == other_user_id {
        return Err(AppError::BadRequest("Cannot create a conversation with yourself".into()));
    }

    // Fail fast on a bogus participant rather than letting the later INSERT
    // hit the FK constraint and surface as an opaque database error.
    let participant_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
        .bind(other_user_id)
        .fetch_one(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    if !participant_exists {
        return Err(AppError::NotFound("User not found".into()));
    }

    // Sort the pair so the advisory lock key is the same regardless of which
    // user is "current user" vs "other user", so both orderings serialize
    // against each other.
    let (lo, hi) = if user_id < other_user_id { (user_id, other_user_id) } else { (other_user_id, user_id) };

    let mut tx = db.pool.begin().await.map_err(|e| AppError::Database(e.to_string()))?;

    // Serializes concurrent create-or-get calls for this pair of users so
    // they can't both pass the SELECT below and insert duplicate
    // conversations. Transaction-scoped: released automatically on commit
    // or rollback.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))")
        .bind(lo.to_string())
        .bind(hi.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let existing_id: Option<Uuid> = sqlx::query_scalar(
        r#"
        SELECT p1.conversation_id
        FROM conversation_participants p1
        JOIN conversation_participants p2 ON p2.conversation_id = p1.conversation_id
        WHERE p1.user_id = $1 AND p2.user_id = $2
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .bind(other_user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let conversation_id = if let Some(id) = existing_id {
        id
    } else {
        let new_id: Uuid = sqlx::query_scalar("INSERT INTO conversations DEFAULT VALUES RETURNING id")
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        sqlx::query(
            "INSERT INTO conversation_participants (conversation_id, user_id) VALUES ($1, $2), ($1, $3)",
        )
        .bind(new_id)
        .bind(user_id)
        .bind(other_user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        new_id
    };

    tx.commit().await.map_err(|e| AppError::Database(e.to_string()))?;

    let conversation = fetch_conversation(&db, conversation_id, user_id).await?;
    Ok(Json(conversation))
}

/// A direct message within a conversation. Mirrors `routes::messages::Message`
/// where the shapes overlap, but `channel_id` doesn't apply to DMs so it's
/// left out rather than carried as an always-null field.
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct ConversationMessage {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub content: String,
    pub attachment_url: Option<String>,
    pub attachment_filename: Option<String>,
    pub attachment_mime_type: Option<String>,
    pub attachment_size: Option<i64>,
    pub is_edited: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

const CONVERSATION_MESSAGE_COLUMNS: &str = r#"
    m.id, m.conversation_id, m.user_id, u.username, m.content,
    m.attachment_url, m.attachment_filename, m.attachment_mime_type, m.attachment_size,
    COALESCE(m.is_edited, false) AS is_edited,
    m.created_at
"#;

/// Messages per page when loading DM history.
const PAGE_SIZE: i64 = 50;
const MAX_PAGE_SIZE: i64 = 100;

#[derive(Deserialize)]
pub struct HistoryQuery {
    /// Load messages older than this message. Omit for the latest page.
    pub before: Option<Uuid>,
    pub limit: Option<i64>,
}

/// GET /api/v1/conversations/:id/messages?before=<message_id>&limit=50
///
/// Returns a page of the conversation's messages, oldest first: the latest
/// ones, or with `before`, the ones just older than that message. Fewer than
/// `limit` messages means there's no more history. The current user must be
/// a participant.
pub async fn get_conversation_messages(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(conversation_id): Path<Uuid>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<Vec<ConversationMessage>>, AppError> {
    require_participant(&db, conversation_id, user_id).await?;
    let limit = query.limit.unwrap_or(PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);

    // Page by (created_at, id) so messages with the same timestamp are
    // neither skipped nor repeated.
    let messages: Vec<ConversationMessage> = if let Some(before) = query.before {
        let cursor: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT created_at FROM messages WHERE id = $1 AND conversation_id = $2")
                .bind(before)
                .bind(conversation_id)
                .fetch_optional(&db.pool)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        let cursor = cursor.ok_or_else(|| AppError::NotFound("Message not found in this conversation".into()))?;

        sqlx::query_as(&format!(
            r#"
            SELECT * FROM (
                SELECT {CONVERSATION_MESSAGE_COLUMNS}
                FROM messages m
                JOIN users u ON m.user_id = u.id
                WHERE m.conversation_id = $1 AND (m.created_at, m.id) < ($2, $3)
                ORDER BY m.created_at DESC, m.id DESC
                LIMIT $4
            ) older
            ORDER BY created_at ASC, id ASC
            "#
        ))
        .bind(conversation_id)
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
                SELECT {CONVERSATION_MESSAGE_COLUMNS}
                FROM messages m
                JOIN users u ON m.user_id = u.id
                WHERE m.conversation_id = $1
                ORDER BY m.created_at DESC, m.id DESC
                LIMIT $2
            ) latest
            ORDER BY created_at ASC, id ASC
            "#
        ))
        .bind(conversation_id)
        .bind(limit)
        .fetch_all(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
    };

    Ok(Json(messages))
}

/// Longest message content accepted (matches channel messages).
const MAX_CONTENT_CHARS: usize = 4000;

#[derive(Deserialize)]
pub struct SendDirectMessageRequest {
    pub content: String,
    pub attachment_url: Option<String>,
    pub attachment_filename: Option<String>,
    pub attachment_size: Option<i64>,
    pub attachment_mime_type: Option<String>,
}

/// POST /api/v1/conversations/:id/messages
///
/// The conversation id in the path is authoritative; a `conversation_id` in
/// the body (the desktop client sends one) is ignored.
pub async fn send_conversation_message(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(conversation_id): Path<Uuid>,
    Json(payload): Json<SendDirectMessageRequest>,
) -> Result<Json<ConversationMessage>, AppError> {
    require_participant(&db, conversation_id, user_id).await?;

    if payload.content.chars().count() > MAX_CONTENT_CHARS {
        return Err(AppError::BadRequest(format!("Messages can be at most {MAX_CONTENT_CHARS} characters")));
    }
    if payload.content.trim().is_empty() && payload.attachment_url.is_none() {
        return Err(AppError::BadRequest("Message cannot be empty".into()));
    }

    let msg_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO messages (conversation_id, channel_id, user_id, content, attachment_url, attachment_filename, attachment_mime_type, attachment_size)
        VALUES ($1, NULL, $2, $3, $4, $5, $6, $7)
        RETURNING id
        "#,
    )
    .bind(conversation_id)
    .bind(user_id)
    .bind(&payload.content)
    .bind(&payload.attachment_url)
    .bind(&payload.attachment_filename)
    .bind(&payload.attachment_mime_type)
    .bind(payload.attachment_size)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let message: ConversationMessage = sqlx::query_as(&format!(
        "SELECT {CONVERSATION_MESSAGE_COLUMNS} FROM messages m JOIN users u ON m.user_id = u.id WHERE m.id = $1"
    ))
    .bind(msg_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Notify the other participant(s) over the websocket; the sender gets
    // the new message back in this response already.
    let other_participants: Vec<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM conversation_participants WHERE conversation_id = $1 AND user_id != $2",
    )
    .bind(conversation_id)
    .bind(user_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if let Ok(payload) = serde_json::to_value(&message) {
        for recipient in other_participants {
            let _ = db.message_tx.send(BroadcastMessage::to_user("new_direct_message", payload.clone(), recipient));
        }
    }

    Ok(Json(message))
}

use std::collections::HashSet;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::access::{channel_server_id, is_moderator, require_member};
use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::{CurrentSession, CurrentUser};
use crate::files::sign_opt;
use crate::models::device::{EncryptedRecipient, MessageRecipientPayload};
use crate::models::message::BroadcastMessage;
use crate::routes::conversations::{
    fetch_recipients_for_messages, MAX_ATTACHMENT_KEY_CIPHERTEXT_B64_CHARS, MAX_FANOUT_CIPHERTEXT_B64_CHARS,
    MAX_FANOUT_NONCE_B64_CHARS, MAX_RATCHET_HEADER_JSON_CHARS,
};

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
    /// The author's nickname in this message's server, if they have one set
    /// -- resolved live (like `username`), so renaming updates history too.
    pub nickname: Option<String>,
    pub avatar_url: Option<String>,
    /// Plaintext content, or `None` for a per-device fan-out encrypted
    /// message -- its ciphertext is in `recipients` instead. Unlike DMs,
    /// channel messages have no legacy single-device-era encrypted path:
    /// `is_encrypted` true always means `content` is `None` here.
    pub content: Option<String>,
    pub attachment_url: Option<String>,
    pub attachment_filename: Option<String>,
    pub attachment_mime_type: Option<String>,
    pub attachment_size: Option<i64>,
    /// Base64 `crypto_secretbox` nonce for the encrypted attachment blob at
    /// `attachment_url`. `None` when there's no attachment or it's
    /// plaintext (pre-E2EE) history.
    pub attachment_nonce: Option<String>,
    pub is_edited: bool,
    /// Whether this message went through the per-device fan-out send path.
    /// False for all history that predates server-level E2EE.
    pub is_encrypted: bool,
    /// Unused for channel messages (no legacy single-device path exists
    /// here) -- always `None`. Kept so `Message` can share `MESSAGE_COLUMNS`
    /// with the generic `messages` table columns without a mismatch.
    pub nonce: Option<String>,
    pub is_locked: bool,
    pub is_pinned: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Whether the *requesting* user has hidden this message.
    pub is_hidden: bool,
    pub reactions: sqlx::types::Json<Vec<ReactionSummary>>,
    /// Per-device ciphertext for a fan-out message. Populated manually
    /// after the main `SELECT` (see `fetch_recipients_for_messages`), never
    /// a DB column itself. From the history-fetch endpoint, at most one
    /// entry -- this device's own, if any. From the broadcast/create-
    /// response path, every recipient device's entry.
    #[sqlx(skip)]
    pub recipients: Vec<MessageRecipientPayload>,
}

/// Columns for `Message`. `$1` must be the requesting user's id.
const MESSAGE_COLUMNS: &str = r#"
    m.id, m.channel_id, m.user_id, u.username, sm.nickname, u.avatar_url, m.content,
    m.attachment_url, m.attachment_filename, m.attachment_mime_type, m.attachment_size, m.attachment_nonce,
    COALESCE(m.is_edited, false) AS is_edited,
    m.is_encrypted, m.nonce,
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
    let mut message: Message = sqlx::query_as(&format!(
        r#"
        SELECT {MESSAGE_COLUMNS}
        FROM messages m
        JOIN users u ON m.user_id = u.id
        JOIN channels c ON c.id = m.channel_id
        LEFT JOIN server_members sm ON sm.server_id = c.server_id AND sm.user_id = m.user_id
        WHERE m.id = $2
        "#
    ))
    .bind(viewer_id)
    .bind(message_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Message not found".into()))?;

    // Every recipient device's entry, not just the viewer's own -- used
    // both for the create-response and for the WebSocket broadcast
    // payload, where each connected client filters down to its own device
    // client-side (see `ws.rs`). The history-fetch endpoint below uses a
    // narrower, per-device filter instead.
    let recipients_by_message = fetch_recipients_for_messages(db, &[message.id], None).await?;
    if let Some(entries) = recipients_by_message.get(&message.id) {
        message.recipients = entries.clone();
    }
    Ok(message)
}

/// Author, server, lock state and the current user's role for a channel message.
/// Fails with NotFound if the message doesn't exist, Forbidden if the user isn't
/// in the message's server.
struct MessageContext {
    author_id: Uuid,
    server_id: Uuid,
    is_locked: bool,
    is_encrypted: bool,
    role: String,
}

async fn message_context(db: &Database, message_id: Uuid, user_id: Uuid) -> Result<MessageContext, AppError> {
    let row: Option<(Uuid, Uuid, bool, bool)> = sqlx::query_as(
        r#"
        SELECT m.user_id, c.server_id, COALESCE(m.is_locked, false), m.is_encrypted
        FROM messages m JOIN channels c ON m.channel_id = c.id
        WHERE m.id = $1 AND c.server_id IS NOT NULL
        "#,
    )
    .bind(message_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let (author_id, server_id, is_locked, is_encrypted) =
        row.ok_or_else(|| AppError::NotFound("Message not found".into()))?;
    let role = require_member(db, server_id, user_id).await?;

    Ok(MessageContext { author_id, server_id, is_locked, is_encrypted, role })
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
    /// This device's own id, needed to get back any fan-out message's
    /// ciphertext at all -- omitting it (or passing a device id that isn't
    /// the caller's own) is indistinguishable from an unrecognized device,
    /// so every such message comes back with no ciphertext. Mirrors
    /// `conversations::HistoryQuery`.
    pub device_id: Option<Uuid>,
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
    crate::permissions::require_channel_permission(&db, channel_id, user_id, crate::permissions::Permission::VIEW_CHANNEL).await?;
    let limit = query.limit.unwrap_or(PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);

    // Page by (created_at, id) so messages with the same timestamp are
    // neither skipped nor repeated.
    let mut messages: Vec<Message> = if let Some(before) = query.before {
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
                JOIN channels c ON c.id = m.channel_id
                LEFT JOIN server_members sm ON sm.server_id = c.server_id AND sm.user_id = m.user_id
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
                JOIN channels c ON c.id = m.channel_id
                LEFT JOIN server_members sm ON sm.server_id = c.server_id AND sm.user_id = m.user_id
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

    // A client that never set up per-device keys (or just hasn't told us
    // which device it is) must never see ANY device's ciphertext for a
    // fan-out message -- not even by accident via a NULL-matches-anything
    // filter bug. `Uuid::nil()` is never a real device id, so filtering by
    // it deterministically yields zero rows.
    //
    // `device_id` is caller-supplied and otherwise unverified: without
    // confirming it's actually one of the caller's OWN registered devices,
    // a member could pass another member's device_id and receive that
    // device's per-device ciphertext/nonce instead of their own. Mirrors
    // `conversations::get_conversation_messages`'s identical check.
    let device_filter = match query.device_id {
        Some(id) => {
            let owned: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM device_keys WHERE id = $1 AND user_id = $2)")
                    .bind(id)
                    .bind(user_id)
                    .fetch_one(&db.pool)
                    .await
                    .map_err(|e| AppError::Database(e.to_string()))?;
            if owned { id } else { Uuid::nil() }
        }
        None => Uuid::nil(),
    };
    let message_ids: Vec<Uuid> = messages.iter().map(|m| m.id).collect();
    let recipients_by_message = fetch_recipients_for_messages(&db, &message_ids, Some(device_filter)).await?;
    for m in &mut messages {
        if let Some(entries) = recipients_by_message.get(&m.id) {
            m.recipients = entries.clone();
        }
    }

    if query.before.is_some() {
        for m in &mut messages {
            sign_opt(&mut m.attachment_url, user_id, session_id);
            sign_opt(&mut m.avatar_url, user_id, session_id);
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

    for m in &mut messages {
        sign_opt(&mut m.attachment_url, user_id, session_id);
        sign_opt(&mut m.avatar_url, user_id, session_id);
    }
    Ok(Json(messages))
}

/// Request body for `POST /api/v1/channels/:channel_id/messages`.
///
/// Channel messages are mandatory end-to-end encrypted: there is no
/// plaintext send path and no legacy single-device path either (unlike
/// DMs, which still support both for backward compatibility with history
/// that predates per-device fan-out -- channels never had that history to
/// preserve, so this cuts over cleanly). An attachment, if any, must
/// already be uploaded as its encrypted ciphertext blob via the generic
/// `POST /api/v1/upload` endpoint (same as the DM flow) before this is
/// called -- this endpoint only ever stores a reference to it.
#[derive(Deserialize)]
pub struct SendChannelMessageRequest {
    pub attachment_url: Option<String>,
    pub attachment_filename: Option<String>,
    pub attachment_size: Option<i64>,
    pub attachment_mime_type: Option<String>,
    /// Base64 `crypto_secretbox` nonce for the encrypted attachment blob at
    /// `attachment_url`. Required (and must be non-empty) when
    /// `attachment_url` is set; must be absent otherwise.
    pub attachment_nonce: Option<String>,
    /// One ciphertext per recipient device -- must cover EXACTLY every
    /// currently-registered device of every current member of this
    /// channel's server, including the sender's own sending device. See
    /// the completeness check below.
    pub encrypted_for: Vec<EncryptedRecipient>,
    /// The id of THIS device (the one that did the encrypting), so the
    /// server can resolve and record its public key on every
    /// `message_recipients` row -- recipients need the sender's public
    /// key to decrypt, not their own.
    pub sender_device_id: Uuid,
}

/// POST /api/v1/channels/:channel_id/messages
///
/// Validates that `encrypted_for` covers every currently-registered device
/// of every current member of this channel's server exactly -- no more, no
/// less -- then inserts the `messages` row and every `message_recipients`
/// row in one transaction: either all of it lands, or none of it does.
/// Mirrors `conversations::send_fanout_message`, scoped to `server_members`
/// instead of a fixed two-person `conversation_participants`.
///
/// A member who joins this server after a message is sent never gets a
/// row here for it -- there is no re-share/history-backfill ceremony, by
/// design. A member who leaves (or is removed) simply isn't in the
/// completeness check for any message sent after they're gone.
pub async fn create_message(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
    Path(channel_id): Path<Uuid>,
    Json(payload): Json<SendChannelMessageRequest>,
) -> Result<Json<Message>, AppError> {
    let server_id = channel_server_id(&db, channel_id).await?;
    require_member(&db, server_id, user_id).await?;
    crate::permissions::require_channel_permission(&db, channel_id, user_id, crate::permissions::Permission::SEND_MESSAGES).await?;

    if payload.encrypted_for.is_empty() {
        return Err(AppError::BadRequest(
            "encrypted_for is required: channel messages are always encrypted".into(),
        ));
    }

    // An attachment is encrypted iff `attachment_url` is set: then every
    // recipient MUST carry a wrapped copy of the file key, and the message
    // needs the shared blob's nonce. With no attachment, neither applies --
    // reject a mismatched client payload outright rather than silently
    // ignoring stray fields.
    let has_attachment = payload.attachment_url.is_some();
    if has_attachment && payload.attachment_nonce.as_deref().unwrap_or("").trim().is_empty() {
        return Err(AppError::BadRequest("attachment_nonce is required when attachment_url is set".into()));
    }
    if !has_attachment && payload.attachment_nonce.is_some() {
        return Err(AppError::BadRequest("attachment_nonce must not be set without attachment_url".into()));
    }

    for r in &payload.encrypted_for {
        if r.ciphertext.trim().is_empty() || r.nonce.trim().is_empty() {
            return Err(AppError::BadRequest("ciphertext and nonce are required for every entry in encrypted_for".into()));
        }
        if r.ciphertext.len() > MAX_FANOUT_CIPHERTEXT_B64_CHARS {
            return Err(AppError::BadRequest(format!(
                "ciphertext in encrypted_for can be at most {MAX_FANOUT_CIPHERTEXT_B64_CHARS} characters"
            )));
        }
        if r.nonce.len() > MAX_FANOUT_NONCE_B64_CHARS {
            return Err(AppError::BadRequest(format!(
                "nonce in encrypted_for can be at most {MAX_FANOUT_NONCE_B64_CHARS} characters"
            )));
        }
        let key_ct = r.attachment_key_ciphertext.as_deref().unwrap_or("").trim();
        let key_nonce = r.attachment_key_nonce.as_deref().unwrap_or("").trim();
        if has_attachment {
            if key_ct.is_empty() || key_nonce.is_empty() {
                return Err(AppError::BadRequest(
                    "attachment_key_ciphertext and attachment_key_nonce are required for every entry in encrypted_for when attachment_url is set".into(),
                ));
            }
            if key_ct.len() > MAX_ATTACHMENT_KEY_CIPHERTEXT_B64_CHARS {
                return Err(AppError::BadRequest(format!(
                    "attachment_key_ciphertext in encrypted_for can be at most {MAX_ATTACHMENT_KEY_CIPHERTEXT_B64_CHARS} characters"
                )));
            }
            if key_nonce.len() > MAX_FANOUT_NONCE_B64_CHARS {
                return Err(AppError::BadRequest(format!(
                    "attachment_key_nonce in encrypted_for can be at most {MAX_FANOUT_NONCE_B64_CHARS} characters"
                )));
            }
        } else if !key_ct.is_empty() || !key_nonce.is_empty() {
            return Err(AppError::BadRequest(
                "attachment_key_ciphertext/attachment_key_nonce must not be set without attachment_url".into(),
            ));
        }
        if let Some(header) = &r.ratchet_header_json {
            if header.len() > MAX_RATCHET_HEADER_JSON_CHARS {
                return Err(AppError::BadRequest(format!(
                    "ratchet_header_json in encrypted_for can be at most {MAX_RATCHET_HEADER_JSON_CHARS} characters"
                )));
            }
        }
        if let Some(header) = &r.attachment_key_ratchet_header_json {
            if !has_attachment {
                return Err(AppError::BadRequest(
                    "attachment_key_ratchet_header_json must not be set without attachment_url".into(),
                ));
            }
            if header.len() > MAX_RATCHET_HEADER_JSON_CHARS {
                return Err(AppError::BadRequest(format!(
                    "attachment_key_ratchet_header_json in encrypted_for can be at most {MAX_RATCHET_HEADER_JSON_CHARS} characters"
                )));
            }
        }
    }

    let device_ids: Vec<Uuid> = payload.encrypted_for.iter().map(|r| r.device_id).collect();
    let mut seen = HashSet::new();
    for id in &device_ids {
        if !seen.insert(*id) {
            return Err(AppError::BadRequest("encrypted_for contains the same device_id more than once".into()));
        }
    }

    let mut tx = db.pool.begin().await.map_err(|e| AppError::Database(e.to_string()))?;

    // Read inside the transaction (not via `db.pool` beforehand) so this
    // is genuinely the same consistent snapshot the completeness check
    // below claims to use, rather than a membership list that could have
    // gone stale by the time the transaction actually started.
    let member_ids: Vec<Uuid> = sqlx::query_scalar("SELECT user_id FROM server_members WHERE server_id = $1")
        .bind(server_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let sender_public_key: Option<String> =
        sqlx::query_scalar("SELECT public_key FROM device_keys WHERE id = $1 AND user_id = $2")
            .bind(payload.sender_device_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    let sender_public_key = sender_public_key
        .ok_or_else(|| AppError::BadRequest("sender_device_id must be one of your own registered devices".into()))?;

    // Every recipient device must belong to device_keys owned by a CURRENT
    // member of this server -- otherwise reject the whole send rather than
    // partially deliver it.
    let valid_device_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM device_keys WHERE id = ANY($1) AND user_id = ANY($2)")
            .bind(&device_ids)
            .bind(&member_ids)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    if valid_device_count as usize != device_ids.len() {
        return Err(AppError::BadRequest(
            "encrypted_for contains a device_id that doesn't belong to a current member of this server".into(),
        ));
    }

    // `encrypted_for` must cover every currently-registered device of
    // every current server member, INCLUDING the sender's own sending
    // device -- read inside the same transaction as the rest of this
    // function's checks so it sees a consistent device/membership list; a
    // device or membership change racing this transaction is an existing
    // acceptable race, not a new one.
    let registered_device_ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM device_keys WHERE user_id = ANY($1)")
        .bind(&member_ids)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    let required_device_ids: HashSet<Uuid> = registered_device_ids.into_iter().collect();
    if required_device_ids != seen {
        let missing: Vec<Uuid> = required_device_ids.difference(&seen).copied().collect();
        return Err(AppError::BadRequest(format!(
            "encrypted_for must contain exactly every currently-registered device of every current server member (including the sender's own sending device); missing: {missing:?}"
        )));
    }

    let msg_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO messages (channel_id, user_id, content, attachment_url, attachment_filename, attachment_mime_type, attachment_size, attachment_nonce, is_encrypted, nonce)
        VALUES ($1, $2, NULL, $3, $4, $5, $6, $7, true, NULL)
        RETURNING id
        "#,
    )
    .bind(channel_id)
    .bind(user_id)
    .bind(&payload.attachment_url)
    .bind(&payload.attachment_filename)
    .bind(&payload.attachment_mime_type)
    .bind(payload.attachment_size)
    .bind(&payload.attachment_nonce)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    for r in &payload.encrypted_for {
        sqlx::query(
            "INSERT INTO message_recipients (message_id, device_id, ciphertext, nonce, sender_public_key, attachment_key_ciphertext, attachment_key_nonce, ratchet_header_json, attachment_key_ratchet_header_json) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(msg_id)
        .bind(r.device_id)
        .bind(&r.ciphertext)
        .bind(&r.nonce)
        .bind(&sender_public_key)
        .bind(&r.attachment_key_ciphertext)
        .bind(&r.attachment_key_nonce)
        .bind(&r.ratchet_header_json)
        .bind(&r.attachment_key_ratchet_header_json)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    }

    tx.commit().await.map_err(|e| AppError::Database(e.to_string()))?;

    let mut message = fetch_message(&db, msg_id, user_id).await?;

    // Broadcast every recipient's ciphertext; each connected client filters
    // down to its own device (and signs the stored attachment path for
    // itself) client-side.
    let broadcast_payload = serde_json::to_value(&message).map_err(|e| AppError::Internal(e.to_string()))?;
    broadcast(&db, "new_message", broadcast_payload, server_id);

    sign_opt(&mut message.attachment_url, user_id, session_id);
    sign_opt(&mut message.avatar_url, user_id, session_id);
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
    // Editing would mean re-encrypting for every current member's device,
    // but that recipient set may have grown since the original send -- and
    // re-fanning-out to it would hand a NEW member the (edited) content of
    // a message that predates them joining, violating the same "no history
    // for new joiners" invariant the original send enforces. Rather than
    // re-deriving a narrower "only the original recipients" completeness
    // check here (DMs don't support editing either -- see
    // `conversations.rs`), editing an encrypted message is simply not
    // supported: delete and resend instead.
    if ctx.is_encrypted {
        return Err(AppError::BadRequest(
            "Encrypted messages can't be edited -- delete and resend instead".into(),
        ));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::devices::{register_device, RegisterDeviceRequest};

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

    /// Creates a server with `owner_id` as its owning member.
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

    async fn create_test_channel(db: &Database, server_id: Uuid) -> Uuid {
        sqlx::query_scalar("INSERT INTO channels (server_id, name, type) VALUES ($1, $2, 'text') RETURNING id")
            .bind(server_id)
            .bind(format!("general-{}", Uuid::new_v4()))
            .fetch_one(&db.pool)
            .await
            .expect("failed to insert test channel")
    }

    async fn cleanup_test_server(db: &Database, server_id: Uuid) {
        let _ = sqlx::query("DELETE FROM servers WHERE id = $1").bind(server_id).execute(&db.pool).await;
    }

    async fn cleanup_test_user(db: &Database, user_id: Uuid) {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1").bind(user_id).execute(&db.pool).await;
    }

    fn fake_public_key(byte: u8) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [byte; 32])
    }

    async fn register_test_device(db: &Database, user_id: Uuid, byte: u8) -> Uuid {
        register_device(
            State(db.clone()),
            CurrentUser(user_id),
            Json(RegisterDeviceRequest { public_key: fake_public_key(byte), device_label: format!("device-{byte}"), signing_public_key: None }),
        )
        .await
        .expect("registering a test device should succeed")
        .0
        .id
    }

    fn fake_recipient(device_id: Uuid) -> EncryptedRecipient {
        EncryptedRecipient {
            device_id,
            ciphertext: "ciphertext".into(),
            nonce: "nonce".into(),
            attachment_key_ciphertext: None,
            attachment_key_nonce: None,
            ratchet_header_json: None,
            attachment_key_ratchet_header_json: None,
        }
    }

    #[tokio::test]
    async fn fanout_send_round_trips_through_history_fetch() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let device = register_test_device(&db, owner, 1).await;

        let created = create_message(
            State(db.clone()),
            CurrentSession { user_id: owner, session_id: Uuid::new_v4() },
            Path(channel),
            Json(SendChannelMessageRequest {
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                encrypted_for: vec![fake_recipient(device)],
                sender_device_id: device,
            }),
        )
        .await
        .expect("a complete fan-out send should succeed")
        .0;

        assert!(created.content.is_none(), "a fan-out message must not store shared plaintext content");
        assert!(created.is_encrypted);
        assert_eq!(created.recipients.len(), 1);
        assert_eq!(created.recipients[0].device_id, device);
        assert_eq!(created.recipients[0].ciphertext, "ciphertext");

        let history = get_channel_messages(
            State(db.clone()),
            CurrentSession { user_id: owner, session_id: Uuid::new_v4() },
            Path(channel),
            Query(HistoryQuery { before: None, limit: None, device_id: Some(device) }),
        )
        .await
        .expect("fetching channel history should succeed")
        .0;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].recipients.len(), 1, "the history endpoint should return this device's own ciphertext");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    /// Migration 0044: a channel attachment's symmetric file key can be
    /// wrapped through the ratchet (`attachment_key_ratchet_header_json`
    /// set) instead of the legacy static scheme -- the server stores and
    /// returns it as opaque bytes either way, same as the DM path tested
    /// in `conversations.rs`.
    #[tokio::test]
    async fn fanout_attachment_round_trips_ratchet_wrapped_key_and_header() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let device = register_test_device(&db, owner, 10).await;

        let ratchet_header = r#"{"dh":"dh-bytes","pn":0,"n":1}"#;
        let created = create_message(
            State(db.clone()),
            CurrentSession { user_id: owner, session_id: Uuid::new_v4() },
            Path(channel),
            Json(SendChannelMessageRequest {
                attachment_url: Some("/uploads/photo.png".into()),
                attachment_filename: Some("photo.png".into()),
                attachment_size: Some(1234),
                attachment_mime_type: Some("image/png".into()),
                attachment_nonce: Some("file-nonce".into()),
                encrypted_for: vec![EncryptedRecipient {
                    device_id: device,
                    ciphertext: "ciphertext".into(),
                    nonce: "nonce".into(),
                    attachment_key_ciphertext: Some("ratchet-wrapped-key".into()),
                    attachment_key_nonce: Some("ratchet-wrap-nonce".into()),
                    ratchet_header_json: None,
                    attachment_key_ratchet_header_json: Some(ratchet_header.into()),
                }],
                sender_device_id: device,
            }),
        )
        .await
        .expect("a fan-out send with a ratchet-wrapped attachment key should succeed")
        .0;

        assert_eq!(created.recipients[0].attachment_key_ciphertext.as_deref(), Some("ratchet-wrapped-key"));
        assert_eq!(created.recipients[0].attachment_key_ratchet_header_json.as_deref(), Some(ratchet_header));

        let history = get_channel_messages(
            State(db.clone()),
            CurrentSession { user_id: owner, session_id: Uuid::new_v4() },
            Path(channel),
            Query(HistoryQuery { before: None, limit: None, device_id: Some(device) }),
        )
        .await
        .expect("fetching channel history should succeed")
        .0;
        let found = history.iter().find(|m| m.id == created.id).expect("message should appear");
        assert_eq!(found.recipients[0].attachment_key_ratchet_header_json.as_deref(), Some(ratchet_header));

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    /// `attachment_key_ratchet_header_json` set without `attachment_url`
    /// is rejected for channel messages too -- same validation as the DM
    /// path (`conversations.rs`'s identical test).
    #[tokio::test]
    async fn fanout_rejects_attachment_key_ratchet_header_without_attachment() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let device = register_test_device(&db, owner, 11).await;

        let result = create_message(
            State(db.clone()),
            CurrentSession { user_id: owner, session_id: Uuid::new_v4() },
            Path(channel),
            Json(SendChannelMessageRequest {
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                encrypted_for: vec![EncryptedRecipient {
                    device_id: device,
                    ciphertext: "ciphertext".into(),
                    nonce: "nonce".into(),
                    attachment_key_ciphertext: None,
                    attachment_key_nonce: None,
                    ratchet_header_json: None,
                    attachment_key_ratchet_header_json: Some(r#"{"dh":"x","pn":0,"n":0}"#.into()),
                }],
                sender_device_id: device,
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::BadRequest(_))));

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    #[tokio::test]
    async fn fanout_rejects_incomplete_device_coverage() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let other = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let owner_device = register_test_device(&db, owner, 2).await;
        let _other_device = register_test_device(&db, other, 3).await;
        add_server_member(&db, server, other).await;

        // Only the sender's own device is covered -- the other member's
        // device is missing from `encrypted_for`.
        let result = create_message(
            State(db.clone()),
            CurrentSession { user_id: owner, session_id: Uuid::new_v4() },
            Path(channel),
            Json(SendChannelMessageRequest {
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                encrypted_for: vec![fake_recipient(owner_device)],
                sender_device_id: owner_device,
            }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for incomplete device coverage, got {other:?}"),
        }

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, other).await;
    }

    #[tokio::test]
    async fn fanout_rejects_a_device_that_does_not_belong_to_a_current_member() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let outsider = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let owner_device = register_test_device(&db, owner, 4).await;
        // Not added to the server -- this device belongs to a non-member.
        let outsider_device = register_test_device(&db, outsider, 5).await;

        let result = create_message(
            State(db.clone()),
            CurrentSession { user_id: owner, session_id: Uuid::new_v4() },
            Path(channel),
            Json(SendChannelMessageRequest {
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                encrypted_for: vec![fake_recipient(owner_device), fake_recipient(outsider_device)],
                sender_device_id: owner_device,
            }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for a non-member's device, got {other:?}"),
        }

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, outsider).await;
    }

    /// The single most important invariant behind this feature: a member
    /// who joins a channel's server AFTER a message was sent must never
    /// be able to decrypt it -- no re-share/backfill ceremony. Verifies
    /// this holds with no special-case code: the new member's device
    /// simply never gets a `message_recipients` row for the earlier
    /// message, because the completeness check was computed against
    /// server membership as it stood at send time.
    #[tokio::test]
    async fn a_member_who_joins_later_gets_no_recipient_row_for_an_earlier_message() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let newcomer = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let owner_device = register_test_device(&db, owner, 6).await;

        // Sent while `newcomer` is not yet a member.
        let created = create_message(
            State(db.clone()),
            CurrentSession { user_id: owner, session_id: Uuid::new_v4() },
            Path(channel),
            Json(SendChannelMessageRequest {
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                encrypted_for: vec![fake_recipient(owner_device)],
                sender_device_id: owner_device,
            }),
        )
        .await
        .expect("send before the newcomer joins should succeed")
        .0;

        // Newcomer joins and registers a device AFTER the message exists.
        add_server_member(&db, server, newcomer).await;
        let newcomer_device = register_test_device(&db, newcomer, 7).await;

        let recipient_device_ids: Vec<Uuid> =
            sqlx::query_scalar("SELECT device_id FROM message_recipients WHERE message_id = $1")
                .bind(created.id)
                .fetch_all(&db.pool)
                .await
                .expect("failed to query message_recipients");
        assert_eq!(recipient_device_ids, vec![owner_device], "no row must exist for the newcomer's device");
        assert!(!recipient_device_ids.contains(&newcomer_device));

        // And the newcomer's own history fetch confirms it: no ciphertext
        // for this message on their device.
        let history = get_channel_messages(
            State(db.clone()),
            CurrentSession { user_id: newcomer, session_id: Uuid::new_v4() },
            Path(channel),
            Query(HistoryQuery { before: None, limit: None, device_id: Some(newcomer_device) }),
        )
        .await
        .expect("the newcomer should still be able to list channel history")
        .0;
        let same_message = history.iter().find(|m| m.id == created.id).expect("the message should still be listed");
        assert!(same_message.recipients.is_empty(), "the newcomer's device must get no ciphertext for this message");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, newcomer).await;
    }

    #[tokio::test]
    async fn editing_an_encrypted_channel_message_is_rejected() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let device = register_test_device(&db, owner, 8).await;

        let created = create_message(
            State(db.clone()),
            CurrentSession { user_id: owner, session_id: Uuid::new_v4() },
            Path(channel),
            Json(SendChannelMessageRequest {
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                encrypted_for: vec![fake_recipient(device)],
                sender_device_id: device,
            }),
        )
        .await
        .expect("send should succeed")
        .0;

        let result = edit_message(
            State(db.clone()),
            CurrentUser(owner),
            Path(created.id),
            Json(EditMessageRequest { content: "edited".into() }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest when editing an encrypted message, got {other:?}"),
        }

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }
}

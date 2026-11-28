use std::collections::HashSet;

use axum::{
    body::Bytes,
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
    /// A readable copy of this message's content, stored only when a
    /// moderator explicitly chose to reveal it while pinned (see
    /// `set_pin_visibility`) -- lets a member who joined after this
    /// message was sent, and so never got a `message_recipients` row for
    /// it, still read a pinned announcement/rule. `None` for every
    /// ordinary message, and for a pinned one nobody has revealed.
    /// Deliberately a *plaintext* column: the whole point is that the
    /// server (and therefore any viewer) can read it without per-device
    /// decryption, which the client must make unmistakably clear in its UI.
    pub pin_plaintext_content: Option<String>,
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
    /// Who this message `@mentions`, resolved and sent by the author's own
    /// client at send time (see `message_mentions` migration's doc
    /// comment for why the server can't derive this itself). Every id here
    /// was validated, at send time, to be a current viewer of the channel
    /// this message is in -- but a mentioned member could since have lost
    /// access (left, been kicked, lost the role granting VIEW_CHANNEL), so
    /// this is "who was mentioned", not "who can currently see that they
    /// were".
    pub mentioned_user_ids: Vec<Uuid>,
}

/// Columns for `Message`. `$1` must be the requesting user's id.
const MESSAGE_COLUMNS: &str = r#"
    m.id, m.channel_id, m.user_id, u.username, sm.nickname, u.avatar_url, m.content,
    m.attachment_url, m.attachment_filename, m.attachment_mime_type, m.attachment_size, m.attachment_nonce,
    COALESCE(m.is_edited, false) AS is_edited,
    m.is_encrypted, m.nonce,
    COALESCE(m.is_locked, false) AS is_locked,
    COALESCE(m.is_pinned, false) AS is_pinned,
    -- Masked at read time, not just cleared at write time: this is the
    -- backstop that makes "revealed only while pinned" hold even if some
    -- future write path (or a bug in this one) ever leaves the column set
    -- on an unpinned row -- see `reveal_pin_plaintext`'s doc comment for
    -- the concurrency race this also independently closes.
    CASE WHEN COALESCE(m.is_pinned, false) THEN m.pin_plaintext_content ELSE NULL END AS pin_plaintext_content,
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
    ), '[]'::json) AS reactions,
    COALESCE((
        SELECT array_agg(mm.mentioned_user_id)
        FROM message_mentions mm
        WHERE mm.message_id = m.id
    ), ARRAY[]::uuid[]) AS mentioned_user_ids
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

/// Author, server, channel, lock state and the current user's role for a
/// channel message. Fails with NotFound if the message doesn't exist,
/// Forbidden if the user isn't in the message's server or can't view the
/// message's specific channel.
struct MessageContext {
    author_id: Uuid,
    server_id: Uuid,
    channel_id: Uuid,
    is_locked: bool,
    is_encrypted: bool,
    is_pinned: bool,
    /// Needed by `unpin_message` to decide whether an already-pinned
    /// message is old enough that unpinning it means immediate deletion
    /// (see `retention::UNPIN_IMMEDIATE_LOSS_DAYS`).
    created_at: chrono::DateTime<chrono::Utc>,
    role: String,
}

/// Every caller of this (edit/delete/lock/pin/hide a message, add/remove a
/// reaction) targets one already-existing message by id rather than acting
/// within a channel a client navigated to, so none of them had anywhere
/// else to enforce `VIEW_CHANNEL` -- `get_channel_messages` and
/// `create_message` check it themselves because they take a `channel_id`
/// path param, but every route built on `message_context` used to stop at
/// `require_member` (server membership) and never checked the *channel's*
/// permission overwrites at all. That let a member denied `VIEW_CHANNEL`
/// on a private channel via a role/member overwrite still mutate its
/// messages -- delete them, edit them, lock/pin them, or react to them --
/// as long as they had (or could otherwise obtain) a message id from
/// before the overwrite was added, even though they can no longer `GET`
/// the channel's history or see any of this live over the socket (the
/// broadcast is already scoped to `VIEW_CHANNEL`-holders). Checked here,
/// once, so every caller gets it: a site owner or server owner still
/// bypasses it the same way `resolve_channel` always lets them bypass
/// everything.
async fn message_context(db: &Database, message_id: Uuid, user_id: Uuid) -> Result<MessageContext, AppError> {
    type Row = (Uuid, Uuid, Uuid, bool, bool, bool, chrono::DateTime<chrono::Utc>);
    let row: Option<Row> = sqlx::query_as(
        r#"
        SELECT m.user_id, c.server_id, c.id, COALESCE(m.is_locked, false), m.is_encrypted, COALESCE(m.is_pinned, false), m.created_at
        FROM messages m JOIN channels c ON m.channel_id = c.id
        WHERE m.id = $1 AND c.server_id IS NOT NULL
        "#,
    )
    .bind(message_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let (author_id, server_id, channel_id, is_locked, is_encrypted, is_pinned, created_at) =
        row.ok_or_else(|| AppError::NotFound("Message not found".into()))?;
    let role = require_member(db, server_id, user_id).await?;
    crate::permissions::require_channel_permission(db, channel_id, user_id, crate::permissions::Permission::VIEW_CHANNEL).await?;

    Ok(MessageContext { author_id, server_id, channel_id, is_locked, is_encrypted, is_pinned, created_at, role })
}

/// Enforces this channel's slowmode (`channels.slowmode_seconds`, set via
/// `routes::channels::set_channel_slowmode`), if it has one. A member
/// holding `manage_messages` on the channel -- a moderator -- is exempt,
/// same as Discord: slowmode is meant to throttle ordinary chatter, not to
/// get in a moderator's way while they're actively handling the channel.
///
/// Uses the same in-memory `RateLimiter` as login/invite throttling
/// (`db.limits`), keyed per (channel, user) with a one-off `Rule` built
/// from this channel's own configured window rather than one of the fixed
/// `rate_limit` constants -- `limit: 1` is exactly "at most one send per
/// window", which is what slowmode means. Like the rest of that limiter,
/// this resets if the server restarts and isn't shared between replicas;
/// an acceptable looseness for a chat-pacing nicety, not a security control.
async fn enforce_slowmode(db: &Database, channel_id: Uuid, user_id: Uuid) -> Result<(), AppError> {
    let slowmode_seconds: i32 = sqlx::query_scalar("SELECT slowmode_seconds FROM channels WHERE id = $1")
        .bind(channel_id)
        .fetch_one(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    if slowmode_seconds <= 0 {
        return Ok(());
    }

    if crate::permissions::resolve_channel(db, channel_id, user_id)
        .await?
        .has(crate::permissions::Permission::MANAGE_MESSAGES)
    {
        return Ok(());
    }

    let rule = crate::rate_limit::Rule {
        name: "channel-slowmode",
        limit: 1,
        window: std::time::Duration::from_secs(slowmode_seconds as u64),
    };
    db.limits.hit(&rule, &format!("{channel_id}:{user_id}"))
}

pub(crate) async fn server_attachment_total(db: &Database, server_id: Uuid) -> Result<i64, AppError> {
    sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(m.attachment_size), 0)::bigint
        FROM messages m
        JOIN channels c ON c.id = m.channel_id
        WHERE c.server_id = $1 AND COALESCE(m.is_pinned, false) = false
        "#,
    )
    .bind(server_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))
}

/// Strips the attachment from the single oldest non-pinned, still-attached
/// message in `server_id`, deletes its file, and tells connected clients
/// the attachment is gone (a `message_updated` with `attachment_url: null`,
/// same event type every other in-place message change already uses) --
/// the message itself, and its text content, are untouched. Also clears
/// the now-meaningless per-device wrapped file keys in `message_recipients`
/// for it, since they'd otherwise outlive the attachment they used to
/// unlock. Returns `false` if there's nothing left eligible to evict
/// (everything remaining is pinned, or the server has no attachments at
/// all) -- a pinned attachment is never evicted to make room for anything.
async fn evict_oldest_attachment(db: &Database, server_id: Uuid) -> Result<bool, AppError> {
    type Row = (Uuid, Uuid, String);
    let row: Option<Row> = sqlx::query_as(
        r#"
        SELECT m.id, m.channel_id, m.attachment_url
        FROM messages m
        JOIN channels c ON c.id = m.channel_id
        WHERE c.server_id = $1 AND COALESCE(m.is_pinned, false) = false AND m.attachment_url IS NOT NULL
        ORDER BY m.created_at ASC
        LIMIT 1
        "#,
    )
    .bind(server_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let Some((message_id, channel_id, attachment_url)) = row else {
        return Ok(false);
    };

    sqlx::query(
        r#"
        UPDATE messages SET
            attachment_url = NULL, attachment_filename = NULL,
            attachment_mime_type = NULL, attachment_size = NULL, attachment_nonce = NULL
        WHERE id = $1
        "#,
    )
    .bind(message_id)
    .execute(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    sqlx::query(
        r#"
        UPDATE message_recipients SET
            attachment_key_ciphertext = NULL, attachment_key_nonce = NULL, attachment_key_ratchet_header_json = NULL
        WHERE message_id = $1
        "#,
    )
    .bind(message_id)
    .execute(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if let Some(name) = attachment_url.strip_prefix("/uploads/") {
        let _ = tokio::fs::remove_file(std::path::Path::new("uploads").join(name)).await; // already gone is fine
    }

    broadcast(
        db,
        "message_updated",
        serde_json::json!({ "id": message_id, "attachment_url": serde_json::Value::Null, "attachment_evicted": true }),
        server_id,
        channel_id,
    )
    .await;

    Ok(true)
}

/// Makes room for a new attachment under `MAX_SERVER_ATTACHMENT_STORAGE_BYTES`
/// by evicting the server's oldest non-pinned attachments, one at a time,
/// oldest first, until the new one fits -- a sliding window over the
/// server's attachment history rather than a hard "no more until someone
/// cleans up" wall. Pinning a message is still the way to exempt an
/// attachment from ever being evicted this way. Only fails if the incoming
/// attachment alone can't fit even once every evictable attachment is
/// gone (it's bigger than the whole quota, or everything left is pinned) --
/// that's the one case eviction genuinely can't solve.
///
/// `incoming_bytes` is the client-reported size of the attachment about to
/// be attached; a non-positive value (no real attachment, or a client that
/// never reported one) can't push anything over the line, so it's skipped
/// without a query.
async fn make_room_for_attachment(db: &Database, server_id: Uuid, incoming_bytes: i64) -> Result<(), AppError> {
    if incoming_bytes <= 0 {
        return Ok(());
    }

    loop {
        let current_total = server_attachment_total(db, server_id).await?;
        if current_total + incoming_bytes <= crate::access::MAX_SERVER_ATTACHMENT_STORAGE_BYTES {
            return Ok(());
        }
        if !evict_oldest_attachment(db, server_id).await? {
            return Err(AppError::BadRequest(format!(
                "This attachment doesn't fit even after freeing everything this server's {}GB attachment limit allows evicting -- pin anything you need to keep, or send a smaller file.",
                crate::access::MAX_SERVER_ATTACHMENT_STORAGE_BYTES / (1024 * 1024 * 1024)
            )));
        }
    }
}

fn require_moderator(ctx: &MessageContext) -> Result<(), AppError> {
    if is_moderator(&ctx.role) {
        Ok(())
    } else {
        Err(AppError::Forbidden("Only moderators can do this".into()))
    }
}

/// Broadcasts a channel-message event to exactly the members who currently
/// hold `VIEW_CHANNEL` on `channel_id` -- NEVER to the whole server
/// unconditionally. This matters a great deal more here than it first looks:
/// for `new_message`, `payload` carries every recipient device's actual
/// fan-out ciphertext (see `fetch_message`'s doc comment) -- a member denied
/// `VIEW_CHANNEL` on a "private" channel (via a role/member overwrite)
/// already can't `GET` its history (`get_channel_messages` checks the same
/// permission), but a plain server-wide broadcast would have handed them
/// their own already-decryptable wrapped ciphertext live over the
/// WebSocket anyway, with their own device's private key being all that's
/// needed to read it -- completely bypassing the "private channel" they're
/// supposed to be excluded from, the moment a message is sent while
/// they're connected. `channels::create_channel`/`rename_channel`/
/// `delete_channel` already scope their own broadcasts this same way; this
/// closes the same gap for messages, edits, deletes, locks, pins and
/// reactions. On a lookup failure, broadcasts to nobody rather than falling
/// back to everyone -- a missed live update is recoverable (the next
/// history fetch catches up); an over-broadcast isn't.
async fn broadcast(db: &Database, event_type: &str, payload: serde_json::Value, server_id: Uuid, channel_id: Uuid) {
    let recipients = match crate::routes::channels::members_who_can_view(db, server_id, channel_id).await {
        Ok(recipients) => recipients,
        Err(e) => {
            eprintln!("Failed to compute channel viewers for a {event_type} broadcast: {e}");
            return;
        }
    };
    // Ignore the send error: it only means nobody is connected.
    let _ = db.message_tx.send(BroadcastMessage::to_users(event_type, payload, recipients));
}

/// Longest message content accepted.
const MAX_CONTENT_CHARS: usize = 4000;
/// Messages per page when loading history.
const PAGE_SIZE: i64 = 50;
/// A generous cap, not a realistic expectation -- nobody @mentions this
/// many people in one message, but with no limit a hostile client could
/// submit an arbitrarily long list and force an arbitrarily large INSERT
/// batch per message.
const MAX_MENTIONS_PER_MESSAGE: usize = 100;
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

#[derive(Deserialize)]
pub struct PinnedQuery {
    /// Same meaning as `HistoryQuery::device_id` above.
    pub device_id: Option<Uuid>,
}

/// GET /api/v1/channels/:channel_id/pinned
///
/// Every currently-pinned message in the channel, oldest first. Unlike
/// `get_channel_messages`, every caller sees `pin_plaintext_content` for a
/// message where a moderator chose to reveal it (see
/// `set_pin_visibility`) regardless of whether this device has its own
/// `message_recipients` entry -- that field existing at all means it was
/// deliberately exposed to everyone who can view this channel, pinned
/// members list included.
///
/// Capped at 200 rather than paginated like `get_channel_messages`: a
/// channel realistically has a handful of pinned messages, so this is a
/// sanity bound against an unbounded result (nothing stops a moderator
/// from pinning far more than that today) rather than a real limit anyone
/// should hit.
pub async fn get_pinned_messages(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
    Path(channel_id): Path<Uuid>,
    Query(query): Query<PinnedQuery>,
) -> Result<Json<Vec<Message>>, AppError> {
    let server_id = channel_server_id(&db, channel_id).await?;
    require_member(&db, server_id, user_id).await?;
    crate::permissions::require_channel_permission(&db, channel_id, user_id, crate::permissions::Permission::VIEW_CHANNEL).await?;

    let mut messages: Vec<Message> = sqlx::query_as(&format!(
        r#"
        SELECT {MESSAGE_COLUMNS}
        FROM messages m
        JOIN users u ON m.user_id = u.id
        JOIN channels c ON c.id = m.channel_id
        LEFT JOIN server_members sm ON sm.server_id = c.server_id AND sm.user_id = m.user_id
        WHERE m.channel_id = $2 AND COALESCE(m.is_pinned, false)
        ORDER BY m.created_at ASC, m.id ASC
        LIMIT 200
        "#
    ))
    .bind(user_id)
    .bind(channel_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Same ownership check as `get_channel_messages`/`conversations::get_conversation_messages`:
    // without confirming `device_id` is actually one of the caller's own
    // devices, a member could pass another member's id and receive that
    // device's ciphertext instead of their own.
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
    /// currently-registered device of every current member who can
    /// currently see this channel (`VIEW_CHANNEL`), including the sender's
    /// own sending device. See the completeness check below.
    pub encrypted_for: Vec<EncryptedRecipient>,
    /// The id of THIS device (the one that did the encrypting), so the
    /// server can resolve and record its public key on every
    /// `message_recipients` row -- recipients need the sender's public
    /// key to decrypt, not their own.
    pub sender_device_id: Uuid,
    /// Who this message `@mentions`, resolved by the sending client from
    /// its own plaintext before encrypting it -- the server never sees
    /// that plaintext, so it can't detect mentions itself. Every id here
    /// must be a current viewer of this channel (checked below); anything
    /// else is rejected rather than silently dropped, same as every other
    /// validated field in this request.
    #[serde(default)]
    pub mentioned_user_ids: Vec<Uuid>,
}

/// POST /api/v1/channels/:channel_id/messages
///
/// Validates that `encrypted_for` covers every currently-registered device
/// of every current member who can currently see this specific channel
/// (i.e. holds `VIEW_CHANNEL` on it, same set `channels::members_who_can_view`
/// computes for live broadcasts) exactly -- no more, no less -- then
/// inserts the `messages` row and every `message_recipients` row in one
/// transaction: either all of it lands, or none of it does. Mirrors
/// `conversations::send_fanout_message`, scoped to this channel's current
/// viewers instead of a fixed two-person `conversation_participants`.
///
/// Scoping to channel viewers rather than the whole server (the previous
/// behavior) is what actually makes a private channel private against
/// OTHER MEMBERS, not just against outsiders: content keys themselves are
/// per-message and per-device (a `message_recipients` row, produced fresh
/// by the sender's ratchet/crypto_box for exactly this send), never a
/// standing shared secret, so a member who doesn't currently hold
/// `VIEW_CHANNEL` simply never receives a row for any message sent while
/// they lack it -- there's no key left lying around to revoke. A member
/// who regains (or newly gains) `VIEW_CHANNEL` is, symmetrically, in the
/// `encrypted_for` requirement for every message sent from that point on,
/// same as joining the server fresh already worked for channel history:
/// there is no re-share/history-backfill ceremony, by design. (The one
/// thing this can't do anything about, nor can any similar scheme: a
/// member who legitimately held `VIEW_CHANNEL` when a message was sent
/// already received that message's key then and keeps it after being
/// denied `VIEW_CHANNEL` later -- forward secrecy for messages already
/// shared with you isn't a thing any encryption scheme provides.)
pub async fn create_message(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
    Path(channel_id): Path<Uuid>,
    Json(payload): Json<SendChannelMessageRequest>,
) -> Result<Json<Message>, AppError> {
    let server_id = channel_server_id(&db, channel_id).await?;
    require_member(&db, server_id, user_id).await?;
    crate::permissions::require_channel_permission(&db, channel_id, user_id, crate::permissions::Permission::SEND_MESSAGES).await?;
    enforce_slowmode(&db, channel_id, user_id).await?;

    // Computed here, before the transaction below, same timing as the
    // `require_channel_permission` check just above (and the exact same
    // staleness tolerance that check already has): a member's access
    // changing in the instant between this read and the transaction's
    // commit is an existing acceptable race, not a new one introduced
    // here. Includes the sender themselves unconditionally -- a role could
    // in principle grant SEND_MESSAGES without VIEW_CHANNEL on a channel
    // (the two are independent bits), and the sender's own device must
    // always be in the completeness requirement regardless.
    let mut viewer_ids = crate::routes::channels::members_who_can_view(&db, server_id, channel_id).await?;
    if !viewer_ids.contains(&user_id) {
        viewer_ids.push(user_id);
    }

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
    // See `files::is_safe_external_url`'s doc comment: without this, any
    // string at all would be stored and handed straight back to every
    // viewer of this channel as a file link, rendered directly into an
    // `href`/`src` client-side with no scheme check of its own.
    if let Some(url) = &payload.attachment_url {
        if !crate::files::is_safe_external_url(url) {
            return Err(AppError::BadRequest(
                "attachment_url must be one of your own uploaded files or an http(s) URL".into(),
            ));
        }
    }
    if has_attachment {
        if let Err(e) = make_room_for_attachment(&db, server_id, payload.attachment_size.unwrap_or(0)).await {
            // The file behind `attachment_url` was already written to disk
            // by the earlier upload step and is about to be rejected here
            // with nothing ever pointing at it -- clean it up rather than
            // leaving an orphan that doesn't even count toward the quota
            // it just tripped. Only for our own local uploads (never an
            // arbitrary http(s) URL, which isn't ours to delete).
            if let Some(url) = payload.attachment_url.as_deref() {
                if let Some(name) = url.strip_prefix("/uploads/") {
                    let _ = tokio::fs::remove_file(std::path::Path::new("uploads").join(name)).await;
                }
            }
            return Err(e);
        }
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

    if payload.mentioned_user_ids.len() > MAX_MENTIONS_PER_MESSAGE {
        return Err(AppError::BadRequest(format!(
            "mentioned_user_ids can have at most {MAX_MENTIONS_PER_MESSAGE} entries"
        )));
    }
    let mut mentioned_user_ids: Vec<Uuid> = payload.mentioned_user_ids.clone();
    mentioned_user_ids.sort_unstable();
    mentioned_user_ids.dedup();
    // Mentioning someone who can't currently view this channel would
    // notify someone about a message they have no access to -- reject the
    // whole send rather than silently dropping the bad id, same policy as
    // every other validated list in this request.
    if let Some(bad) = mentioned_user_ids.iter().find(|id| !viewer_ids.contains(id)) {
        return Err(AppError::BadRequest(format!(
            "mentioned_user_ids contains {bad}, who isn't a current member who can view this channel"
        )));
    }

    let mut tx = db.pool.begin().await.map_err(|e| AppError::Database(e.to_string()))?;
    let member_ids = viewer_ids;

    let sender_public_key: Option<String> =
        sqlx::query_scalar("SELECT public_key FROM device_keys WHERE id = $1 AND user_id = $2")
            .bind(payload.sender_device_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    let sender_public_key = sender_public_key
        .ok_or_else(|| AppError::BadRequest("sender_device_id must be one of your own registered devices".into()))?;

    // Every recipient device must belong to device_keys owned by a member
    // who can currently VIEW this channel -- otherwise reject the whole
    // send rather than partially deliver it.
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
    // every current VIEWER of this channel (`member_ids` here is really
    // "this channel's current viewer ids", computed above), INCLUDING the
    // sender's own sending device. The device lookup itself still runs
    // inside the transaction so it's a consistent snapshot with the rest
    // of this function's checks; only the viewer-id computation (a
    // permission resolution, not a plain row read) happened just before
    // it -- see the comment above `members_who_can_view` being called.
    let registered_device_ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM device_keys WHERE user_id = ANY($1)")
        .bind(&member_ids)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    let required_device_ids: HashSet<Uuid> = registered_device_ids.into_iter().collect();
    if required_device_ids != seen {
        let missing: Vec<Uuid> = required_device_ids.difference(&seen).copied().collect();
        return Err(AppError::BadRequest(format!(
            "encrypted_for must contain exactly every currently-registered device of every member who can currently view this channel (including the sender's own sending device); missing: {missing:?}"
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

    for mentioned_id in &mentioned_user_ids {
        sqlx::query("INSERT INTO message_mentions (message_id, mentioned_user_id) VALUES ($1, $2)")
            .bind(msg_id)
            .bind(mentioned_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    }

    tx.commit().await.map_err(|e| AppError::Database(e.to_string()))?;

    let mut message = fetch_message(&db, msg_id, user_id).await?;

    // Broadcast every recipient's ciphertext; each connected client filters
    // down to its own device (and signs the stored attachment path for
    // itself) client-side. Scoped to members who can currently view this
    // channel -- see `broadcast`'s own doc comment for why that matters far
    // more here than for an ordinary event.
    let broadcast_payload = serde_json::to_value(&message).map_err(|e| AppError::Internal(e.to_string()))?;
    broadcast(&db, "new_message", broadcast_payload, server_id, channel_id).await;

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

    delete_message_now(&db, message_id, ctx.server_id, ctx.channel_id).await?;

    Ok(Json(()))
}

/// Deletes a message row and its attachment file (if any), and broadcasts
/// `message_deleted` to whoever can currently view the channel. Shared by
/// the plain DELETE endpoint above, the retention sweep (`retention.rs`,
/// which has no HTTP request to hang a handler off), and
/// `unpin_message`'s immediate-loss path for an already-expired pin.
pub(crate) async fn delete_message_now(db: &Database, message_id: Uuid, server_id: Uuid, channel_id: Uuid) -> Result<(), AppError> {
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

    broadcast(db, "message_deleted", serde_json::json!({ "message_id": message_id }), server_id, channel_id).await;

    Ok(())
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
    broadcast(&db, "message_updated", payload.clone(), ctx.server_id, ctx.channel_id).await;
    Ok(Json(payload))
}

/// Longest plaintext copy of a message accepted when revealing a pinned
/// message -- same cap as an ordinary message's content, since this is
/// meant to hold exactly that message's own text.
const MAX_PIN_PLAINTEXT_CHARS: usize = MAX_CONTENT_CHARS;

#[derive(Deserialize, Default)]
pub struct PinMessageRequest {
    /// When set, pins AND reveals in one step -- the convenience path the
    /// client's "pin" dialog uses when the pinning moderator chooses to
    /// also make the message readable for members who join later. See
    /// `set_pin_visibility`'s doc comment for what this actually means and
    /// why the server can't verify it against the real ciphertext.
    #[serde(default)]
    pub reveal_plaintext: Option<String>,
}

/// POST /api/v1/messages/:message_id/pin  `{ "reveal_plaintext": "..." }` (body optional)
///
/// Takes the body as raw bytes rather than `Json<PinMessageRequest>` so an
/// older client (or a caller that just wants a plain pin) can send no body
/// at all, same as before this endpoint accepted one -- `Json<T>` would
/// reject a body-less request outright for lacking a JSON content type.
/// An empty body is treated as "no reveal"; a non-empty one must still
/// parse as `PinMessageRequest`.
pub async fn pin_message(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(message_id): Path<Uuid>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, AppError> {
    let payload: PinMessageRequest = if body.is_empty() {
        PinMessageRequest::default()
    } else {
        serde_json::from_slice(&body).map_err(|e| AppError::BadRequest(format!("Invalid request body: {e}")))?
    };

    let mut response = set_pinned(&db, user_id, message_id, true).await?;
    if let Some(plaintext) = payload.reveal_plaintext {
        response = reveal_pin_plaintext(&db, user_id, message_id, plaintext).await?;
    }
    Ok(Json(response))
}

/// DELETE /api/v1/messages/:message_id/pin?confirm=true
///
/// Unpinning also clears any revealed plaintext copy (see
/// `set_pin_visibility`): the whole point of that copy is to help a new
/// member find a *currently pinned* announcement, so there's no reason for
/// it to keep living, readable by the server, once the message is no
/// longer pinned. Re-pinning later means revealing it again, deliberately
/// -- no silent carry-over.
///
/// A pin is the one thing that holds a message outside the retention
/// sweep's reach (`retention.rs`) once it's older than the sweep's own
/// `UNREAD_GRACE_DAYS`/cap window would otherwise allow -- so unpinning a
/// message that old doesn't return it to ordinary standing, it makes it
/// immediately eligible for (and here, immediately subject to) deletion.
/// Rather than silently losing that, this first responds with a
/// confirmation request (`requires_confirmation: true`) unless the caller
/// already passed `?confirm=true`; only once confirmed does it unpin *and*
/// delete the message in the same step.
pub async fn unpin_message(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(message_id): Path<Uuid>,
    Query(params): Query<UnpinQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let ctx = message_context(&db, message_id, user_id).await?;
    require_moderator(&ctx)?;

    if ctx.is_pinned && chrono::Utc::now() - ctx.created_at >= chrono::Duration::days(crate::retention::UNPIN_IMMEDIATE_LOSS_DAYS) {
        if !params.confirm {
            return Ok(Json(serde_json::json!({
                "id": message_id,
                "requires_confirmation": true,
                "warning": format!(
                    "This message is older than the {}-day retention window. Unpinning it will delete it immediately, and that can't be undone.",
                    crate::retention::UNPIN_IMMEDIATE_LOSS_DAYS
                ),
            })));
        }
        delete_message_now(&db, message_id, ctx.server_id, ctx.channel_id).await?;
        return Ok(Json(serde_json::json!({ "id": message_id, "deleted": true })));
    }

    let response = set_pinned(&db, user_id, message_id, false).await?;
    Ok(Json(response))
}

#[derive(Deserialize, Default)]
pub struct UnpinQuery {
    /// Set to actually go through with unpinning (and, for an already-
    /// expired pin, deleting) a message after being warned. Defaults to
    /// `false` so the first call against an old pin always just warns.
    #[serde(default)]
    pub confirm: bool,
}

async fn set_pinned(db: &Database, user_id: Uuid, message_id: Uuid, pinned: bool) -> Result<serde_json::Value, AppError> {
    let ctx = message_context(db, message_id, user_id).await?;
    require_moderator(&ctx)?;

    // Only check the cap when this would be a *new* pin -- re-pinning an
    // already-pinned message (or unpinning) must never be blocked by a
    // count that already includes the message itself.
    if pinned && !ctx.is_pinned {
        let pinned_count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM messages m
            JOIN channels c ON c.id = m.channel_id
            WHERE c.server_id = $1 AND COALESCE(m.is_pinned, false) = true
            "#,
        )
        .bind(ctx.server_id)
        .fetch_one(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if pinned_count >= crate::retention::PIN_CAP_PER_SERVER {
            return Err(AppError::BadRequest(format!(
                "This server already has {} pinned messages, its limit. Unpin something before pinning another.",
                crate::retention::PIN_CAP_PER_SERVER
            )));
        }
    }

    let row: (Option<String>,) = sqlx::query_as(
        r#"
        UPDATE messages SET
            is_pinned = $1,
            pinned_by = $2,
            pin_plaintext_content = CASE WHEN $1 THEN pin_plaintext_content ELSE NULL END,
            pin_plaintext_revealed_by = CASE WHEN $1 THEN pin_plaintext_revealed_by ELSE NULL END,
            pin_plaintext_revealed_at = CASE WHEN $1 THEN pin_plaintext_revealed_at ELSE NULL END
        WHERE id = $3
        RETURNING pin_plaintext_content
        "#,
    )
    .bind(pinned)
    .bind(if pinned { Some(user_id) } else { None })
    .bind(message_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let payload = serde_json::json!({ "id": message_id, "is_pinned": pinned, "pin_plaintext_content": row.0 });
    broadcast(db, "message_updated", payload.clone(), ctx.server_id, ctx.channel_id).await;
    Ok(payload)
}

/// PUT /api/v1/messages/:message_id/pin-visibility  `{ "plaintext_content": "..." | null }`
///
/// Toggles whether a currently-pinned, encrypted message's content is also
/// stored readable on the server, so a member who joins the channel after
/// it was sent -- and so never received a `message_recipients` row for it
/// (channel E2EE has no history-backfill; see `create_message`'s doc
/// comment) -- can still read a pinned rule or announcement. `null`
/// revokes a previous reveal, restoring the message to encrypted-only;
/// a string reveals (or replaces) it.
///
/// This is a deliberate, explicit, per-message weakening of end-to-end
/// encryption, gated the same way pinning itself is (a moderator or
/// above), and the server has no way to confirm `plaintext_content`
/// actually matches the real ciphertext -- it trusts the calling client's
/// own decryption, the same trust a moderator already carries when
/// locking, pinning or deleting someone else's message. The client MUST
/// make this trade-off unmistakable before calling this with a non-null
/// body.
pub async fn set_pin_visibility(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(message_id): Path<Uuid>,
    Json(payload): Json<SetPinVisibilityRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    match payload.plaintext_content {
        Some(plaintext) => Ok(Json(reveal_pin_plaintext(&db, user_id, message_id, plaintext).await?)),
        None => Ok(Json(hide_pin_plaintext(&db, user_id, message_id).await?)),
    }
}

#[derive(Deserialize)]
pub struct SetPinVisibilityRequest {
    pub plaintext_content: Option<String>,
}

async fn reveal_pin_plaintext(db: &Database, user_id: Uuid, message_id: Uuid, plaintext: String) -> Result<serde_json::Value, AppError> {
    let ctx = message_context(db, message_id, user_id).await?;
    require_moderator(&ctx)?;
    if !ctx.is_encrypted {
        return Err(AppError::BadRequest(
            "This message isn't encrypted -- it's already visible to everyone who can view this channel.".into(),
        ));
    }
    if !ctx.is_pinned {
        return Err(AppError::BadRequest("Pin the message before revealing it.".into()));
    }
    let plaintext = plaintext.trim();
    if plaintext.is_empty() {
        return Err(AppError::BadRequest("plaintext_content must not be empty".into()));
    }
    if plaintext.chars().count() > MAX_PIN_PLAINTEXT_CHARS {
        return Err(AppError::BadRequest(format!(
            "plaintext_content can be at most {MAX_PIN_PLAINTEXT_CHARS} characters"
        )));
    }

    // `AND is_pinned` closes a real race, not just a redundant check: the
    // `ctx.is_pinned` read above and this write aren't one transaction, so
    // a concurrent unpin can land in between them. Without this guard,
    // this UPDATE would still fire after that unpin committed and quietly
    // resurrect a plaintext copy of an unpinned message -- the one thing
    // this feature promises never happens (see this fn's and
    // `unpin_message`'s doc comments). Checking `rows_affected` turns that
    // race into a clean, reportable error instead of a silent no-op.
    let result = sqlx::query(
        "UPDATE messages SET pin_plaintext_content = $1, pin_plaintext_revealed_by = $2, pin_plaintext_revealed_at = NOW() WHERE id = $3 AND is_pinned",
    )
    .bind(plaintext)
    .bind(user_id)
    .bind(message_id)
    .execute(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    if result.rows_affected() == 0 {
        return Err(AppError::BadRequest("The message was unpinned while this was being revealed; pin it again first.".into()));
    }

    let payload = serde_json::json!({ "id": message_id, "is_pinned": true, "pin_plaintext_content": plaintext });
    broadcast(db, "message_updated", payload.clone(), ctx.server_id, ctx.channel_id).await;
    Ok(payload)
}

async fn hide_pin_plaintext(db: &Database, user_id: Uuid, message_id: Uuid) -> Result<serde_json::Value, AppError> {
    let ctx = message_context(db, message_id, user_id).await?;
    require_moderator(&ctx)?;

    sqlx::query(
        "UPDATE messages SET pin_plaintext_content = NULL, pin_plaintext_revealed_by = NULL, pin_plaintext_revealed_at = NULL WHERE id = $1",
    )
    .bind(message_id)
    .execute(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let payload = serde_json::json!({ "id": message_id, "is_pinned": ctx.is_pinned, "pin_plaintext_content": serde_json::Value::Null });
    broadcast(db, "message_updated", payload.clone(), ctx.server_id, ctx.channel_id).await;
    Ok(payload)
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
    broadcast(db, "message_updated", payload.clone(), server_id, message.channel_id).await;
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
    broadcast(&db, "message_updated", update.clone(), ctx.server_id, ctx.channel_id).await;
    Ok(Json(update))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::devices::{register_device, RegisterDeviceRequest};
    use crate::routes::reactions::{add_reaction, AddReactionRequest};

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
                mentioned_user_ids: vec![],
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
                mentioned_user_ids: vec![],
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
                mentioned_user_ids: vec![],
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::BadRequest(_))));

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    /// A channel attachment is rendered client-side straight into
    /// `fileUrl(...)` and then an `<a href>`/`<img src>` with no scheme
    /// check of its own -- a `javascript:` attachment_url would be a
    /// stored-XSS payload against every member of the channel who ever
    /// views the message and clicks the resulting link (see
    /// `files::is_safe_external_url`'s doc comment).
    #[tokio::test]
    async fn fanout_rejects_a_javascript_attachment_url() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let device = register_test_device(&db, owner, 12).await;

        let result = create_message(
            State(db.clone()),
            CurrentSession { user_id: owner, session_id: Uuid::new_v4() },
            Path(channel),
            Json(SendChannelMessageRequest {
                attachment_url: Some("javascript:alert(document.cookie)".into()),
                attachment_filename: Some("photo.png".into()),
                attachment_size: Some(1234),
                attachment_mime_type: Some("image/png".into()),
                attachment_nonce: Some("file-nonce".into()),
                encrypted_for: vec![EncryptedRecipient {
                    device_id: device,
                    ciphertext: "ciphertext".into(),
                    nonce: "nonce".into(),
                    attachment_key_ciphertext: Some("key".into()),
                    attachment_key_nonce: Some("key-nonce".into()),
                    ratchet_header_json: None,
                    attachment_key_ratchet_header_json: None,
                }],
                sender_device_id: device,
                mentioned_user_ids: vec![],
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::BadRequest(_))), "a javascript: attachment_url must be rejected");

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
                mentioned_user_ids: vec![],
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
                mentioned_user_ids: vec![],
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
                mentioned_user_ids: vec![],
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
                mentioned_user_ids: vec![],
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

    /// Regression test for a bug found in a fresh adversarial audit: the
    /// `new_message` WebSocket broadcast used to go to every member of the
    /// server unconditionally (`BroadcastMessage::to_server`), carrying each
    /// recipient device's actual fan-out ciphertext (see `fetch_message`).
    /// A member explicitly denied `VIEW_CHANNEL` on a channel via a
    /// member-level overwrite -- a "private" channel -- already couldn't
    /// `GET` its history, but would still receive their own
    /// already-decryptable wrapped ciphertext live over the socket the
    /// moment anyone sent a message there, completely bypassing the
    /// channel's privacy with nothing more than an open connection and
    /// their own device key. This asserts the broadcast is scoped to
    /// current viewers only, the same way `channels::create_channel`'s own
    /// broadcast already is.
    #[tokio::test]
    async fn new_message_broadcast_excludes_a_member_denied_view_channel() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;

        let viewer = create_test_user(&db).await;
        add_server_member(&db, server, viewer).await;
        let blocked = create_test_user(&db).await;
        add_server_member(&db, server, blocked).await;

        // Deny VIEW_CHANNEL to `blocked` specifically on this channel --
        // a member-level overwrite applies regardless of whether this
        // server has any role rows at all (this test fixture has none; see
        // `permissions::resolve_channel`).
        sqlx::query("INSERT INTO channel_member_overwrites (channel_id, user_id, allow, deny) VALUES ($1, $2, 0, $3)")
            .bind(channel)
            .bind(blocked)
            .bind(crate::permissions::Permission::VIEW_CHANNEL.0)
            .execute(&db.pool)
            .await
            .expect("inserting the member overwrite should succeed");

        let owner_device = register_test_device(&db, owner, 40).await;
        let viewer_device = register_test_device(&db, viewer, 41).await;
        // Registered, but deliberately never passed to `encrypted_for`
        // below -- proving `blocked` is excluded even though their device
        // is real and registered, not merely absent from this test.
        let _blocked_device = register_test_device(&db, blocked, 42).await;

        let mut rx = db.message_tx.subscribe();

        let _ = create_message(
            State(db.clone()),
            CurrentSession { user_id: owner, session_id: Uuid::new_v4() },
            Path(channel),
            Json(SendChannelMessageRequest {
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                // `blocked`'s device is deliberately NOT included: the
                // completeness check is scoped to current channel viewers
                // (see `create_message`'s doc comment), and `blocked` isn't
                // one. This also doubles as this test's own proof that the
                // send succeeds without their device present at all.
                encrypted_for: vec![fake_recipient(owner_device), fake_recipient(viewer_device)],
                sender_device_id: owner_device,
                mentioned_user_ids: vec![],
            }),
        )
        .await
        .expect("the send itself should still succeed")
        .0;

        let broadcast = rx.try_recv().expect("a new_message event should have been broadcast");
        assert_eq!(broadcast.event_type, "new_message");
        let recipients = broadcast.to_users.expect("new_message must be scoped with to_users, not sent to the whole server");
        assert!(recipients.contains(&owner), "the sender can see their own channel");
        assert!(recipients.contains(&viewer), "a member with VIEW_CHANNEL must still receive the live update");
        assert!(
            !recipients.contains(&blocked),
            "a member denied VIEW_CHANNEL must not receive the message's ciphertext live over the socket"
        );

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, viewer).await;
        cleanup_test_user(&db, blocked).await;
    }

    /// The deeper architectural fix beneath `new_message_broadcast_excludes_...`
    /// above: the broadcast-scoping fix alone only stopped a denied member
    /// from receiving their *live* copy over the socket -- it didn't change
    /// that `encrypted_for` still had to cover their device at send time,
    /// meaning the server still held, and the client still had to produce,
    /// a decryptable `message_recipients` row for them. That meant a
    /// member's cryptographic access to a "private" channel never actually
    /// shrank when their `VIEW_CHANNEL` was revoked -- only the server's
    /// willingness to hand them the ciphertext through the API did. This
    /// proves the completeness requirement itself is now scoped to current
    /// channel viewers: a denied member's device is neither required NOR
    /// accepted in `encrypted_for`, and no row for them is ever created.
    #[tokio::test]
    async fn create_message_excludes_a_member_denied_view_channel_from_encrypted_for() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;

        let viewer = create_test_user(&db).await;
        add_server_member(&db, server, viewer).await;
        let blocked = create_test_user(&db).await;
        add_server_member(&db, server, blocked).await;
        deny_view_channel(&db, channel, blocked).await;

        let owner_device = register_test_device(&db, owner, 60).await;
        let viewer_device = register_test_device(&db, viewer, 61).await;
        let blocked_device = register_test_device(&db, blocked, 62).await;

        // A client that still builds `encrypted_for` as if `blocked` were a
        // required recipient (the old, pre-fix behavior) must now be
        // rejected outright -- the completeness check is EXACT, so an
        // extra, no-longer-required device is just as much a mismatch as a
        // missing one.
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
                encrypted_for: vec![
                    fake_recipient(owner_device),
                    fake_recipient(viewer_device),
                    fake_recipient(blocked_device),
                ],
                sender_device_id: owner_device,
                mentioned_user_ids: vec![],
            }),
        )
        .await;
        assert!(
            matches!(result, Err(AppError::BadRequest(_))),
            "encrypted_for including a device_id of a member denied VIEW_CHANNEL must be rejected, got {result:?}"
        );

        // The correctly-scoped send (what a fixed client actually produces,
        // e.g. from `channels::get_channel_member_devices`) succeeds, and
        // leaves no `message_recipients` row for `blocked` at all.
        let message_id = create_message(
            State(db.clone()),
            CurrentSession { user_id: owner, session_id: Uuid::new_v4() },
            Path(channel),
            Json(SendChannelMessageRequest {
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                encrypted_for: vec![fake_recipient(owner_device), fake_recipient(viewer_device)],
                sender_device_id: owner_device,
                mentioned_user_ids: vec![],
            }),
        )
        .await
        .expect("a correctly-scoped send must succeed")
        .0
        .id;

        let recipient_devices: Vec<Uuid> = sqlx::query_scalar("SELECT device_id FROM message_recipients WHERE message_id = $1")
            .bind(message_id)
            .fetch_all(&db.pool)
            .await
            .expect("failed to query message_recipients");
        assert!(recipient_devices.contains(&owner_device));
        assert!(recipient_devices.contains(&viewer_device));
        assert!(
            !recipient_devices.contains(&blocked_device),
            "a member denied VIEW_CHANNEL must never get a message_recipients row -- there's no key to hold"
        );

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, viewer).await;
        cleanup_test_user(&db, blocked).await;
    }

    async fn add_server_moderator(db: &Database, server_id: Uuid, user_id: Uuid) {
        sqlx::query("INSERT INTO server_members (server_id, user_id, role) VALUES ($1, $2, 'moderator')")
            .bind(server_id)
            .bind(user_id)
            .execute(&db.pool)
            .await
            .expect("failed to insert moderator");
    }

    async fn deny_view_channel(db: &Database, channel_id: Uuid, user_id: Uuid) {
        sqlx::query("INSERT INTO channel_member_overwrites (channel_id, user_id, allow, deny) VALUES ($1, $2, 0, $3)")
            .bind(channel_id)
            .bind(user_id)
            .bind(crate::permissions::Permission::VIEW_CHANNEL.0)
            .execute(&db.pool)
            .await
            .expect("inserting the member overwrite should succeed");
    }

    async fn send_test_message(db: &Database, server: Uuid, channel: Uuid, sender: Uuid, sender_device: Uuid, other_devices: &[Uuid]) -> Uuid {
        let _ = server;
        let mut encrypted_for = vec![fake_recipient(sender_device)];
        encrypted_for.extend(other_devices.iter().map(|d| fake_recipient(*d)));
        create_message(
            State(db.clone()),
            CurrentSession { user_id: sender, session_id: Uuid::new_v4() },
            Path(channel),
            Json(SendChannelMessageRequest {
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                encrypted_for,
                sender_device_id: sender_device,
                mentioned_user_ids: vec![],
            }),
        )
        .await
        .expect("the send itself should succeed")
        .0
        .id
    }

    /// Before this fix, `message_context` (and therefore every route built
    /// on it -- edit/delete/lock/pin/hide a message, add/remove a
    /// reaction) checked only server membership, never the message's own
    /// channel's `VIEW_CHANNEL` permission. A legacy "moderator" is
    /// normally allowed to delete any message in the server via
    /// `is_moderator`, but that must not reach into a channel they've been
    /// specifically denied access to by a member overwrite -- the same
    /// kind of carve-out `resolve_channel` is built to support everywhere
    /// else.
    #[tokio::test]
    async fn delete_message_is_rejected_for_a_moderator_denied_view_channel() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;

        let moderator = create_test_user(&db).await;
        add_server_moderator(&db, server, moderator).await;
        deny_view_channel(&db, channel, moderator).await;

        let owner_device = register_test_device(&db, owner, 50).await;
        let moderator_device = register_test_device(&db, moderator, 51).await;

        // `moderator_device` isn't passed to `encrypted_for` here: now that
        // `encrypted_for` is scoped to current channel viewers, a moderator
        // denied VIEW_CHANNEL isn't a required recipient of this message at
        // all -- which is exactly the point. The mutation check under test
        // (message_context's VIEW_CHANNEL requirement) doesn't depend on
        // whether they have a `message_recipients` row.
        let _ = moderator_device;
        let message_id = send_test_message(&db, server, channel, owner, owner_device, &[]).await;

        let result = delete_message(State(db.clone()), CurrentUser(moderator), Path(message_id)).await;
        assert!(
            matches!(result, Err(AppError::Forbidden(_))),
            "a moderator denied VIEW_CHANNEL on this channel must not be able to delete its messages, got {result:?}"
        );

        // Sanity check: the same moderator, NOT denied access, can still
        // delete -- this isn't just broken for everyone.
        sqlx::query("DELETE FROM channel_member_overwrites WHERE channel_id = $1 AND user_id = $2")
            .bind(channel)
            .bind(moderator)
            .execute(&db.pool)
            .await
            .expect("removing the overwrite should succeed");
        let result = delete_message(State(db.clone()), CurrentUser(moderator), Path(message_id)).await;
        assert!(result.is_ok(), "a moderator WITH VIEW_CHANNEL should still be able to delete messages: {result:?}");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, moderator).await;
    }

    /// Same gap, cheaper to trigger: an ordinary member (no special role at
    /// all) denied `VIEW_CHANNEL` could still add or remove reactions on a
    /// message in that channel, as long as they had a message id from
    /// before the overwrite was added.
    #[tokio::test]
    async fn add_reaction_is_rejected_for_a_member_denied_view_channel() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;

        let blocked = create_test_user(&db).await;
        add_server_member(&db, server, blocked).await;
        deny_view_channel(&db, channel, blocked).await;

        let owner_device = register_test_device(&db, owner, 52).await;
        let blocked_device = register_test_device(&db, blocked, 53).await;

        // Same reasoning as the delete-message test above: `blocked_device`
        // isn't a required `encrypted_for` recipient once the completeness
        // check is scoped to current channel viewers.
        let _ = blocked_device;
        let message_id = send_test_message(&db, server, channel, owner, owner_device, &[]).await;

        let result = add_reaction(
            State(db.clone()),
            CurrentUser(blocked),
            Path(message_id),
            Json(AddReactionRequest { emoji: "👍".to_string() }),
        )
        .await;
        assert!(
            matches!(result, Err(AppError::Forbidden(_))),
            "a member denied VIEW_CHANNEL must not be able to react to messages in that channel, got {result:?}"
        );

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, blocked).await;
    }

    /// Pinning with `reveal_plaintext` stores it, exposes it on the
    /// message, and `get_pinned_messages` returns it to a member with no
    /// `message_recipients` entry for this message at all -- the whole
    /// point of the feature: a member who joined after the send.
    #[tokio::test]
    async fn pin_with_reveal_exposes_plaintext_to_a_member_with_no_decryption_key() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let owner_device = register_test_device(&db, owner, 60).await;

        // `late_joiner` is added to the server AFTER the message is sent --
        // mirroring a real new member -- so they were never a required
        // `encrypted_for` recipient and have no row in `message_recipients`.
        let message_id = send_test_message(&db, server, channel, owner, owner_device, &[]).await;
        let late_joiner = create_test_user(&db).await;
        add_server_member(&db, server, late_joiner).await;

        let response = pin_message(
            State(db.clone()),
            CurrentUser(owner),
            Path(message_id),
            Bytes::from_static(br#"{"reveal_plaintext":"Server rules: be kind."}"#),
        )
        .await
        .expect("pinning with a reveal should succeed")
        .0;
        assert_eq!(response["pin_plaintext_content"], "Server rules: be kind.");

        let pinned = get_pinned_messages(
            State(db.clone()),
            CurrentSession { user_id: late_joiner, session_id: Uuid::new_v4() },
            Path(channel),
            Query(PinnedQuery { device_id: None }),
        )
        .await
        .expect("a member should be able to list this channel's pinned messages")
        .0;
        assert_eq!(pinned.len(), 1);
        assert!(pinned[0].recipients.is_empty(), "the late joiner must have no decryption key for the original ciphertext");
        assert_eq!(
            pinned[0].pin_plaintext_content.as_deref(),
            Some("Server rules: be kind."),
            "a member who never received this message's key should still see the revealed plaintext"
        );

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, late_joiner).await;
    }

    /// Unpinning clears a revealed plaintext copy -- the reveal is scoped
    /// to "while pinned", not a permanent exception for that message.
    #[tokio::test]
    async fn unpinning_clears_a_revealed_plaintext_copy() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let owner_device = register_test_device(&db, owner, 61).await;
        let message_id = send_test_message(&db, server, channel, owner, owner_device, &[]).await;

        let _ = pin_message(
            State(db.clone()),
            CurrentUser(owner),
            Path(message_id),
            Bytes::from_static(br#"{"reveal_plaintext":"Welcome!"}"#),
        )
        .await
        .expect("pin with reveal should succeed");

        let _ = unpin_message(State(db.clone()), CurrentUser(owner), Path(message_id), Query(UnpinQuery::default()))
            .await
            .expect("unpinning should succeed");

        let fetched = fetch_message(&db, message_id, owner).await.expect("fetching the message should succeed");
        assert!(!fetched.is_pinned);
        assert!(fetched.pin_plaintext_content.is_none(), "unpinning must clear a previously revealed plaintext copy");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    /// `set_pin_visibility` can reveal (and later hide again) a plaintext
    /// copy without touching the pin itself -- the "toggle" the client's
    /// pin-visibility button uses independently of pin/unpin.
    #[tokio::test]
    async fn set_pin_visibility_toggles_independently_of_pinning() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let owner_device = register_test_device(&db, owner, 62).await;
        let message_id = send_test_message(&db, server, channel, owner, owner_device, &[]).await;

        let _ = pin_message(State(db.clone()), CurrentUser(owner), Path(message_id), Bytes::new())
            .await
            .expect("plain pin (no reveal) should succeed");

        let _ = set_pin_visibility(
            State(db.clone()),
            CurrentUser(owner),
            Path(message_id),
            Json(SetPinVisibilityRequest { plaintext_content: Some("Read the pinned notice.".into()) }),
        )
        .await
        .expect("revealing via the toggle should succeed");

        let revealed = fetch_message(&db, message_id, owner).await.expect("fetch should succeed");
        assert!(revealed.is_pinned, "toggling visibility must not unpin the message");
        assert_eq!(revealed.pin_plaintext_content.as_deref(), Some("Read the pinned notice."));

        let _ = set_pin_visibility(
            State(db.clone()),
            CurrentUser(owner),
            Path(message_id),
            Json(SetPinVisibilityRequest { plaintext_content: None }),
        )
        .await
        .expect("hiding via the toggle should succeed");

        let hidden = fetch_message(&db, message_id, owner).await.expect("fetch should succeed");
        assert!(hidden.is_pinned, "hiding the reveal must not unpin the message");
        assert!(hidden.pin_plaintext_content.is_none());

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    /// Revealing requires the message to already be pinned, and to
    /// actually be encrypted -- there's nothing to reveal otherwise.
    #[tokio::test]
    async fn set_pin_visibility_rejects_an_unpinned_message() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let owner_device = register_test_device(&db, owner, 63).await;
        let message_id = send_test_message(&db, server, channel, owner, owner_device, &[]).await;

        let result = set_pin_visibility(
            State(db.clone()),
            CurrentUser(owner),
            Path(message_id),
            Json(SetPinVisibilityRequest { plaintext_content: Some("too early".into()) }),
        )
        .await;
        assert!(matches!(result, Err(AppError::BadRequest(_))), "revealing an unpinned message must be rejected, got {result:?}");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    /// Only a moderator (or above) can reveal a pinned message's plaintext
    /// -- same gate as pinning itself.
    #[tokio::test]
    async fn set_pin_visibility_is_rejected_for_a_plain_member() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let owner_device = register_test_device(&db, owner, 64).await;
        let message_id = send_test_message(&db, server, channel, owner, owner_device, &[]).await;

        let _ = pin_message(State(db.clone()), CurrentUser(owner), Path(message_id), Bytes::new())
            .await
            .expect("pin should succeed");

        let member = create_test_user(&db).await;
        add_server_member(&db, server, member).await;

        let result = set_pin_visibility(
            State(db.clone()),
            CurrentUser(member),
            Path(message_id),
            Json(SetPinVisibilityRequest { plaintext_content: Some("sneaky".into()) }),
        )
        .await;
        assert!(matches!(result, Err(AppError::Forbidden(_))), "a plain member must not be able to reveal a pinned message, got {result:?}");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, member).await;
    }

    /// The database itself refuses a row with a plaintext reveal on an
    /// unpinned message -- the backstop (`pin_plaintext_only_while_pinned`)
    /// behind the application-level guards, for whatever future write path
    /// forgets them. This never goes through any handler: a raw UPDATE is
    /// the most direct way to confirm the constraint itself, not just the
    /// application code that's supposed to respect it.
    #[tokio::test]
    async fn the_database_rejects_a_plaintext_reveal_on_an_unpinned_message() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let owner_device = register_test_device(&db, owner, 66).await;
        let message_id = send_test_message(&db, server, channel, owner, owner_device, &[]).await;
        // Deliberately never pinned.

        let result = sqlx::query("UPDATE messages SET pin_plaintext_content = $1 WHERE id = $2")
            .bind("sneaking in")
            .bind(message_id)
            .execute(&db.pool)
            .await;
        assert!(result.is_err(), "the CHECK constraint should reject this write, but it succeeded");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    /// Even if a stale plaintext reveal somehow ended up on an unpinned
    /// row (the two guards above are meant to make that impossible, but
    /// this is the read-time backstop for if they're ever bypassed, e.g.
    /// by a future migration or a direct DB fix-up), every read path masks
    /// it back to `None` rather than exposing it. Postgres has no way to
    /// bypass a single CHECK constraint for one statement, so this test
    /// drops and re-adds it around the write -- the only way to construct
    /// the otherwise-impossible state needed to exercise the mask.
    #[tokio::test]
    async fn an_unpinned_messages_stale_reveal_is_masked_on_every_read_path() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let owner_device = register_test_device(&db, owner, 67).await;
        let message_id = send_test_message(&db, server, channel, owner, owner_device, &[]).await;

        // All three statements run in one transaction so the ACCESS
        // EXCLUSIVE lock the first ALTER TABLE takes on `messages` is held
        // for the whole sequence, not just that one statement. Without
        // this, another test running concurrently against the same shared
        // database (cargo test runs tests in parallel threads) could write
        // -- or read, expecting the constraint to be enforced -- in the
        // window between the DROP and the re-ADD, which is exactly how an
        // earlier version of this test flaked another test into a
        // spurious failure.
        //
        // The re-add uses `NOT VALID`: a plain `ADD CONSTRAINT` re-checks
        // every existing row, which would fail on the very row this test
        // just wrote to deliberately violate the invariant (that row has
        // to stay in that state for the assertions below). `NOT VALID`
        // enforces the constraint for all writes from here on without
        // re-validating current data -- exactly what's needed to restore
        // protection going forward while still exercising the read-time
        // mask against this one pre-existing bad row.
        let mut tx = db.pool.begin().await.expect("beginning the transaction should succeed");
        sqlx::query("ALTER TABLE messages DROP CONSTRAINT pin_plaintext_only_while_pinned")
            .execute(&mut *tx)
            .await
            .expect("dropping the constraint for this test should succeed");
        sqlx::query("UPDATE messages SET pin_plaintext_content = $1 WHERE id = $2")
            .bind("should never be visible")
            .bind(message_id)
            .execute(&mut *tx)
            .await
            .expect("the raw write should succeed with the constraint dropped");
        sqlx::query(
            "ALTER TABLE messages ADD CONSTRAINT pin_plaintext_only_while_pinned CHECK (pin_plaintext_content IS NULL OR COALESCE(is_pinned, false)) NOT VALID",
        )
        .execute(&mut *tx)
        .await
        .expect("restoring the constraint should succeed");
        tx.commit().await.expect("committing the transaction should succeed");

        let fetched = fetch_message(&db, message_id, owner).await.expect("fetching the message should succeed");
        assert!(!fetched.is_pinned);
        assert!(fetched.pin_plaintext_content.is_none(), "an unpinned message's stale reveal must be masked, not exposed, on read");

        let channel_history = get_channel_messages(
            State(db.clone()),
            CurrentSession { user_id: owner, session_id: Uuid::new_v4() },
            Path(channel),
            Query(HistoryQuery { before: None, limit: None, device_id: None }),
        )
        .await
        .expect("fetching channel history should succeed")
        .0;
        assert!(
            channel_history.iter().all(|m| m.pin_plaintext_content.is_none()),
            "channel history must never surface a stale reveal on an unpinned message either"
        );

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        // The bad row is gone now (cascaded away with the server/channel
        // above), so this re-validates the constraint against all
        // remaining data, returning it to a fully validated state rather
        // than leaving it marked NOT VALID for the rest of this database's
        // life. Enforcement for new writes was never affected either way;
        // this only restores the catalog's bookkeeping.
        sqlx::query("ALTER TABLE messages VALIDATE CONSTRAINT pin_plaintext_only_while_pinned")
            .execute(&db.pool)
            .await
            .expect("re-validating the constraint after cleanup should succeed");
    }

    /// `get_pinned_messages` must apply the same `VIEW_CHANNEL` scoping as
    /// every other message-reading endpoint -- a member denied access to a
    /// private channel must not be able to list, let alone read, its
    /// pinned (and possibly plaintext-revealed) messages via this
    /// side-door.
    #[tokio::test]
    async fn get_pinned_messages_is_rejected_for_a_member_denied_view_channel() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let owner_device = register_test_device(&db, owner, 65).await;
        let message_id = send_test_message(&db, server, channel, owner, owner_device, &[]).await;
        let _ = pin_message(
            State(db.clone()),
            CurrentUser(owner),
            Path(message_id),
            Bytes::from_static(br#"{"reveal_plaintext":"private notice"}"#),
        )
        .await
        .expect("pin with reveal should succeed");

        let blocked = create_test_user(&db).await;
        add_server_member(&db, server, blocked).await;
        deny_view_channel(&db, channel, blocked).await;

        let result = get_pinned_messages(
            State(db.clone()),
            CurrentSession { user_id: blocked, session_id: Uuid::new_v4() },
            Path(channel),
            Query(PinnedQuery { device_id: None }),
        )
        .await;
        assert!(matches!(result, Err(AppError::Forbidden(_))), "a member denied VIEW_CHANNEL must not list pinned messages, got {result:?}");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, blocked).await;
    }

    /// Mentioning a current viewer of the channel is recorded and comes
    /// back on both the send response and a later fetch of the same
    /// message -- the two read paths `MESSAGE_COLUMNS` backs.
    #[tokio::test]
    async fn mentioning_a_current_viewer_is_recorded_and_returned() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let owner_device = register_test_device(&db, owner, 70).await;

        let member = create_test_user(&db).await;
        add_server_member(&db, server, member).await;
        let member_device = register_test_device(&db, member, 71).await;

        let encrypted_for = vec![fake_recipient(owner_device), fake_recipient(member_device)];
        let sent = create_message(
            State(db.clone()),
            CurrentSession { user_id: owner, session_id: Uuid::new_v4() },
            Path(channel),
            Json(SendChannelMessageRequest {
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                encrypted_for,
                sender_device_id: owner_device,
                mentioned_user_ids: vec![member],
            }),
        )
        .await
        .expect("sending with a valid mention should succeed")
        .0;
        assert_eq!(sent.mentioned_user_ids, vec![member]);

        let fetched = fetch_message(&db, sent.id, owner).await.expect("fetching the message should succeed");
        assert_eq!(fetched.mentioned_user_ids, vec![member], "a later fetch must still report the mention");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, member).await;
    }

    /// Mentioning someone who can't currently view the channel -- denied
    /// `VIEW_CHANNEL` via an overwrite here, same as a non-member would be
    /// -- is rejected outright rather than silently dropped or notifying
    /// someone about a message they have no access to.
    #[tokio::test]
    async fn mentioning_someone_denied_view_channel_is_rejected() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let owner_device = register_test_device(&db, owner, 72).await;

        let blocked = create_test_user(&db).await;
        add_server_member(&db, server, blocked).await;
        deny_view_channel(&db, channel, blocked).await;

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
                mentioned_user_ids: vec![blocked],
            }),
        )
        .await;
        assert!(
            matches!(result, Err(AppError::BadRequest(_))),
            "mentioning a member denied VIEW_CHANNEL must be rejected, got {result:?}"
        );

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, blocked).await;
    }

    /// A duplicated id in `mentioned_user_ids` is deduped rather than
    /// rejected or double-recorded (the table's primary key would reject a
    /// literal duplicate INSERT outright, so this also confirms the
    /// dedup actually runs before the insert loop, not just incidentally
    /// surviving it).
    #[tokio::test]
    async fn duplicate_mentions_are_deduped() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let owner_device = register_test_device(&db, owner, 73).await;

        let member = create_test_user(&db).await;
        add_server_member(&db, server, member).await;

        let sent = create_message(
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
                mentioned_user_ids: vec![member, member, member],
            }),
        )
        .await
        .expect("a duplicated mention should still succeed")
        .0;
        assert_eq!(sent.mentioned_user_ids, vec![member]);

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, member).await;
    }

    /// `MAX_MENTIONS_PER_MESSAGE` is enforced, so a hostile client can't
    /// force an arbitrarily large `message_mentions` insert batch by
    /// padding this list.
    #[tokio::test]
    async fn too_many_mentions_is_rejected() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let owner_device = register_test_device(&db, owner, 74).await;

        let too_many: Vec<Uuid> = (0..=MAX_MENTIONS_PER_MESSAGE).map(|_| Uuid::new_v4()).collect();
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
                mentioned_user_ids: too_many,
            }),
        )
        .await;
        assert!(matches!(result, Err(AppError::BadRequest(_))), "over the cap must be rejected, got {result:?}");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    /// Inserts a message with an attachment directly, bypassing
    /// `create_message` -- these tests need to seed an existing attachment
    /// total without going through a real upload.
    async fn insert_raw_attachment(db: &Database, channel: Uuid, user: Uuid, size: i64, pinned: bool) {
        sqlx::query(
            r#"
            INSERT INTO messages (channel_id, user_id, content, attachment_url, attachment_size, is_pinned, pinned_by)
            VALUES ($1, $2, 'att', '/uploads/seed.bin', $3, $4, CASE WHEN $4 THEN $2 ELSE NULL END)
            "#,
        )
        .bind(channel)
        .bind(user)
        .bind(size)
        .bind(pinned)
        .execute(&db.pool)
        .await
        .expect("failed to seed a raw attachment");
    }

    async fn send_test_message_with_attachment(db: &Database, channel: Uuid, sender: Uuid, sender_device: Uuid, size: i64) -> Result<Message, AppError> {
        create_message(
            State(db.clone()),
            CurrentSession { user_id: sender, session_id: Uuid::new_v4() },
            Path(channel),
            Json(SendChannelMessageRequest {
                attachment_url: Some("/uploads/new.bin".into()),
                attachment_filename: Some("new.bin".into()),
                attachment_size: Some(size),
                attachment_mime_type: Some("application/octet-stream".into()),
                attachment_nonce: Some("file-nonce".into()),
                encrypted_for: vec![EncryptedRecipient {
                    device_id: sender_device,
                    ciphertext: "ciphertext".into(),
                    nonce: "nonce".into(),
                    attachment_key_ciphertext: Some("key".into()),
                    attachment_key_nonce: Some("key-nonce".into()),
                    ratchet_header_json: None,
                    attachment_key_ratchet_header_json: None,
                }],
                sender_device_id: sender_device,
                mentioned_user_ids: vec![],
            }),
        )
        .await
        .map(|Json(m)| m)
    }

    async fn has_attachment(db: &Database, message_id: Uuid) -> bool {
        sqlx::query_scalar("SELECT attachment_url IS NOT NULL FROM messages WHERE id = $1")
            .bind(message_id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to check attachment presence")
    }

    /// The headline behavior requested: instead of just refusing a send
    /// that would bust the quota, the server frees room by stripping the
    /// oldest non-pinned attachment(s) first, same direction as everything
    /// else in this file (cap, not a wall) -- the send itself still
    /// succeeds.
    #[tokio::test]
    async fn sending_an_attachment_evicts_the_oldest_non_pinned_one_to_make_room() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let device = register_test_device(&db, owner, 95).await;

        insert_raw_attachment(&db, channel, owner, crate::access::MAX_SERVER_ATTACHMENT_STORAGE_BYTES - 1000, false).await;
        let oldest_id: Uuid = sqlx::query_scalar("SELECT id FROM messages WHERE channel_id = $1")
            .bind(channel)
            .fetch_one(&db.pool)
            .await
            .expect("failed to find the seeded attachment's message");

        let result = send_test_message_with_attachment(&db, channel, owner, device, 2000).await;
        assert!(result.is_ok(), "the send itself should succeed once enough room is freed, got {result:?}");

        assert!(!has_attachment(&db, oldest_id).await, "the oldest non-pinned attachment should have been evicted to make room");
        assert!(
            server_attachment_total(&db, server).await.expect("failed to total attachments") <= crate::access::MAX_SERVER_ATTACHMENT_STORAGE_BYTES,
            "the server's attachment total must be back under quota after eviction"
        );

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    /// One eviction isn't always enough -- a new attachment that needs
    /// more room than any single old one holds should walk further back
    /// through history, oldest first, until it fits.
    #[tokio::test]
    async fn sending_an_attachment_evicts_multiple_oldest_ones_if_one_is_not_enough() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let device = register_test_device(&db, owner, 98).await;

        // Three small attachments that together fill the quota -- no one
        // of them is enough room on its own for the new send below.
        let third = crate::access::MAX_SERVER_ATTACHMENT_STORAGE_BYTES / 3;
        insert_raw_attachment(&db, channel, owner, third, false).await;
        insert_raw_attachment(&db, channel, owner, third, false).await;
        insert_raw_attachment(&db, channel, owner, third, false).await;
        let seeded_ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM messages WHERE channel_id = $1 ORDER BY created_at ASC")
            .bind(channel)
            .fetch_all(&db.pool)
            .await
            .expect("failed to list seeded messages");

        // Needs room two of the three don't have alone.
        let result = send_test_message_with_attachment(&db, channel, owner, device, third * 2).await;
        assert!(result.is_ok(), "the send should succeed once enough of the backlog is evicted, got {result:?}");

        assert!(!has_attachment(&db, seeded_ids[0]).await, "the oldest seeded attachment should be evicted first");
        assert!(!has_attachment(&db, seeded_ids[1]).await, "a second eviction should follow once the first alone isn't enough room");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    /// A pinned attachment is never evicted to make room, even if it's the
    /// oldest thing in the channel and even if nothing else is evictable --
    /// the send should fail rather than touch it.
    #[tokio::test]
    async fn eviction_never_touches_a_pinned_attachment() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let device = register_test_device(&db, owner, 99).await;

        insert_raw_attachment(&db, channel, owner, crate::access::MAX_SERVER_ATTACHMENT_STORAGE_BYTES, true).await;
        let pinned_id: Uuid = sqlx::query_scalar("SELECT id FROM messages WHERE channel_id = $1")
            .bind(channel)
            .fetch_one(&db.pool)
            .await
            .expect("failed to find the seeded pinned message");

        // The server's non-pinned total is 0 (the only attachment is
        // pinned), so this alone exceeding the whole quota is the one case
        // eviction genuinely can't solve -- there's nothing left to evict.
        let result = send_test_message_with_attachment(&db, channel, owner, device, crate::access::MAX_SERVER_ATTACHMENT_STORAGE_BYTES + 1).await;
        assert!(matches!(result, Err(AppError::BadRequest(_))), "a send that can't fit even with nothing left to evict must be rejected, got {result:?}");
        assert!(has_attachment(&db, pinned_id).await, "a pinned attachment must survive even when eviction can't free enough room");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    #[tokio::test]
    async fn attachment_is_accepted_when_it_fits_the_remaining_quota() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let device = register_test_device(&db, owner, 96).await;

        insert_raw_attachment(&db, channel, owner, crate::access::MAX_SERVER_ATTACHMENT_STORAGE_BYTES - 5000, false).await;

        let result = send_test_message_with_attachment(&db, channel, owner, device, 1000).await;
        assert!(result.is_ok(), "an attachment that still fits under the quota must be accepted, got {result:?}");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    /// Same carve-out as the message cap itself (`retention::MESSAGE_CAP_PER_SERVER`):
    /// a pinned message's attachment is exempt from the quota entirely, not
    /// merely cheaper -- a pinned attachment alone twice the size of the
    /// whole quota must not block an ordinary new one.
    #[tokio::test]
    async fn pinned_attachments_do_not_count_toward_the_storage_quota() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let device = register_test_device(&db, owner, 97).await;

        insert_raw_attachment(&db, channel, owner, crate::access::MAX_SERVER_ATTACHMENT_STORAGE_BYTES * 2, true).await;

        let result = send_test_message_with_attachment(&db, channel, owner, device, 1000).await;
        assert!(
            result.is_ok(),
            "a pinned attachment must not count toward the storage quota, got {result:?}"
        );

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    /// `retention::PIN_CAP_PER_SERVER` is per *server*, summed across all of
    /// its channels, not per channel -- so seeding the cap into a single
    /// channel is enough to prove the check isn't scoped too narrowly.
    #[tokio::test]
    async fn pin_message_is_rejected_once_the_server_hits_its_pin_cap() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;

        sqlx::query(
            r#"
            INSERT INTO messages (channel_id, user_id, content, is_pinned, pinned_by)
            SELECT $1, $2, 'pinned ' || i, true, $2
            FROM generate_series(1, $3) AS i
            "#,
        )
        .bind(channel)
        .bind(owner)
        .bind(crate::retention::PIN_CAP_PER_SERVER)
        .execute(&db.pool)
        .await
        .expect("failed to seed pinned messages");

        let owner_device = register_test_device(&db, owner, 90).await;
        let target = send_test_message(&db, server, channel, owner, owner_device, &[]).await;

        let result = pin_message(State(db.clone()), CurrentUser(owner), Path(target), Bytes::new()).await;
        assert!(
            matches!(result, Err(AppError::BadRequest(_))),
            "pinning past the server's pin cap must be rejected, got {result:?}"
        );

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    /// The pin-cap count must exclude the message being pinned itself, or
    /// re-pinning (or pin_message's reveal-in-one-step path acting on an
    /// already-pinned message) would start failing the instant a server
    /// hits its cap even though no *new* pin is being created.
    #[tokio::test]
    async fn pin_message_allows_repinning_an_already_pinned_message_at_the_cap() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let owner_device = register_test_device(&db, owner, 91).await;

        let target = send_test_message(&db, server, channel, owner, owner_device, &[]).await;
        let _ = pin_message(State(db.clone()), CurrentUser(owner), Path(target), Bytes::new())
            .await
            .expect("the first pin, under the cap, should succeed");

        sqlx::query(
            r#"
            INSERT INTO messages (channel_id, user_id, content, is_pinned, pinned_by)
            SELECT $1, $2, 'pinned ' || i, true, $2
            FROM generate_series(1, $3) AS i
            "#,
        )
        .bind(channel)
        .bind(owner)
        .bind(crate::retention::PIN_CAP_PER_SERVER - 1)
        .execute(&db.pool)
        .await
        .expect("failed to seed pinned messages");

        let result = pin_message(State(db.clone()), CurrentUser(owner), Path(target), Bytes::new()).await;
        assert!(
            result.is_ok(),
            "re-pinning an already-pinned message must not be blocked by a cap that already counts it, got {result:?}"
        );

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    #[tokio::test]
    async fn unpin_message_on_a_recent_pin_just_unpins() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let owner_device = register_test_device(&db, owner, 92).await;
        let target = send_test_message(&db, server, channel, owner, owner_device, &[]).await;

        let _ = pin_message(State(db.clone()), CurrentUser(owner), Path(target), Bytes::new())
            .await
            .expect("pin should succeed");

        let response = unpin_message(State(db.clone()), CurrentUser(owner), Path(target), Query(UnpinQuery::default()))
            .await
            .expect("unpinning a fresh pin should succeed outright, with no confirmation step")
            .0;
        assert_eq!(response["is_pinned"], serde_json::json!(false));

        let still_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM messages WHERE id = $1)")
            .bind(target)
            .fetch_one(&db.pool)
            .await
            .expect("failed to check survival");
        assert!(still_exists, "unpinning a message nowhere near the retention window must not delete it");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    async fn insert_expired_pinned_message(db: &Database, channel: Uuid, owner: Uuid) -> Uuid {
        sqlx::query_scalar(
            r#"
            INSERT INTO messages (channel_id, user_id, content, is_pinned, pinned_by, created_at)
            VALUES ($1, $2, 'old pin', true, $2, NOW() - INTERVAL '31 days')
            RETURNING id
            "#,
        )
        .bind(channel)
        .bind(owner)
        .fetch_one(&db.pool)
        .await
        .expect("failed to insert an already-expired pinned message")
    }

    /// A pin is what's been keeping this message alive past where the
    /// retention sweep would otherwise have taken it (see `retention.rs`);
    /// unpinning it needs a confirmation step before anything changes.
    #[tokio::test]
    async fn unpin_message_warns_before_deleting_an_expired_pin() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let target = insert_expired_pinned_message(&db, channel, owner).await;

        let response = unpin_message(State(db.clone()), CurrentUser(owner), Path(target), Query(UnpinQuery::default()))
            .await
            .expect("the warning call itself should succeed")
            .0;
        assert_eq!(response["requires_confirmation"], serde_json::json!(true));
        assert!(response["warning"].is_string());

        let still_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM messages WHERE id = $1)")
            .bind(target)
            .fetch_one(&db.pool)
            .await
            .expect("failed to check survival");
        assert!(still_exists, "an unconfirmed unpin must not delete or unpin anything yet");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    #[tokio::test]
    async fn unpin_message_with_confirm_deletes_an_expired_pin_immediately() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        let target = insert_expired_pinned_message(&db, channel, owner).await;

        let response = unpin_message(State(db.clone()), CurrentUser(owner), Path(target), Query(UnpinQuery { confirm: true }))
            .await
            .expect("a confirmed unpin of an expired pin should succeed")
            .0;
        assert_eq!(response["deleted"], serde_json::json!(true));

        let still_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM messages WHERE id = $1)")
            .bind(target)
            .fetch_one(&db.pool)
            .await
            .expect("failed to check survival");
        assert!(!still_exists, "confirming the warning must delete the message immediately, not just unpin it");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    // ---------- Channel slowmode ----------

    async fn set_slowmode(db: &Database, channel_id: Uuid, seconds: i32) {
        sqlx::query("UPDATE channels SET slowmode_seconds = $1 WHERE id = $2")
            .bind(seconds)
            .bind(channel_id)
            .execute(&db.pool)
            .await
            .expect("failed to set slowmode directly");
    }

    #[tokio::test]
    async fn second_message_within_the_slowmode_window_is_rejected() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        set_slowmode(&db, channel, 30).await;

        // A plain member, not `owner` -- the server's own owner always
        // bypasses every permission check (`is_unconditional_owner`), so
        // using them here would test nothing.
        let member = create_test_user(&db).await;
        add_server_member(&db, server, member).await;
        let member_device = register_test_device(&db, member, 60).await;
        send_test_message(&db, server, channel, member, member_device, &[]).await;

        let result = create_message(
            State(db.clone()),
            CurrentSession { user_id: member, session_id: Uuid::new_v4() },
            Path(channel),
            Json(SendChannelMessageRequest {
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                encrypted_for: vec![fake_recipient(member_device)],
                sender_device_id: member_device,
                mentioned_user_ids: vec![],
            }),
        )
        .await;
        assert!(
            matches!(result, Err(AppError::TooManyRequests { .. })),
            "a second send inside a 30s slowmode window should be rate limited, got {result:?}"
        );

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, member).await;
    }

    #[tokio::test]
    async fn slowmode_is_scoped_per_user_not_per_channel() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        set_slowmode(&db, channel, 30).await;

        let member_a = create_test_user(&db).await;
        let member_b = create_test_user(&db).await;
        add_server_member(&db, server, member_a).await;
        add_server_member(&db, server, member_b).await;

        let device_a = register_test_device(&db, member_a, 61).await;
        let device_b = register_test_device(&db, member_b, 62).await;

        // Both members already have devices registered by this point, so
        // the completeness check requires both in `encrypted_for`.
        send_test_message(&db, server, channel, member_a, device_a, &[device_b]).await;

        // `member_b` hasn't sent anything yet in this channel, so their own
        // first send must not be blocked by `member_a`'s cooldown.
        let result = create_message(
            State(db.clone()),
            CurrentSession { user_id: member_b, session_id: Uuid::new_v4() },
            Path(channel),
            Json(SendChannelMessageRequest {
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                encrypted_for: vec![fake_recipient(device_a), fake_recipient(device_b)],
                sender_device_id: device_b,
                mentioned_user_ids: vec![],
            }),
        )
        .await;
        assert!(result.is_ok(), "slowmode must be keyed per (channel, user), not shared across members: {result:?}");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, member_a).await;
        cleanup_test_user(&db, member_b).await;
    }

    #[tokio::test]
    async fn a_moderator_is_exempt_from_slowmode() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        set_slowmode(&db, channel, 30).await;

        let moderator = create_test_user(&db).await;
        add_server_moderator(&db, server, moderator).await;
        let moderator_device = register_test_device(&db, moderator, 63).await;

        send_test_message(&db, server, channel, moderator, moderator_device, &[]).await;

        // The legacy "moderator" rank carries MANAGE_MESSAGES via
        // `permissions::legacy_fallback_bits`, so back-to-back sends from a
        // moderator must never trip the cooldown ordinary members face.
        let result = create_message(
            State(db.clone()),
            CurrentSession { user_id: moderator, session_id: Uuid::new_v4() },
            Path(channel),
            Json(SendChannelMessageRequest {
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                encrypted_for: vec![fake_recipient(moderator_device)],
                sender_device_id: moderator_device,
                mentioned_user_ids: vec![],
            }),
        )
        .await;
        assert!(result.is_ok(), "a moderator (manage_messages) should be exempt from slowmode: {result:?}");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, moderator).await;
    }

    #[tokio::test]
    async fn a_send_is_allowed_again_once_the_slowmode_window_elapses() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        set_slowmode(&db, channel, 1).await;

        let member = create_test_user(&db).await;
        add_server_member(&db, server, member).await;
        let member_device = register_test_device(&db, member, 64).await;
        send_test_message(&db, server, channel, member, member_device, &[]).await;

        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        let result = create_message(
            State(db.clone()),
            CurrentSession { user_id: member, session_id: Uuid::new_v4() },
            Path(channel),
            Json(SendChannelMessageRequest {
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                encrypted_for: vec![fake_recipient(member_device)],
                sender_device_id: member_device,
                mentioned_user_ids: vec![],
            }),
        )
        .await;
        assert!(result.is_ok(), "once the window has elapsed, sending again should succeed: {result:?}");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, member).await;
    }

    #[tokio::test]
    async fn slowmode_off_never_rate_limits_sends() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        // slowmode_seconds defaults to 0 -- left unset deliberately.

        let member = create_test_user(&db).await;
        add_server_member(&db, server, member).await;
        let member_device = register_test_device(&db, member, 65).await;
        send_test_message(&db, server, channel, member, member_device, &[]).await;
        let result = create_message(
            State(db.clone()),
            CurrentSession { user_id: member, session_id: Uuid::new_v4() },
            Path(channel),
            Json(SendChannelMessageRequest {
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                encrypted_for: vec![fake_recipient(member_device)],
                sender_device_id: member_device,
                mentioned_user_ids: vec![],
            }),
        )
        .await;
        assert!(result.is_ok(), "with slowmode off, back-to-back sends must never be rate limited: {result:?}");

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, member).await;
    }
}

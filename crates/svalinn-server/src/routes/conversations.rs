use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::{CurrentSession, CurrentUser};
use crate::files::sign_opt;
use crate::models::conversation::ConversationWithParticipant;
use crate::models::device::{EncryptedRecipient, MessageRecipientPayload, ParticipantDevice};
use crate::models::message::BroadcastMessage;

/// Columns for `ConversationWithParticipant`: the conversation plus the
/// *other* participant's identity, online status, presence, patron tier, and
/// whether the requesting user has unread messages in it. `$1` must be the
/// requesting user's id (see `CONVERSATION_JOIN`).
const CONVERSATION_COLUMNS: &str = r#"
    c.id, c.created_at,
    other.user_id AS participant_id,
    u.username AS participant_username,
    COALESCE(u.is_online, false) AS participant_is_online,
    u.status AS participant_status,
    COALESCE(u.patron_tier, 'free') AS participant_patron_tier,
    u.public_key AS participant_public_key,
    EXISTS(
        SELECT 1 FROM messages m
        WHERE m.conversation_id = c.id
          AND m.user_id != $1
          AND m.created_at > COALESCE(cr.last_read_at, '-infinity'::timestamptz)
    ) AS has_unread
"#;

/// Joins a conversation to its other participant (and that user's row), and
/// to the requesting user's `channel_reads` row (for `has_unread`), for the
/// requesting user `$1`. Callers add their own WHERE/ORDER BY.
const CONVERSATION_JOIN: &str = r#"
    FROM conversations c
    JOIN conversation_participants me ON me.conversation_id = c.id AND me.user_id = $1
    JOIN conversation_participants other ON other.conversation_id = c.id AND other.user_id != $1
    JOIN users u ON u.id = other.user_id
    LEFT JOIN channel_reads cr ON cr.conversation_id = c.id AND cr.user_id = $1
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
    /// Legacy ciphertext (single-device model) or plaintext. `None` for a
    /// message sent through the new per-device fan-out model -- that
    /// message's ciphertext lives entirely in `recipients` below. This is
    /// the discriminator the frontend uses to tell "legacy encrypted
    /// message, decrypt with the old single-key path" apart from "new
    /// fan-out message, decrypt via `recipients`": `is_encrypted && content
    /// == null` means the latter.
    pub content: Option<String>,
    pub attachment_url: Option<String>,
    pub attachment_filename: Option<String>,
    pub attachment_mime_type: Option<String>,
    pub attachment_size: Option<i64>,
    /// Base64 nonce for the attachment blob at `attachment_url`, encrypted
    /// with `crypto_secretbox_easy` under a symmetric key shared across
    /// every recipient device (that key itself is wrapped per-device --
    /// see `recipients[].attachment_key_ciphertext`). `None` when there's
    /// no attachment, or it's a plaintext/legacy one.
    pub attachment_nonce: Option<String>,
    pub is_edited: bool,
    /// Whether this message is encrypted (either the legacy single-device
    /// way, with ciphertext in `content`, or the new fan-out way, with
    /// ciphertext in `recipients`). False for all pre-E2EE history, which
    /// is left exactly as it was sent.
    pub is_encrypted: bool,
    /// Base64-encoded nonce used to encrypt the legacy `content`. Only
    /// present for a legacy single-device-era encrypted message; `None` for
    /// a new fan-out message (whose per-recipient nonces are in
    /// `recipients`) and for plaintext messages.
    pub nonce: Option<String>,
    /// Per-device ciphertext for a fan-out (new multi-device model)
    /// message. Always empty for plaintext and for legacy single-device
    /// messages.
    ///
    /// Populated differently depending on how this `ConversationMessage`
    /// was built, since who's allowed to see which device's ciphertext
    /// differs by delivery path:
    /// - History fetch (`get_conversation_messages`): at most one entry --
    ///   the row addressed to the requesting device (`?device_id=`), if
    ///   any. Other devices' ciphertext for this message is never sent
    ///   here.
    /// - WebSocket broadcast (`new_direct_message`): every recipient
    ///   device's entry, for both participants. Each connected device
    ///   picks out the one entry matching its own device id and ignores
    ///   the rest; this avoids the server needing to filter per-connection
    ///   (every device of a user already receives the same broadcast
    ///   event, the same way pre-fan-out single-shared-ciphertext messages
    ///   did).
    #[sqlx(skip)]
    pub recipients: Vec<MessageRecipientPayload>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

const CONVERSATION_MESSAGE_COLUMNS: &str = r#"
    m.id, m.conversation_id, m.user_id, u.username, m.content,
    m.attachment_url, m.attachment_filename, m.attachment_mime_type, m.attachment_size,
    m.attachment_nonce,
    COALESCE(m.is_edited, false) AS is_edited,
    m.is_encrypted, m.nonce,
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
    /// This client's own device id (from `POST /users/me/devices`'s
    /// response, as stored locally). Needed to pick this device's own
    /// ciphertext out of `message_recipients` for any fan-out message in
    /// the page -- see `ConversationMessage::recipients`. Omitting it
    /// (e.g. an old client that hasn't adopted per-device keys) just means
    /// every fan-out message comes back with no ciphertext, same as an
    /// unrecognized device id would.
    pub device_id: Option<Uuid>,
}

/// Looks up `message_recipients` rows for a set of messages, grouped by
/// message id.
///
/// `device_id_filter`:
/// - `Some(id)`: only rows addressed to that device (used by the history
///   fetch endpoint -- a client only ever gets its own ciphertext).
/// - `None`: every row for those messages, across every recipient device
///   of both participants (used when building the WebSocket broadcast
///   payload -- see `ConversationMessage::recipients` for why).
async fn fetch_recipients_for_messages(
    db: &Database,
    message_ids: &[Uuid],
    device_id_filter: Option<Uuid>,
) -> Result<HashMap<Uuid, Vec<MessageRecipientPayload>>, AppError> {
    if message_ids.is_empty() {
        return Ok(HashMap::new());
    }

    #[derive(FromRow)]
    struct RecipientRow {
        message_id: Uuid,
        device_id: Uuid,
        ciphertext: String,
        nonce: String,
        sender_public_key: String,
        attachment_key_ciphertext: Option<String>,
        attachment_key_nonce: Option<String>,
    }

    let rows: Vec<RecipientRow> = sqlx::query_as(
        r#"
        SELECT message_id, device_id, ciphertext, nonce, sender_public_key,
               attachment_key_ciphertext, attachment_key_nonce
        FROM message_recipients
        WHERE message_id = ANY($1) AND ($2::uuid IS NULL OR device_id = $2)
        "#,
    )
    .bind(message_ids)
    .bind(device_id_filter)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut map: HashMap<Uuid, Vec<MessageRecipientPayload>> = HashMap::new();
    for row in rows {
        map.entry(row.message_id).or_default().push(MessageRecipientPayload {
            device_id: row.device_id,
            ciphertext: row.ciphertext,
            nonce: row.nonce,
            sender_public_key: row.sender_public_key,
            attachment_key_ciphertext: row.attachment_key_ciphertext,
            attachment_key_nonce: row.attachment_key_nonce,
        });
    }
    Ok(map)
}

/// GET /api/v1/conversations/:id/messages?before=<message_id>&limit=50
///
/// Returns a page of the conversation's messages, oldest first: the latest
/// ones, or with `before`, the ones just older than that message. Fewer than
/// `limit` messages means there's no more history. The current user must be
/// a participant.
pub async fn get_conversation_messages(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
    Path(conversation_id): Path<Uuid>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<Vec<ConversationMessage>>, AppError> {
    require_participant(&db, conversation_id, user_id).await?;
    let limit = query.limit.unwrap_or(PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);

    // Page by (created_at, id) so messages with the same timestamp are
    // neither skipped nor repeated.
    let mut messages: Vec<ConversationMessage> = if let Some(before) = query.before {
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

    // A client that never set up per-device keys (or just hasn't told us
    // which device it is) must never see ANY device's ciphertext for a
    // fan-out message -- not even by accident via a NULL-matches-anything
    // filter bug. Uuid::nil() is never a real device id, so filtering by it
    // deterministically yields zero rows, same as an unrecognized real id
    // would.
    //
    // `device_id` is caller-supplied and otherwise unverified: without
    // confirming it's actually one of the caller's OWN registered devices,
    // a participant could pass another participant's device_id and receive
    // that device's per-device ciphertext/nonce instead of their own. A
    // device_id that doesn't belong to the caller is treated exactly like
    // no device_id was supplied -- i.e. it falls back to the nil sentinel --
    // so a confused/stale/malicious client gets back no ciphertext rather
    // than being told why.
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
    for message in &mut messages {
        if let Some(entries) = recipients_by_message.get(&message.id) {
            message.recipients = entries.clone();
        }
    }

    // Opening a conversation (loading its latest page) marks it as read, so
    // `has_unread` clears. Paging into older history doesn't touch the read
    // cursor.
    if query.before.is_none() {
        // Use the latest fetched message's own timestamp as the read cutoff
        // rather than NOW(), so a message that arrives after the SELECT above
        // but before this INSERT isn't incorrectly marked as read.
        let last_read_at = messages.last().map(|m| m.created_at).unwrap_or_else(chrono::Utc::now);
        sqlx::query(
            r#"
            INSERT INTO channel_reads (user_id, conversation_id, last_read_message_id, last_read_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id, conversation_id)
            DO UPDATE SET last_read_message_id = EXCLUDED.last_read_message_id, last_read_at = EXCLUDED.last_read_at
            "#,
        )
        .bind(user_id)
        .bind(conversation_id)
        .bind(messages.last().map(|m| m.id))
        .bind(last_read_at)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    }

    // Each message's `attachment_url`, if any, is stored as a bare
    // `/uploads/<name>` path -- turn it into a signed, viewer-bound link
    // before it leaves the server (see `files.rs`). Unlike the WebSocket
    // broadcast path (where `ws.rs` signs generically per-connection at
    // delivery time), this HTTP response has exactly one recipient --
    // this request's own caller -- so it's signed once, right here.
    for message in &mut messages {
        sign_opt(&mut message.attachment_url, user_id, session_id);
    }

    Ok(Json(messages))
}

/// Longest message content accepted (matches channel messages).
const MAX_CONTENT_CHARS: usize = 4000;

/// Longest per-recipient ciphertext accepted in a fan-out send's
/// `encrypted_for` (base64, `crypto_box_easy` output). Derived from
/// `MAX_CONTENT_CHARS`: 4000 plaintext chars, worst case 4 bytes/char in
/// UTF-8 (16,000 bytes), plus the 16-byte Poly1305 MAC `crypto_box_easy`
/// appends (16,016 bytes), base64-encoded at ~4/3 expansion (~21,355
/// chars) -- rounded up with real headroom so a legitimate max-length
/// message is never at risk of rejection.
const MAX_FANOUT_CIPHERTEXT_B64_CHARS: usize = 24_000;

/// Longest per-recipient nonce accepted in a fan-out send's
/// `encrypted_for`. The client always base64-encodes a fixed-size
/// `crypto_box_NONCEBYTES` (24-byte) nonce, which is always exactly 32
/// base64 chars -- no headroom needed since this isn't an estimate.
const MAX_FANOUT_NONCE_B64_CHARS: usize = 32;

/// Longest per-recipient wrapped attachment key accepted. The wrapped
/// value is a `crypto_box_easy` ciphertext of a fixed 32-byte
/// `crypto_secretbox` key: 32 + 16 (Poly1305 MAC) = 48 bytes, base64 ->
/// exactly 64 chars. Rounded up with headroom, same style as
/// `MAX_FANOUT_CIPHERTEXT_B64_CHARS` above.
const MAX_ATTACHMENT_KEY_CIPHERTEXT_B64_CHARS: usize = 100;

/// GET /api/v1/conversations/:id/participant-devices
///
/// Lists every registered device (id, owning user, public key, label) for
/// BOTH participants of this conversation -- the current user and the
/// other one. A client composing a send uses this to know exactly which
/// devices to encrypt a copy for: EVERY entry this returns, with no
/// exclusions -- every `is_me: false` entry (the other participant's
/// devices -- skipping any of them leaves that device unable to read
/// anything, which must never happen silently), every OTHER `is_me: true`
/// entry (so the sender's own other sessions can read what was just
/// sent), AND the `is_me: true` entry for the device making the request
/// itself. That last one matters: the sending device gets a real
/// encrypted copy too, with no special-casing, so it decrypts its own
/// sent message the exact same way any other device would (see
/// `encryptAndSend` in `DMChatArea.svelte`). `send_fanout_message` below
/// enforces that `encrypted_for` covers exactly this whole list.
pub async fn get_participant_devices(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(conversation_id): Path<Uuid>,
) -> Result<Json<Vec<ParticipantDevice>>, AppError> {
    require_participant(&db, conversation_id, user_id).await?;

    let devices: Vec<ParticipantDevice> = sqlx::query_as(
        r#"
        SELECT dk.id AS device_id, dk.user_id, dk.public_key, dk.device_label, (dk.user_id = $1) AS is_me
        FROM device_keys dk
        JOIN conversation_participants cp ON cp.user_id = dk.user_id
        WHERE cp.conversation_id = $2
        ORDER BY dk.created_at ASC
        "#,
    )
    .bind(user_id)
    .bind(conversation_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(devices))
}

#[derive(Deserialize)]
pub struct SendDirectMessageRequest {
    /// Plaintext, or legacy single-device ciphertext (paired with the
    /// legacy `is_encrypted`/`nonce` fields below). Ignored when
    /// `encrypted_for` is present and non-empty -- a fan-out send carries
    /// no shared `content` at all, only per-device ciphertext.
    #[serde(default)]
    pub content: Option<String>,
    pub attachment_url: Option<String>,
    pub attachment_filename: Option<String>,
    pub attachment_size: Option<i64>,
    pub attachment_mime_type: Option<String>,
    /// Base64 `crypto_secretbox_easy` nonce for the attachment blob at
    /// `attachment_url`. Only meaningful (and only accepted) alongside
    /// `encrypted_for` -- see `send_fanout_message`'s validation. Ignored
    /// on the legacy path, same as attachment fields always have been.
    #[serde(default)]
    pub attachment_nonce: Option<String>,
    /// Legacy single-device encryption flag: whether `content` is base64
    /// ciphertext (NaCl `crypto_box`) rather than plaintext. Kept only for
    /// backward compatibility / non-encrypted sends -- a new E2EE send
    /// should use `encrypted_for` instead.
    #[serde(default)]
    pub is_encrypted: bool,
    /// Base64-encoded nonce for the legacy `content` ciphertext. Required
    /// (and must be non-empty) when `is_encrypted` is true and
    /// `encrypted_for` is absent/empty.
    #[serde(default)]
    pub nonce: Option<String>,
    /// New per-device fan-out send: one ciphertext per recipient device
    /// (every device of both participants that should receive this
    /// message -- see `get_participant_devices`). When this is present and
    /// non-empty, it takes over the whole send: `content`/`is_encrypted`/
    /// `nonce` above are ignored, the `messages` row is stored with
    /// `is_encrypted = true` and `content`/`nonce` left NULL, and one
    /// `message_recipients` row is inserted per entry, atomically with the
    /// `messages` insert.
    #[serde(default)]
    pub encrypted_for: Option<Vec<EncryptedRecipient>>,
    /// Required when `encrypted_for` is non-empty: the id of the device
    /// (one of the caller's own, from `POST /users/me/devices`) that did
    /// the encrypting. Used to resolve and record `sender_public_key` on
    /// every inserted `message_recipients` row -- see migration 0030's
    /// comment on why a recipient device needs the *sender's* public key,
    /// not just its own, to decrypt.
    #[serde(default)]
    pub sender_device_id: Option<Uuid>,
}

/// POST /api/v1/conversations/:id/messages
///
/// The conversation id in the path is authoritative; a `conversation_id` in
/// the body (the desktop client sends one) is ignored.
pub async fn send_conversation_message(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
    Path(conversation_id): Path<Uuid>,
    Json(payload): Json<SendDirectMessageRequest>,
) -> Result<Json<ConversationMessage>, AppError> {
    require_participant(&db, conversation_id, user_id).await?;

    let recipients = payload.encrypted_for.clone().unwrap_or_default();
    let msg_id = if !recipients.is_empty() {
        send_fanout_message(&db, conversation_id, user_id, &payload, &recipients).await?
    } else {
        send_legacy_message(&db, conversation_id, user_id, &payload).await?
    };

    let message: ConversationMessage = sqlx::query_as(&format!(
        "SELECT {CONVERSATION_MESSAGE_COLUMNS} FROM messages m JOIN users u ON m.user_id = u.id WHERE m.id = $1"
    ))
    .bind(msg_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // For a fan-out message, attach every recipient device's entry (not
    // just the sender's) -- the broadcast below, and this same response
    // object, are shared across both participants' connected devices, each
    // of which picks out its own entry. See `ConversationMessage::recipients`.
    let mut message = message;
    if message.is_encrypted && message.content.is_none() {
        let recipients_by_message = fetch_recipients_for_messages(&db, &[message.id], None).await?;
        if let Some(entries) = recipients_by_message.get(&message.id) {
            message.recipients = entries.clone();
        }
    }

    // Notify every participant over the websocket -- including the sender's
    // own user_id. `BroadcastMessage::to_user` fans out to every connection
    // registered for that user_id (see `ws.rs`), so including the sender
    // here is what actually reaches the sender's OTHER connected devices
    // (e.g. phone + laptop on the same account). The sending device itself
    // already has the message from this handler's HTTP response and dedupes
    // the echoed broadcast by message id (see `addMessage` in
    // `DMChatArea.svelte`), so re-including the sender is safe.
    let participants: Vec<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM conversation_participants WHERE conversation_id = $1",
    )
    .bind(conversation_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if let Ok(payload) = serde_json::to_value(&message) {
        for recipient in participants {
            let _ = db.message_tx.send(BroadcastMessage::to_user("new_direct_message", payload.clone(), recipient));
        }
    }

    // Signed AFTER building the broadcast payload above, and only on this
    // function's own local `message`, never on a value shared with it: the
    // broadcast must carry the bare `/uploads/<name>` path so `ws.rs` can
    // sign it fresh for each connection it's delivered to (every
    // participant, each with their own user_id/session_id -- see
    // `sign_json` there). Signing it here first would bake in THIS
    // request's caller as the only valid viewer, breaking the link for
    // everyone else it's broadcast to.
    sign_opt(&mut message.attachment_url, user_id, session_id);

    Ok(Json(message))
}

/// The old plaintext / single-device-encrypted send path, unchanged in
/// behavior from before per-device fan-out existed.
async fn send_legacy_message(
    db: &Database,
    conversation_id: Uuid,
    user_id: Uuid,
    payload: &SendDirectMessageRequest,
) -> Result<Uuid, AppError> {
    let content = payload.content.clone().unwrap_or_default();
    if content.chars().count() > MAX_CONTENT_CHARS {
        return Err(AppError::BadRequest(format!("Messages can be at most {MAX_CONTENT_CHARS} characters")));
    }
    if content.trim().is_empty() && payload.attachment_url.is_none() {
        return Err(AppError::BadRequest("Message cannot be empty".into()));
    }
    if payload.is_encrypted && payload.nonce.as_deref().unwrap_or("").trim().is_empty() {
        return Err(AppError::BadRequest("nonce is required for an encrypted message".into()));
    }
    // Encrypted attachments are only supported on the fan-out path (every
    // recipient device needs its own wrapped copy of the file key, which
    // only exists there) -- a client sending `attachment_nonce` here
    // without `encrypted_for` is sending a payload this path can't honor,
    // not an attachment this path should silently store unencrypted.
    if payload.attachment_nonce.is_some() {
        return Err(AppError::BadRequest(
            "attachment_nonce requires encrypted_for (per-device fan-out send)".into(),
        ));
    }

    sqlx::query_scalar(
        r#"
        INSERT INTO messages (conversation_id, channel_id, user_id, content, attachment_url, attachment_filename, attachment_mime_type, attachment_size, is_encrypted, nonce)
        VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#,
    )
    .bind(conversation_id)
    .bind(user_id)
    .bind(&content)
    .bind(&payload.attachment_url)
    .bind(&payload.attachment_filename)
    .bind(&payload.attachment_mime_type)
    .bind(payload.attachment_size)
    .bind(payload.is_encrypted)
    .bind(&payload.nonce)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))
}

/// The new per-device fan-out send path: validates every recipient device
/// actually belongs to a real participant of this conversation and that
/// `sender_device_id` belongs to the caller, then inserts the `messages`
/// row and every `message_recipients` row in one transaction -- either all
/// of it lands, or none of it does.
async fn send_fanout_message(
    db: &Database,
    conversation_id: Uuid,
    user_id: Uuid,
    payload: &SendDirectMessageRequest,
    recipients: &[EncryptedRecipient],
) -> Result<Uuid, AppError> {
    let sender_device_id = payload
        .sender_device_id
        .ok_or_else(|| AppError::BadRequest("sender_device_id is required when encrypted_for is set".into()))?;

    // An attachment is encrypted iff `attachment_url` is set: then every
    // recipient MUST carry a wrapped copy of the file key (skipping even
    // one leaves that device permanently unable to read the attachment,
    // same invariant as the message ciphertext itself), and the message
    // needs the shared blob's nonce. With no attachment, none of this
    // applies -- reject a mismatched client payload outright rather than
    // silently ignoring stray fields, since either direction of mismatch
    // is a real client bug worth surfacing immediately.
    let has_attachment = payload.attachment_url.is_some();
    if has_attachment && payload.attachment_nonce.as_deref().unwrap_or("").trim().is_empty() {
        return Err(AppError::BadRequest("attachment_nonce is required when attachment_url is set".into()));
    }
    if !has_attachment && payload.attachment_nonce.is_some() {
        return Err(AppError::BadRequest("attachment_nonce must not be set without attachment_url".into()));
    }

    for r in recipients {
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
    }
    let device_ids: Vec<Uuid> = recipients.iter().map(|r| r.device_id).collect();
    let mut seen = HashSet::new();
    for id in &device_ids {
        if !seen.insert(*id) {
            return Err(AppError::BadRequest("encrypted_for contains the same device_id more than once".into()));
        }
    }

    let participant_ids: Vec<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM conversation_participants WHERE conversation_id = $1")
            .bind(conversation_id)
            .fetch_all(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    let mut tx = db.pool.begin().await.map_err(|e| AppError::Database(e.to_string()))?;

    let sender_public_key: Option<String> =
        sqlx::query_scalar("SELECT public_key FROM device_keys WHERE id = $1 AND user_id = $2")
            .bind(sender_device_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    let sender_public_key =
        sender_public_key.ok_or_else(|| AppError::BadRequest("sender_device_id must be one of your own registered devices".into()))?;

    // Every recipient device must belong to device_keys owned by one of
    // this conversation's two real participants -- otherwise reject the
    // whole send rather than partially deliver it.
    let valid_device_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM device_keys WHERE id = ANY($1) AND user_id = ANY($2)",
    )
    .bind(&device_ids)
    .bind(&participant_ids)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    if valid_device_count as usize != device_ids.len() {
        return Err(AppError::BadRequest(
            "encrypted_for contains a device_id that doesn't belong to a participant in this conversation".into(),
        ));
    }

    // `encrypted_for` must cover every currently-registered device of every
    // participant, INCLUDING the sender's own sending device -- the client
    // (`encryptAndSend` in `DMChatArea.svelte`) deliberately encrypts a
    // real copy for its own current device too, with no special-casing, so
    // that it decrypts its own sent message the exact same way any other
    // device would (this is what fixed the self-echo race: see the
    // comments there). Excluding sender_device_id here would reject every
    // real send the actual client makes. A buggy/malicious client could
    // otherwise submit a fan-out that only its own device(s) can decrypt,
    // silently excluding the other participant (or one of the sender's
    // OTHER devices) with no error anywhere. Read inside the same
    // transaction as the rest of this function's checks so it sees a
    // consistent device list; a device registered/removed concurrently via
    // another transaction is an existing acceptable race, not a new one.
    let registered_device_ids: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM device_keys WHERE user_id = ANY($1)")
            .bind(&participant_ids)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    let required_device_ids: HashSet<Uuid> = registered_device_ids.into_iter().collect();
    if required_device_ids != seen {
        let missing: Vec<Uuid> = required_device_ids.difference(&seen).copied().collect();
        return Err(AppError::BadRequest(format!(
            "encrypted_for must contain exactly every currently-registered device of both participants (including the sender's own sending device); missing: {missing:?}"
        )));
    }

    let msg_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO messages (conversation_id, channel_id, user_id, content, attachment_url, attachment_filename, attachment_mime_type, attachment_size, attachment_nonce, is_encrypted, nonce)
        VALUES ($1, NULL, $2, NULL, $3, $4, $5, $6, $7, true, NULL)
        RETURNING id
        "#,
    )
    .bind(conversation_id)
    .bind(user_id)
    .bind(&payload.attachment_url)
    .bind(&payload.attachment_filename)
    .bind(&payload.attachment_mime_type)
    .bind(payload.attachment_size)
    .bind(&payload.attachment_nonce)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    for r in recipients {
        sqlx::query(
            "INSERT INTO message_recipients (message_id, device_id, ciphertext, nonce, sender_public_key, attachment_key_ciphertext, attachment_key_nonce) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(msg_id)
        .bind(r.device_id)
        .bind(&r.ciphertext)
        .bind(&r.nonce)
        .bind(&sender_public_key)
        .bind(&r.attachment_key_ciphertext)
        .bind(&r.attachment_key_nonce)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    }

    tx.commit().await.map_err(|e| AppError::Database(e.to_string()))?;

    Ok(msg_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::future::join_all;

    /// Connects to the same database the app uses in development (see
    /// `.env`), matching `main.rs`'s own startup. Every test using this
    /// shares that database with manual testing and every other test, so
    /// each test must create its own uniquely-named data and never mutate
    /// or assert on rows it didn't create itself.
    async fn test_db() -> Database {
        dotenvy::dotenv().ok();
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is required for tests");
        Database::new(&database_url).await.expect("failed to connect to test database")
    }

    /// Inserts a throwaway user with a randomly-generated unique
    /// username/email, so concurrent/test runs never collide. The password
    /// hash is a dummy value: these users never log in.
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

    /// Like `create_test_user`, but explicitly sets `patron_tier` to NULL
    /// (rather than relying on the column's default) to prove the
    /// `COALESCE(u.patron_tier, 'free')` in the conversation queries really
    /// handles a null value, not just an unset one.
    async fn create_test_user_with_null_patron_tier(db: &Database) -> Uuid {
        let unique = Uuid::new_v4();
        sqlx::query_scalar(
            "INSERT INTO users (username, email, password_hash, display_name, patron_tier) VALUES ($1, $2, $3, $4, NULL) RETURNING id",
        )
        .bind(format!("test_{unique}"))
        .bind(format!("test_{unique}@example.invalid"))
        .bind("not-a-real-hash")
        .bind(format!("Test User {unique}"))
        .fetch_one(&db.pool)
        .await
        .expect("failed to insert test user with null patron_tier")
    }

    /// Deletes a test user by id. Relies on the `ON DELETE CASCADE` FKs from
    /// `conversation_participants.user_id`, `messages.user_id`, and
    /// `channel_reads.user_id` to clean up everything that user created, so
    /// repeated test runs don't grow the shared dev database forever.
    ///
    /// Note: this does NOT delete the `conversations` row itself (that table
    /// has no FK back to `users`), so a test that created a conversation must
    /// also call `cleanup_test_conversation` for it.
    ///
    /// Best-effort / happy-path only: called at the end of each test's
    /// function body, so a panicking `assert!` earlier in the test will skip
    /// it and leave that test's rows behind. That's an acceptable tradeoff
    /// for a non-blocking cleanup improvement; a panic-safe RAII guard would
    /// add real complexity for comparatively little benefit here.
    async fn cleanup_test_user(db: &Database, user_id: Uuid) {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1").bind(user_id).execute(&db.pool).await;
    }

    /// Deletes a test conversation by id. The `conversations` table has no
    /// FK back to `users`, so `cleanup_test_user` alone leaves an empty
    /// orphaned conversation row behind; call this too (after cleaning up
    /// that conversation's test users) in any test that created one. By the
    /// time this runs, `conversation_participants`/`messages`/
    /// `channel_reads` rows for that conversation are already gone via the
    /// user-cascade, so this plain delete has nothing left to cascade and is
    /// safe to run afterward. Same best-effort/happy-path caveat as
    /// `cleanup_test_user`.
    async fn cleanup_test_conversation(db: &Database, conversation_id: Uuid) {
        let _ = sqlx::query("DELETE FROM conversations WHERE id = $1").bind(conversation_id).execute(&db.pool).await;
    }

    #[tokio::test]
    async fn create_or_get_conversation_is_idempotent_both_orderings() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conv_ab = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("A->B create_or_get_conversation should succeed")
        .0
        .id;

        let conv_ba = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_b),
            Json(CreateConversationRequest { participant_id: user_a }),
        )
        .await
        .expect("B->A create_or_get_conversation should succeed")
        .0
        .id;

        assert_eq!(conv_ab, conv_ba, "both orderings should return the same conversation id");

        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM conversations c
            WHERE EXISTS(SELECT 1 FROM conversation_participants p WHERE p.conversation_id = c.id AND p.user_id = $1)
              AND EXISTS(SELECT 1 FROM conversation_participants p WHERE p.conversation_id = c.id AND p.user_id = $2)
            "#,
        )
        .bind(user_a)
        .bind(user_b)
        .fetch_one(&db.pool)
        .await
        .expect("count query failed");
        assert_eq!(count, 1, "exactly one conversation should exist for this pair of users");

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, conv_ab).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_or_get_conversation_is_race_safe_under_concurrency() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        const TASK_COUNT: usize = 20;
        let tasks: Vec<_> = (0..TASK_COUNT)
            .map(|i| {
                let db = db.clone();
                // Alternate direction to exercise the sorted-pair advisory lock
                // regardless of who's "current user" vs "other user".
                let (current, other) = if i % 2 == 0 { (user_a, user_b) } else { (user_b, user_a) };
                tokio::spawn(async move {
                    create_or_get_conversation(
                        State(db),
                        CurrentUser(current),
                        Json(CreateConversationRequest { participant_id: other }),
                    )
                    .await
                    .map(|Json(c)| c.id)
                })
            })
            .collect();

        let results: Vec<Uuid> = join_all(tasks)
            .await
            .into_iter()
            .map(|join_result| join_result.expect("task panicked").expect("create_or_get_conversation failed"))
            .collect();

        assert_eq!(results.len(), TASK_COUNT);
        let first = results[0];
        assert!(results.iter().all(|id| *id == first), "every concurrent call should return the same conversation id, got: {results:?}");

        let conversation_count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM conversations c
            WHERE EXISTS(SELECT 1 FROM conversation_participants p WHERE p.conversation_id = c.id AND p.user_id = $1)
              AND EXISTS(SELECT 1 FROM conversation_participants p WHERE p.conversation_id = c.id AND p.user_id = $2)
            "#,
        )
        .bind(user_a)
        .bind(user_b)
        .fetch_one(&db.pool)
        .await
        .expect("conversation count query failed");
        assert_eq!(conversation_count, 1, "concurrent calls must not create more than one conversation");

        let participant_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM conversation_participants WHERE conversation_id = $1",
        )
        .bind(first)
        .fetch_one(&db.pool)
        .await
        .expect("participant count query failed");
        assert_eq!(participant_count, 2, "the conversation must end up with exactly two participants");

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, first).await;
    }

    #[tokio::test]
    async fn create_or_get_conversation_rejects_self() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;

        let result = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_a }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for self-conversation, got {other:?}"),
        }

        cleanup_test_user(&db, user_a).await;
    }

    #[tokio::test]
    async fn create_or_get_conversation_rejects_nonexistent_participant() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let bogus_participant = Uuid::new_v4();

        let result = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: bogus_participant }),
        )
        .await;

        match result {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected AppError::NotFound for a nonexistent participant, got {other:?}"),
        }

        cleanup_test_user(&db, user_a).await;
    }

    #[tokio::test]
    async fn non_participant_is_forbidden_from_messages() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;
        let user_c = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let read_result = get_conversation_messages(
            State(db.clone()),
            CurrentSession { user_id: user_c, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Query(HistoryQuery { before: None, limit: None, device_id: None }),
        )
        .await;
        match read_result {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected AppError::Forbidden reading messages as a non-participant, got {other:?}"),
        }

        let send_result = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_c, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: Some("hello from an outsider".into()),
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                is_encrypted: false,
                nonce: None,
                encrypted_for: None,
                sender_device_id: None,
            }),
        )
        .await;
        match send_result {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected AppError::Forbidden sending a message as a non-participant, got {other:?}"),
        }

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_user(&db, user_c).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    #[tokio::test]
    async fn send_then_fetch_round_trip() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let sent = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: Some("hello from A".into()),
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                is_encrypted: false,
                nonce: None,
                encrypted_for: None,
                sender_device_id: None,
            }),
        )
        .await
        .expect("sending message failed")
        .0;

        assert_eq!(sent.content.as_deref(), Some("hello from A"));
        assert_eq!(sent.user_id, user_a);

        let messages = get_conversation_messages(
            State(db.clone()),
            CurrentSession { user_id: user_b, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Query(HistoryQuery { before: None, limit: None, device_id: None }),
        )
        .await
        .expect("fetching messages failed")
        .0;

        let found = messages.iter().find(|m| m.id == sent.id);
        let found = found.expect("the message sent by A should appear in B's view of the conversation");
        assert_eq!(found.content.as_deref(), Some("hello from A"));
        assert_eq!(found.user_id, user_a);

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    #[tokio::test]
    async fn has_unread_cycles_correctly() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let _ = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: Some("ping".into()),
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                is_encrypted: false,
                nonce: None,
                encrypted_for: None,
                sender_device_id: None,
            }),
        )
        .await
        .expect("sending message failed");

        // B has an unread message from A.
        let b_conversations = get_user_conversations(State(db.clone()), CurrentUser(user_b))
            .await
            .expect("fetching B's conversations failed")
            .0;
        let b_view = b_conversations
            .iter()
            .find(|c| c.id == conversation_id)
            .expect("B should see the conversation");
        assert!(b_view.has_unread, "B should have an unread message right after A sends one");

        // A's own list should never show unread for a message A sent themselves.
        let a_conversations = get_user_conversations(State(db.clone()), CurrentUser(user_a))
            .await
            .expect("fetching A's conversations failed")
            .0;
        let a_view = a_conversations
            .iter()
            .find(|c| c.id == conversation_id)
            .expect("A should see the conversation");
        assert!(!a_view.has_unread, "A should never see unread for their own sent message");

        // B reads the conversation (loading the latest page marks it read).
        let _ = get_conversation_messages(
            State(db.clone()),
            CurrentSession { user_id: user_b, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Query(HistoryQuery { before: None, limit: None, device_id: None }),
        )
        .await
        .expect("fetching messages as B failed");

        let b_conversations_after = get_user_conversations(State(db.clone()), CurrentUser(user_b))
            .await
            .expect("fetching B's conversations after read failed")
            .0;
        let b_view_after = b_conversations_after
            .iter()
            .find(|c| c.id == conversation_id)
            .expect("B should still see the conversation");
        assert!(!b_view_after.has_unread, "B's unread flag should clear after loading messages");

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    #[tokio::test]
    async fn participant_patron_tier_defaults_to_free_when_null() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let patron_user = create_test_user_with_null_patron_tier(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: patron_user }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let a_conversations = get_user_conversations(State(db.clone()), CurrentUser(user_a))
            .await
            .expect("fetching A's conversations failed")
            .0;
        let view = a_conversations
            .iter()
            .find(|c| c.participant_id == patron_user)
            .expect("A should see the conversation with the null-patron-tier user");
        assert_eq!(view.participant_patron_tier, "free", "a NULL patron_tier should surface as \"free\", not an error or missing field");

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, patron_user).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    /// An encrypted message's `content` is opaque ciphertext to the server;
    /// it must still be stored and returned faithfully, along with
    /// `is_encrypted`/`nonce`, exactly as given -- the server never
    /// interprets or validates the ciphertext itself.
    #[tokio::test]
    async fn encrypted_message_round_trips_content_and_nonce() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let fake_ciphertext = "dGhpcyBpcyBub3QgcmVhbCBjaXBoZXJ0ZXh0";
        let fake_nonce = "dGhpcyBpcyBub3QgYSByZWFsIG5vbmNl";

        let sent = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: Some(fake_ciphertext.into()),
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                is_encrypted: true,
                nonce: Some(fake_nonce.into()),
                encrypted_for: None,
                sender_device_id: None,
            }),
        )
        .await
        .expect("sending encrypted message failed")
        .0;

        assert!(sent.is_encrypted);
        assert_eq!(sent.content.as_deref(), Some(fake_ciphertext));
        assert_eq!(sent.nonce.as_deref(), Some(fake_nonce));

        let messages = get_conversation_messages(
            State(db.clone()),
            CurrentSession { user_id: user_b, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Query(HistoryQuery { before: None, limit: None, device_id: None }),
        )
        .await
        .expect("fetching messages failed")
        .0;

        let found = messages.iter().find(|m| m.id == sent.id).expect("encrypted message should appear in history");
        assert!(found.is_encrypted, "fetched message should still be flagged as encrypted");
        assert_eq!(found.content.as_deref(), Some(fake_ciphertext), "ciphertext content must round-trip unchanged");
        assert_eq!(found.nonce.as_deref(), Some(fake_nonce), "nonce must round-trip unchanged");

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    /// An encrypted message sent without a nonce (or with an empty one) is
    /// rejected -- the single most important invariant is that the server
    /// never silently accepts something that looks like a plaintext
    /// fallback for what was supposed to be encrypted.
    #[tokio::test]
    async fn encrypted_message_without_nonce_is_rejected() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let result = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: Some("ciphertext-looking-thing".into()),
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                is_encrypted: true,
                nonce: None,
                encrypted_for: None,
                sender_device_id: None,
            }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for an encrypted message with no nonce, got {other:?}"),
        }

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    /// Uploading a public key makes it retrievable through the conversation
    /// endpoint that the client relies on to find the other participant's
    /// key before encrypting a message to them.
    #[tokio::test]
    async fn public_key_upload_is_visible_via_conversation_participant() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        // A 32-byte value, base64-encoded, matching the shape of a real
        // X25519 public key (the server only checks the shape, not that it's
        // "real").
        let fake_public_key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [7u8; 32]);

        let updated = crate::routes::users::update_public_key(
            State(db.clone()),
            CurrentUser(user_b),
            Json(crate::routes::users::UpdatePublicKeyRequest { public_key: fake_public_key.clone() }),
        )
        .await
        .expect("uploading public key failed")
        .0;
        assert_eq!(updated.public_key.as_deref(), Some(fake_public_key.as_str()));

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let a_conversations = get_user_conversations(State(db.clone()), CurrentUser(user_a))
            .await
            .expect("fetching A's conversations failed")
            .0;
        let view = a_conversations
            .iter()
            .find(|c| c.id == conversation_id)
            .expect("A should see the conversation with B");
        assert_eq!(
            view.participant_public_key.as_deref(),
            Some(fake_public_key.as_str()),
            "B's uploaded public key should be visible to A as the conversation's participant_public_key"
        );

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    /// A public key that doesn't decode to exactly 32 bytes is rejected.
    #[tokio::test]
    async fn public_key_upload_rejects_wrong_length() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;

        let too_short = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [1u8; 16]);
        let result = crate::routes::users::update_public_key(
            State(db.clone()),
            CurrentUser(user_a),
            Json(crate::routes::users::UpdatePublicKeyRequest { public_key: too_short }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for a too-short public key, got {other:?}"),
        }

        cleanup_test_user(&db, user_a).await;
    }

    fn fake_public_key(byte: u8) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [byte; 32])
    }

    async fn register_device(db: &Database, user_id: Uuid, byte: u8, label: &str) -> Uuid {
        crate::routes::devices::register_device(
            State(db.clone()),
            CurrentUser(user_id),
            Json(crate::routes::devices::RegisterDeviceRequest {
                public_key: fake_public_key(byte),
                device_label: label.into(),
            }),
        )
        .await
        .expect("registering a device should succeed")
        .0
        .id
    }

    /// The core new-model flow: A sends a fan-out message addressed to
    /// every registered device of both participants -- B's device, A's
    /// OTHER device, AND A's own sending device (no special-casing --
    /// see `encryptAndSend` in `DMChatArea.svelte`). Each device fetching
    /// history gets back only its own ciphertext.
    #[tokio::test]
    async fn fanout_message_round_trips_per_device_ciphertext() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let a_device1 = register_device(&db, user_a, 1, "A's Laptop").await;
        let a_device2 = register_device(&db, user_a, 2, "A's Phone").await;
        let b_device1 = register_device(&db, user_b, 3, "B's Laptop").await;

        let sent = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: None,
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                is_encrypted: false,
                nonce: None,
                encrypted_for: Some(vec![
                    EncryptedRecipient { device_id: a_device1, ciphertext: "ct-for-a1".into(), nonce: "nonce-a1".into(), ..Default::default() },
                    EncryptedRecipient { device_id: a_device2, ciphertext: "ct-for-a2".into(), nonce: "nonce-a2".into(), ..Default::default() },
                    EncryptedRecipient { device_id: b_device1, ciphertext: "ct-for-b1".into(), nonce: "nonce-b1".into(), ..Default::default() },
                ]),
                sender_device_id: Some(a_device1),
            }),
        )
        .await
        .expect("sending fan-out message failed")
        .0;

        assert!(sent.is_encrypted);
        assert!(sent.content.is_none(), "a fan-out message's shared content column must stay NULL");
        // The response (and broadcast payload it's reused for) carries every
        // recipient's entry, including the sender's own sending device.
        assert_eq!(sent.recipients.len(), 3);

        // A's device 2 fetching history sees only its own ciphertext.
        let a2_messages = get_conversation_messages(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Query(HistoryQuery { before: None, limit: None, device_id: Some(a_device2) }),
        )
        .await
        .expect("fetching as A's device 2 failed")
        .0;
        let found = a2_messages.iter().find(|m| m.id == sent.id).expect("message should appear");
        assert_eq!(found.recipients.len(), 1);
        assert_eq!(found.recipients[0].ciphertext, "ct-for-a2");
        assert_eq!(found.recipients[0].nonce, "nonce-a2");
        assert_eq!(found.recipients[0].sender_public_key, fake_public_key(1), "sender_public_key must be A's SENDING device's key");

        // B's device 1 fetching history sees only its own ciphertext.
        let b1_messages = get_conversation_messages(
            State(db.clone()),
            CurrentSession { user_id: user_b, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Query(HistoryQuery { before: None, limit: None, device_id: Some(b_device1) }),
        )
        .await
        .expect("fetching as B's device 1 failed")
        .0;
        let found = b1_messages.iter().find(|m| m.id == sent.id).expect("message should appear");
        assert_eq!(found.recipients.len(), 1);
        assert_eq!(found.recipients[0].ciphertext, "ct-for-b1");

        // A's SENDING device (device 1) gets its own ciphertext back too --
        // no special-casing of "my own device" (see `encryptAndSend`). This
        // is what lets it decrypt its own sent message the exact same way
        // any other device would, instead of needing a local plaintext
        // echo (which is what caused the self-echo race this replaced).
        let a1_messages = get_conversation_messages(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Query(HistoryQuery { before: None, limit: None, device_id: Some(a_device1) }),
        )
        .await
        .expect("fetching as A's device 1 failed")
        .0;
        let found = a1_messages.iter().find(|m| m.id == sent.id).expect("message should appear");
        assert_eq!(found.recipients.len(), 1);
        assert_eq!(found.recipients[0].ciphertext, "ct-for-a1");
        assert!(found.content.is_none(), "still must not fall back to showing anything in the legacy content column");

        // Omitting device_id entirely must behave the same as an
        // unrecognized device id: no ciphertext handed out.
        let no_device_messages = get_conversation_messages(
            State(db.clone()),
            CurrentSession { user_id: user_b, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Query(HistoryQuery { before: None, limit: None, device_id: None }),
        )
        .await
        .expect("fetching without a device_id failed")
        .0;
        let found = no_device_messages.iter().find(|m| m.id == sent.id).expect("message should appear");
        assert!(found.recipients.is_empty(), "no device_id supplied must never leak any device's ciphertext");

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    /// A participant can't read another participant's per-device
    /// ciphertext by passing that OTHER user's device_id as the `?device_id=`
    /// query filter. Even though A and B are both legitimate participants
    /// in the conversation (so `require_participant` passes for both), A's
    /// device_id is not B's, so A supplying B's device_id must be treated
    /// exactly like supplying no device_id at all -- no ciphertext handed
    /// back, not B's row.
    #[tokio::test]
    async fn get_conversation_messages_rejects_unowned_device_id() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let a_device1 = register_device(&db, user_a, 1, "A's Laptop").await;
        let b_device1 = register_device(&db, user_b, 3, "B's Laptop").await;

        let sent = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: None,
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                is_encrypted: false,
                nonce: None,
                encrypted_for: Some(vec![
                    EncryptedRecipient { device_id: a_device1, ciphertext: "ct-for-a1".into(), nonce: "nonce-a1".into(), ..Default::default() },
                    EncryptedRecipient { device_id: b_device1, ciphertext: "ct-for-b1".into(), nonce: "nonce-b1".into(), ..Default::default() },
                ]),
                sender_device_id: Some(a_device1),
            }),
        )
        .await
        .expect("sending fan-out message failed")
        .0;

        // A is a legitimate participant, so `require_participant` passes.
        // But A passes B's device_id -- NOT one of A's own registered
        // devices -- as the filter. This must not leak B's ciphertext.
        let messages = get_conversation_messages(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Query(HistoryQuery { before: None, limit: None, device_id: Some(b_device1) }),
        )
        .await
        .expect("fetching as A with B's device_id failed")
        .0;
        let found = messages.iter().find(|m| m.id == sent.id).expect("message should appear");
        assert!(
            found.recipients.is_empty(),
            "A must not receive B's per-device ciphertext by passing B's device_id as the filter"
        );

        // Confirm B's own device, fetching for itself, still gets its
        // ciphertext -- i.e. the fix rejects cross-user use of a device_id,
        // not the device_id itself.
        let b_messages = get_conversation_messages(
            State(db.clone()),
            CurrentSession { user_id: user_b, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Query(HistoryQuery { before: None, limit: None, device_id: Some(b_device1) }),
        )
        .await
        .expect("fetching as B's device 1 failed")
        .0;
        let found = b_messages.iter().find(|m| m.id == sent.id).expect("message should appear");
        assert_eq!(found.recipients.len(), 1, "B fetching with B's own device_id must still see B's ciphertext");
        assert_eq!(found.recipients[0].ciphertext, "ct-for-b1");

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    /// A send is rejected outright (nothing partially inserted) if any
    /// device_id in `encrypted_for` doesn't belong to one of the two real
    /// participants in the conversation -- e.g. a stale/forged device id,
    /// or a device belonging to some unrelated third user.
    #[tokio::test]
    async fn fanout_rejects_device_not_belonging_to_a_participant() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;
        let outsider = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let a_device1 = register_device(&db, user_a, 10, "A's Laptop").await;
        let outsider_device = register_device(&db, outsider, 11, "Outsider's Phone").await;

        let result = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: None,
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                is_encrypted: false,
                nonce: None,
                encrypted_for: Some(vec![EncryptedRecipient {
                    device_id: outsider_device,
                    ciphertext: "ct".into(),
                    nonce: "nonce".into(),
                    ..Default::default()
                }]),
                sender_device_id: Some(a_device1),
            }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for a device_id outside the conversation, got {other:?}"),
        }

        // Nothing should have been inserted -- the whole send is atomic.
        let message_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE conversation_id = $1")
            .bind(conversation_id)
            .fetch_one(&db.pool)
            .await
            .expect("count query failed");
        assert_eq!(message_count, 0, "a rejected fan-out send must not leave a partial message row behind");

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_user(&db, outsider).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    /// `sender_device_id` must be one of the caller's OWN devices -- it
    /// can't be used to forge messages as if sent from someone else's
    /// device.
    #[tokio::test]
    async fn fanout_rejects_sender_device_not_owned_by_caller() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let b_device1 = register_device(&db, user_b, 20, "B's Laptop").await;

        let result = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: None,
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                is_encrypted: false,
                nonce: None,
                encrypted_for: Some(vec![EncryptedRecipient {
                    device_id: b_device1,
                    ciphertext: "ct".into(),
                    nonce: "nonce".into(),
                    ..Default::default()
                }]),
                // B's device, not A's -- A must not be able to claim it.
                sender_device_id: Some(b_device1),
            }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest when sender_device_id isn't the caller's own device, got {other:?}"),
        }

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    /// `get_participant_devices` returns every device of both participants,
    /// correctly tagging which ones belong to the caller.
    #[tokio::test]
    async fn participant_devices_lists_both_sides_with_is_me() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let a_device1 = register_device(&db, user_a, 30, "A's Laptop").await;
        let b_device1 = register_device(&db, user_b, 31, "B's Laptop").await;

        let devices = get_participant_devices(State(db.clone()), CurrentUser(user_a), Path(conversation_id))
            .await
            .expect("fetching participant devices failed")
            .0;

        assert_eq!(devices.len(), 2);
        let mine = devices.iter().find(|d| d.device_id == a_device1).expect("A's own device should be listed");
        assert!(mine.is_me);
        let theirs = devices.iter().find(|d| d.device_id == b_device1).expect("B's device should be listed");
        assert!(!theirs.is_me);

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    /// A per-recipient ciphertext longer than `MAX_FANOUT_CIPHERTEXT_B64_CHARS`
    /// is rejected, and nothing is inserted.
    #[tokio::test]
    async fn fanout_rejects_oversized_ciphertext() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let a_device1 = register_device(&db, user_a, 40, "A's Laptop").await;
        let b_device1 = register_device(&db, user_b, 41, "B's Laptop").await;

        let oversized_ciphertext = "a".repeat(MAX_FANOUT_CIPHERTEXT_B64_CHARS + 1);
        let result = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: None,
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                is_encrypted: false,
                nonce: None,
                encrypted_for: Some(vec![EncryptedRecipient {
                    device_id: b_device1,
                    ciphertext: oversized_ciphertext,
                    nonce: "nonce-b1".into(),
                    ..Default::default()
                }]),
                sender_device_id: Some(a_device1),
            }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for an oversized ciphertext, got {other:?}"),
        }

        let message_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE conversation_id = $1")
            .bind(conversation_id)
            .fetch_one(&db.pool)
            .await
            .expect("count query failed");
        assert_eq!(message_count, 0, "a rejected fan-out send must not leave a partial message row behind");

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    /// A per-recipient nonce longer than `MAX_FANOUT_NONCE_B64_CHARS` is
    /// rejected, and nothing is inserted.
    #[tokio::test]
    async fn fanout_rejects_oversized_nonce() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let a_device1 = register_device(&db, user_a, 42, "A's Laptop").await;
        let b_device1 = register_device(&db, user_b, 43, "B's Laptop").await;

        let oversized_nonce = "a".repeat(MAX_FANOUT_NONCE_B64_CHARS + 1);
        let result = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: None,
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                is_encrypted: false,
                nonce: None,
                encrypted_for: Some(vec![EncryptedRecipient {
                    device_id: b_device1,
                    ciphertext: "ct-for-b1".into(),
                    nonce: oversized_nonce,
                    ..Default::default()
                }]),
                sender_device_id: Some(a_device1),
            }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for an oversized nonce, got {other:?}"),
        }

        let message_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE conversation_id = $1")
            .bind(conversation_id)
            .fetch_one(&db.pool)
            .await
            .expect("count query failed");
        assert_eq!(message_count, 0, "a rejected fan-out send must not leave a partial message row behind");

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    /// A fan-out message with an encrypted attachment: every recipient
    /// device gets its own wrapped copy of the attachment key, the shared
    /// blob's nonce lives on the message itself, and fetching history later
    /// returns both back to each device.
    #[tokio::test]
    async fn fanout_attachment_round_trips_per_device_key_and_nonce() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let a_device1 = register_device(&db, user_a, 60, "A's Laptop").await;
        let b_device1 = register_device(&db, user_b, 61, "B's Laptop").await;

        let sent = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: None,
                attachment_url: Some("/uploads/abc.png".into()),
                attachment_filename: Some("photo.png".into()),
                attachment_size: Some(1234),
                attachment_mime_type: Some("image/png".into()),
                attachment_nonce: Some("file-nonce".into()),
                is_encrypted: false,
                nonce: None,
                encrypted_for: Some(vec![
                    EncryptedRecipient {
                        device_id: a_device1,
                        ciphertext: "ct-for-a1".into(),
                        nonce: "nonce-a1".into(),
                        attachment_key_ciphertext: Some("wrapped-key-a1".into()),
                        attachment_key_nonce: Some("wrap-nonce-a1".into()),
                    },
                    EncryptedRecipient {
                        device_id: b_device1,
                        ciphertext: "ct-for-b1".into(),
                        nonce: "nonce-b1".into(),
                        attachment_key_ciphertext: Some("wrapped-key-b1".into()),
                        attachment_key_nonce: Some("wrap-nonce-b1".into()),
                    },
                ]),
                sender_device_id: Some(a_device1),
            }),
        )
        .await
        .expect("sending fan-out message with attachment failed")
        .0;

        assert_eq!(sent.attachment_nonce.as_deref(), Some("file-nonce"));

        let b1_messages = get_conversation_messages(
            State(db.clone()),
            CurrentSession { user_id: user_b, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Query(HistoryQuery { before: None, limit: None, device_id: Some(b_device1) }),
        )
        .await
        .expect("fetching as B's device 1 failed")
        .0;
        let found = b1_messages.iter().find(|m| m.id == sent.id).expect("message should appear");
        assert_eq!(found.attachment_nonce.as_deref(), Some("file-nonce"));
        assert_eq!(found.recipients.len(), 1);
        assert_eq!(found.recipients[0].attachment_key_ciphertext.as_deref(), Some("wrapped-key-b1"));
        assert_eq!(found.recipients[0].attachment_key_nonce.as_deref(), Some("wrap-nonce-b1"));

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    /// `attachment_url` set without `attachment_nonce` is rejected -- an
    /// encrypted attachment blob is never stored without the nonce needed
    /// to decrypt it.
    #[tokio::test]
    async fn fanout_rejects_attachment_without_nonce() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let a_device1 = register_device(&db, user_a, 62, "A's Laptop").await;
        let b_device1 = register_device(&db, user_b, 63, "B's Laptop").await;

        let result = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: None,
                attachment_url: Some("/uploads/abc.png".into()),
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                is_encrypted: false,
                nonce: None,
                encrypted_for: Some(vec![
                    EncryptedRecipient { device_id: a_device1, ciphertext: "ct-for-a1".into(), nonce: "nonce-a1".into(), ..Default::default() },
                    EncryptedRecipient { device_id: b_device1, ciphertext: "ct-for-b1".into(), nonce: "nonce-b1".into(), ..Default::default() },
                ]),
                sender_device_id: Some(a_device1),
            }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for an attachment with no nonce, got {other:?}"),
        }

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    /// `attachment_nonce` set without `attachment_url` is rejected -- there
    /// is nothing for that nonce to decrypt.
    #[tokio::test]
    async fn fanout_rejects_attachment_nonce_without_url() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let a_device1 = register_device(&db, user_a, 64, "A's Laptop").await;
        let b_device1 = register_device(&db, user_b, 65, "B's Laptop").await;

        let result = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: None,
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: Some("file-nonce".into()),
                is_encrypted: false,
                nonce: None,
                encrypted_for: Some(vec![
                    EncryptedRecipient { device_id: a_device1, ciphertext: "ct-for-a1".into(), nonce: "nonce-a1".into(), ..Default::default() },
                    EncryptedRecipient { device_id: b_device1, ciphertext: "ct-for-b1".into(), nonce: "nonce-b1".into(), ..Default::default() },
                ]),
                sender_device_id: Some(a_device1),
            }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for attachment_nonce with no attachment_url, got {other:?}"),
        }

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    /// Every recipient must carry a wrapped attachment key when there's an
    /// attachment -- skipping even one would leave that device permanently
    /// unable to read it, the same invariant as the message ciphertext
    /// itself.
    #[tokio::test]
    async fn fanout_rejects_missing_attachment_key_for_a_recipient() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let a_device1 = register_device(&db, user_a, 66, "A's Laptop").await;
        let b_device1 = register_device(&db, user_b, 67, "B's Laptop").await;

        let result = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: None,
                attachment_url: Some("/uploads/abc.png".into()),
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: Some("file-nonce".into()),
                is_encrypted: false,
                nonce: None,
                encrypted_for: Some(vec![
                    EncryptedRecipient {
                        device_id: a_device1,
                        ciphertext: "ct-for-a1".into(),
                        nonce: "nonce-a1".into(),
                        attachment_key_ciphertext: Some("wrapped-key-a1".into()),
                        attachment_key_nonce: Some("wrap-nonce-a1".into()),
                    },
                    // B's device carries no wrapped key at all.
                    EncryptedRecipient { device_id: b_device1, ciphertext: "ct-for-b1".into(), nonce: "nonce-b1".into(), ..Default::default() },
                ]),
                sender_device_id: Some(a_device1),
            }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for a recipient missing its attachment key, got {other:?}"),
        }

        let message_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE conversation_id = $1")
            .bind(conversation_id)
            .fetch_one(&db.pool)
            .await
            .expect("count query failed");
        assert_eq!(message_count, 0, "a rejected fan-out send must not leave a partial message row behind");

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    /// A recipient carrying a wrapped attachment key when there's no
    /// attachment at all is rejected as a mismatched/buggy payload, rather
    /// than silently stored and ignored.
    #[tokio::test]
    async fn fanout_rejects_attachment_key_without_attachment() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let a_device1 = register_device(&db, user_a, 68, "A's Laptop").await;
        let b_device1 = register_device(&db, user_b, 69, "B's Laptop").await;

        let result = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: None,
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                is_encrypted: false,
                nonce: None,
                encrypted_for: Some(vec![
                    EncryptedRecipient { device_id: a_device1, ciphertext: "ct-for-a1".into(), nonce: "nonce-a1".into(), ..Default::default() },
                    EncryptedRecipient {
                        device_id: b_device1,
                        ciphertext: "ct-for-b1".into(),
                        nonce: "nonce-b1".into(),
                        attachment_key_ciphertext: Some("wrapped-key-b1".into()),
                        attachment_key_nonce: Some("wrap-nonce-b1".into()),
                    },
                ]),
                sender_device_id: Some(a_device1),
            }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for an attachment key with no attachment, got {other:?}"),
        }

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    /// The legacy single-device send path never supports encrypted
    /// attachments (there's no per-device fan-out there to carry a wrapped
    /// key) -- `attachment_nonce` on that path is rejected outright rather
    /// than silently stored with no way to ever decrypt the blob.
    #[tokio::test]
    async fn legacy_send_rejects_attachment_nonce() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let result = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: Some("hi".into()),
                attachment_url: Some("/uploads/abc.png".into()),
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: Some("file-nonce".into()),
                is_encrypted: false,
                nonce: None,
                encrypted_for: None,
                sender_device_id: None,
            }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for attachment_nonce on the legacy send path, got {other:?}"),
        }

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    /// If `encrypted_for` omits one of the OTHER participant's registered
    /// devices, the whole send is rejected -- a buggy/malicious client must
    /// not be able to "send" a message that silently never reaches the
    /// other participant.
    #[tokio::test]
    async fn fanout_rejects_missing_other_participant_device() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let a_device1 = register_device(&db, user_a, 50, "A's Laptop").await;
        let b_device1 = register_device(&db, user_b, 51, "B's Laptop").await;
        let b_device2 = register_device(&db, user_b, 52, "B's Phone").await;

        // Addresses A's own sending device and B's first device, but omits
        // B's second -- B's phone would never receive this message, with
        // no error anywhere, if the server didn't catch it.
        let result = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: None,
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                is_encrypted: false,
                nonce: None,
                encrypted_for: Some(vec![
                    EncryptedRecipient { device_id: a_device1, ciphertext: "ct-for-a1".into(), nonce: "nonce-a1".into(), ..Default::default() },
                    EncryptedRecipient { device_id: b_device1, ciphertext: "ct-for-b1".into(), nonce: "nonce-b1".into(), ..Default::default() },
                ]),
                sender_device_id: Some(a_device1),
            }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest when a participant's device is missing from encrypted_for, got {other:?}"),
        }

        let message_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE conversation_id = $1")
            .bind(conversation_id)
            .fetch_one(&db.pool)
            .await
            .expect("count query failed");
        assert_eq!(message_count, 0, "a rejected fan-out send must not leave a partial message row behind");

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        let _ = b_device2;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    /// If `encrypted_for` omits one of the SENDER's own other registered
    /// devices, the whole send is rejected too -- not just the other
    /// participant's devices are covered by the completeness check.
    #[tokio::test]
    async fn fanout_rejects_missing_senders_own_other_device() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let a_device1 = register_device(&db, user_a, 53, "A's Laptop").await;
        let a_device2 = register_device(&db, user_a, 54, "A's Phone").await;
        let b_device1 = register_device(&db, user_b, 55, "B's Laptop").await;

        // Addresses A's own sending device and B's device, but omits A's
        // OTHER device -- A's phone would never receive this message
        // either.
        let result = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: None,
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                is_encrypted: false,
                nonce: None,
                encrypted_for: Some(vec![
                    EncryptedRecipient { device_id: a_device1, ciphertext: "ct-for-a1".into(), nonce: "nonce-a1".into(), ..Default::default() },
                    EncryptedRecipient { device_id: b_device1, ciphertext: "ct-for-b1".into(), nonce: "nonce-b1".into(), ..Default::default() },
                ]),
                sender_device_id: Some(a_device1),
            }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest when the sender's own other device is missing from encrypted_for, got {other:?}"),
        }

        let message_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE conversation_id = $1")
            .bind(conversation_id)
            .fetch_one(&db.pool)
            .await
            .expect("count query failed");
        assert_eq!(message_count, 0, "a rejected fan-out send must not leave a partial message row behind");

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        let _ = a_device2;
        cleanup_test_conversation(&db, conversation_id).await;
    }

    /// If `encrypted_for` omits the SENDER's own SENDING device, the whole
    /// send is rejected too. This is the one real client code never
    /// actually omits (`encryptAndSend` in `DMChatArea.svelte` always
    /// includes it, with no special-casing -- that's what fixed the
    /// self-echo race), but the server must still catch it rather than
    /// silently storing a message the sending device itself could never
    /// decrypt back. This also guards against ever reintroducing the
    /// opposite bug: requiring this entry to be ABSENT, which would reject
    /// every send the real client makes.
    #[tokio::test]
    async fn fanout_rejects_missing_senders_own_sending_device() {
        let db = test_db().await;
        let user_a = create_test_user(&db).await;
        let user_b = create_test_user(&db).await;

        let conversation_id = create_or_get_conversation(
            State(db.clone()),
            CurrentUser(user_a),
            Json(CreateConversationRequest { participant_id: user_b }),
        )
        .await
        .expect("setup: creating conversation failed")
        .0
        .id;

        let a_device1 = register_device(&db, user_a, 56, "A's Laptop").await;
        let b_device1 = register_device(&db, user_b, 57, "B's Laptop").await;

        // Addresses B's device but omits A's own sending device entirely --
        // the one entry the real client never actually omits.
        let result = send_conversation_message(
            State(db.clone()),
            CurrentSession { user_id: user_a, session_id: Uuid::new_v4() },
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: None,
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
                attachment_nonce: None,
                is_encrypted: false,
                nonce: None,
                encrypted_for: Some(vec![EncryptedRecipient {
                    device_id: b_device1,
                    ciphertext: "ct-for-b1".into(),
                    nonce: "nonce-b1".into(),
                    ..Default::default()
                }]),
                sender_device_id: Some(a_device1),
            }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest when the sender's own sending device is missing from encrypted_for, got {other:?}"),
        }

        let message_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE conversation_id = $1")
            .bind(conversation_id)
            .fetch_one(&db.pool)
            .await
            .expect("count query failed");
        assert_eq!(message_count, 0, "a rejected fan-out send must not leave a partial message row behind");

        cleanup_test_user(&db, user_a).await;
        cleanup_test_user(&db, user_b).await;
        cleanup_test_conversation(&db, conversation_id).await;
    }
}

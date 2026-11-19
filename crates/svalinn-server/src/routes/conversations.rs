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
            CurrentUser(user_c),
            Path(conversation_id),
            Query(HistoryQuery { before: None, limit: None }),
        )
        .await;
        match read_result {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected AppError::Forbidden reading messages as a non-participant, got {other:?}"),
        }

        let send_result = send_conversation_message(
            State(db.clone()),
            CurrentUser(user_c),
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: "hello from an outsider".into(),
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
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
            CurrentUser(user_a),
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: "hello from A".into(),
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
            }),
        )
        .await
        .expect("sending message failed")
        .0;

        assert_eq!(sent.content, "hello from A");
        assert_eq!(sent.user_id, user_a);

        let messages = get_conversation_messages(
            State(db.clone()),
            CurrentUser(user_b),
            Path(conversation_id),
            Query(HistoryQuery { before: None, limit: None }),
        )
        .await
        .expect("fetching messages failed")
        .0;

        let found = messages.iter().find(|m| m.id == sent.id);
        let found = found.expect("the message sent by A should appear in B's view of the conversation");
        assert_eq!(found.content, "hello from A");
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
            CurrentUser(user_a),
            Path(conversation_id),
            Json(SendDirectMessageRequest {
                content: "ping".into(),
                attachment_url: None,
                attachment_filename: None,
                attachment_size: None,
                attachment_mime_type: None,
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
            CurrentUser(user_b),
            Path(conversation_id),
            Query(HistoryQuery { before: None, limit: None }),
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
}

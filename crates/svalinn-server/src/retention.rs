//! Server-wide message retention sweep.
//!
//! Keeps at most [`MESSAGE_CAP_PER_SERVER`] non-pinned messages per server
//! (summed across all of that server's channels, not per channel), but
//! never deletes a message that's still unread by some *current* member
//! until either it turns [`UNREAD_GRACE_DAYS`] days old or the server's
//! total unread-exempt backlog grows past [`MAX_UNREAD_BACKLOG_PER_SERVER`]
//! -- whichever happens first. That second limit exists so one member who
//! never opens the app again can't hold a server's entire backlog hostage
//! forever; without it, "exempt while unread" would have no upper bound at
//! all.
//!
//! Pinned messages are entirely outside this sweep -- they're capped
//! separately, at [`PIN_CAP_PER_SERVER`] per server, enforced at pin time
//! in `routes::messages::set_pinned` rather than cleaned up after the fact.
//! Unpinning an old one has its own immediate-loss rule; see
//! `routes::messages::unpin_message`.
//!
//! DMs are untouched: a message only becomes a candidate here if its
//! channel has a `server_id` at all, which conversation-based DM messages
//! never do. This is a *per-server* cap, and a DM doesn't belong to one.

use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use uuid::Uuid;

use crate::db::Database;
use crate::routes::messages::delete_message_now;

/// Non-pinned messages kept per server before older ones become deletion
/// candidates, subject to the unread exemption below.
pub const MESSAGE_CAP_PER_SERVER: i64 = 500;

/// How many days a message that's still unread by some current member is
/// kept past the cap regardless of how far past it the server already is.
/// It stops being exempt the moment it turns this old, read or not.
pub const UNREAD_GRACE_DAYS: i64 = 30;

/// Hard ceiling on the unread-exemption backlog itself, independent of age
/// -- 2.5x the normal cap. Once a server's "kept only because someone
/// hasn't read it yet" backlog passes this, the oldest of those messages
/// are swept regardless of the 30-day grace period.
pub const MAX_UNREAD_BACKLOG_PER_SERVER: i64 = MESSAGE_CAP_PER_SERVER * 5 / 2;

/// Pinned messages allowed per server. Enforced at pin time (see
/// `routes::messages::set_pinned`) rather than here -- the sweep never
/// touches a pinned message at all.
pub const PIN_CAP_PER_SERVER: i64 = 200;

/// Unpinning a message at least this old deletes it immediately instead of
/// just letting it fall back under the ordinary cap -- see
/// `routes::messages::unpin_message`. Same threshold as the unread grace
/// period: a message this old is already past what the cap would otherwise
/// have protected it from.
pub const UNPIN_IMMEDIATE_LOSS_DAYS: i64 = UNREAD_GRACE_DAYS;

const SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Starts the periodic retention sweep. Fire-and-forget, same pattern as
/// `sessions::spawn_watchers` and `stats::spawn_snapshot_job`: a failure
/// here should never take the server down, it just means cleanup is late.
pub fn spawn_sweeper(db: Database) {
    tokio::spawn(run(db));
}

async fn run(db: Database) {
    let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        ticker.tick().await;
        if let Err(e) = sweep_once(&db).await {
            eprintln!("⚠️  Message retention sweep failed: {e}");
        }
    }
}

struct Candidate {
    id: Uuid,
    channel_id: Uuid,
    server_id: Uuid,
    created_at: chrono::DateTime<Utc>,
}

/// Runs one retention pass across every server and returns how many
/// messages it deleted. Exposed (not just the spawned loop) so tests and
/// an eventual admin "run cleanup now" endpoint can call it directly.
pub async fn sweep_once(db: &Database) -> Result<usize, sqlx::Error> {
    // Every non-pinned channel message that falls outside its server's most
    // recent `MESSAGE_CAP_PER_SERVER` (summed across all of that server's
    // channels, matching the per-server cap this is meant to enforce), plus
    // -- for each one -- whether any *current* member of that server still
    // hasn't read up to it. `cr.id IS NULL` (no read-marker row at all) and
    // `lm.created_at IS NULL` (the read-marker pointed at a message that's
    // since been deleted, so the FK already nulled it out) both count as
    // "hasn't read it", which is the conservative direction to round in --
    // it only ever delays a deletion, never causes a wrongful one.
    let rows: Vec<(Uuid, Uuid, Uuid, chrono::DateTime<Utc>, bool)> = sqlx::query_as(
        r#"
        WITH ranked AS (
            SELECT m.id, m.channel_id, c.server_id, m.created_at,
                   ROW_NUMBER() OVER (
                       PARTITION BY c.server_id ORDER BY m.created_at DESC, m.id DESC
                   ) AS rn
            FROM messages m
            JOIN channels c ON c.id = m.channel_id
            WHERE c.server_id IS NOT NULL AND COALESCE(m.is_pinned, false) = false
        ),
        candidates AS (
            SELECT id, channel_id, server_id, created_at FROM ranked WHERE rn > $1
        )
        SELECT
            cand.id,
            cand.channel_id,
            cand.server_id,
            cand.created_at,
            EXISTS (
                SELECT 1
                FROM server_members sme
                LEFT JOIN channel_reads cr ON cr.user_id = sme.user_id AND cr.channel_id = cand.channel_id
                LEFT JOIN messages lm ON lm.id = cr.last_read_message_id
                WHERE sme.server_id = cand.server_id
                  AND (cr.id IS NULL OR lm.created_at IS NULL OR lm.created_at < cand.created_at)
            ) AS unread_by_someone
        FROM candidates cand
        "#,
    )
    .bind(MESSAGE_CAP_PER_SERVER)
    .fetch_all(&db.pool)
    .await?;

    let now = Utc::now();
    let grace = chrono::Duration::days(UNREAD_GRACE_DAYS);

    let mut to_delete: Vec<Candidate> = Vec::new();
    let mut backlog_by_server: HashMap<Uuid, Vec<Candidate>> = HashMap::new();

    for (id, channel_id, server_id, created_at, unread_by_someone) in rows {
        let candidate = Candidate { id, channel_id, server_id, created_at };
        if !unread_by_someone || now - candidate.created_at >= grace {
            to_delete.push(candidate);
        } else {
            backlog_by_server.entry(server_id).or_default().push(candidate);
        }
    }

    // Trim any server's unread-exemption backlog down to the hard ceiling,
    // oldest first -- the newest unread messages are the ones most likely
    // to still be read soon, so they're the ones worth protecting longest.
    for (_server_id, mut backlog) in backlog_by_server {
        if backlog.len() as i64 > MAX_UNREAD_BACKLOG_PER_SERVER {
            backlog.sort_by_key(|c| c.created_at);
            let overflow = backlog.len() - MAX_UNREAD_BACKLOG_PER_SERVER as usize;
            to_delete.extend(backlog.drain(0..overflow));
        }
    }

    let deleted = to_delete.len();
    for candidate in to_delete {
        // Best-effort: a candidate that's vanished since the SELECT above
        // (deleted by a user in the meantime, say) is fine to skip.
        let _ = delete_message_now(db, candidate.id, candidate.server_id, candidate.channel_id).await;
    }

    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    async fn message_count(db: &Database, channel_id: Uuid) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE channel_id = $1")
            .bind(channel_id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to count messages")
    }

    /// Marks `user_id` as caught up on `channel_id` through its very latest
    /// message, so none of that channel's messages are "unread" for them.
    async fn mark_fully_read(db: &Database, user_id: Uuid, channel_id: Uuid) {
        sqlx::query(
            r#"
            INSERT INTO channel_reads (user_id, channel_id, last_read_message_id, last_read_at)
            VALUES ($1, $2, (SELECT id FROM messages WHERE channel_id = $2 ORDER BY created_at DESC LIMIT 1), NOW())
            ON CONFLICT (user_id, channel_id)
            DO UPDATE SET last_read_message_id = EXCLUDED.last_read_message_id, last_read_at = NOW()
            "#,
        )
        .bind(user_id)
        .bind(channel_id)
        .execute(&db.pool)
        .await
        .expect("failed to mark channel fully read");
    }

    /// Inserts `count` plain messages into `channel_id`, one minute apart,
    /// the newest landing exactly at `newest_at`. Deliberately raw SQL
    /// rather than going through `create_message` -- these tests need
    /// precise, backdated `created_at` values that a real send can't
    /// produce.
    async fn insert_messages_ending(db: &Database, channel_id: Uuid, user_id: Uuid, count: i64, newest_at: chrono::DateTime<Utc>) {
        sqlx::query(
            r#"
            INSERT INTO messages (channel_id, user_id, content, created_at)
            SELECT $1, $2, 'msg ' || i, $3::timestamptz - (($4 - i) * interval '1 minute')
            FROM generate_series(1, $4) AS i
            "#,
        )
        .bind(channel_id)
        .bind(user_id)
        .bind(newest_at)
        .bind(count)
        .execute(&db.pool)
        .await
        .expect("failed to bulk insert test messages");
    }

    #[tokio::test]
    async fn sweep_trims_a_fully_read_channel_down_to_the_cap() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;

        insert_messages_ending(&db, channel, owner, MESSAGE_CAP_PER_SERVER + 50, Utc::now()).await;
        mark_fully_read(&db, owner, channel).await;

        sweep_once(&db).await.expect("sweep should succeed");

        assert_eq!(
            message_count(&db, channel).await,
            MESSAGE_CAP_PER_SERVER,
            "a channel nobody has unread messages in should be trimmed to exactly the cap"
        );

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    #[tokio::test]
    async fn sweep_exempts_recent_messages_a_current_member_has_not_read() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let reader = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        add_server_member(&db, server, reader).await;

        // `reader` never opens the channel at all -- no `channel_reads` row
        // -- so every message in it is unread for them from the start.
        insert_messages_ending(&db, channel, owner, MESSAGE_CAP_PER_SERVER + 50, Utc::now()).await;

        sweep_once(&db).await.expect("sweep should succeed");

        assert_eq!(
            message_count(&db, channel).await,
            MESSAGE_CAP_PER_SERVER + 50,
            "messages a current member hasn't read yet, and that are still well inside the grace period, must not be deleted"
        );

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, reader).await;
    }

    #[tokio::test]
    async fn sweep_wipes_unread_messages_once_they_pass_the_grace_period() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let reader = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        add_server_member(&db, server, reader).await;

        // Same "reader never caught up" setup as above, but every message
        // -- including the newest -- is already older than the grace
        // period, so the exemption no longer applies to any of them.
        let newest_at = Utc::now() - chrono::Duration::days(UNREAD_GRACE_DAYS + 1);
        insert_messages_ending(&db, channel, owner, MESSAGE_CAP_PER_SERVER + 50, newest_at).await;

        sweep_once(&db).await.expect("sweep should succeed");

        assert_eq!(
            message_count(&db, channel).await,
            MESSAGE_CAP_PER_SERVER,
            "an unread message past the grace period loses its exemption and is swept like any other"
        );

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, reader).await;
    }

    #[tokio::test]
    async fn sweep_caps_the_unread_backlog_at_two_and_a_half_times_the_cap() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let reader = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;
        add_server_member(&db, server, reader).await;

        // Every message is recent (well inside the 30-day grace period) and
        // unread by `reader`, so the only thing that can still trim this
        // channel is the hard backlog ceiling.
        let total = MESSAGE_CAP_PER_SERVER + MAX_UNREAD_BACKLOG_PER_SERVER + 250;
        insert_messages_ending(&db, channel, owner, total, Utc::now()).await;

        sweep_once(&db).await.expect("sweep should succeed");

        assert_eq!(
            message_count(&db, channel).await,
            MESSAGE_CAP_PER_SERVER + MAX_UNREAD_BACKLOG_PER_SERVER,
            "the unread-exemption backlog itself must never exceed 2.5x the cap, age and read state aside"
        );

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, reader).await;
    }

    #[tokio::test]
    async fn sweep_never_touches_a_pinned_message_regardless_of_age_or_read_state() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server = create_test_server(&db, owner).await;
        let channel = create_test_channel(&db, server).await;

        // Old, unread by nobody-in-particular (no other member exists to
        // even be "unread" for), and squarely beyond the cap -- the only
        // reason this should survive is `is_pinned`.
        insert_messages_ending(&db, channel, owner, MESSAGE_CAP_PER_SERVER + 10, Utc::now() - chrono::Duration::days(UNREAD_GRACE_DAYS + 5)).await;
        mark_fully_read(&db, owner, channel).await;

        let oldest_id: Uuid = sqlx::query_scalar("SELECT id FROM messages WHERE channel_id = $1 ORDER BY created_at ASC LIMIT 1")
            .bind(channel)
            .fetch_one(&db.pool)
            .await
            .expect("failed to find the oldest message");
        sqlx::query("UPDATE messages SET is_pinned = true WHERE id = $1")
            .bind(oldest_id)
            .execute(&db.pool)
            .await
            .expect("failed to pin the oldest message");

        sweep_once(&db).await.expect("sweep should succeed");

        let still_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM messages WHERE id = $1)")
            .bind(oldest_id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to check survival");
        assert!(still_exists, "a pinned message must never be deleted by the retention sweep");
        assert_eq!(
            message_count(&db, channel).await,
            MESSAGE_CAP_PER_SERVER + 1,
            "the pinned message survives on top of (not counted toward) the ordinary cap"
        );

        cleanup_test_server(&db, server).await;
        cleanup_test_user(&db, owner).await;
    }

    #[tokio::test]
    async fn sweep_leaves_dm_messages_alone() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let other = create_test_user(&db).await;

        let conversation_id: Uuid = sqlx::query_scalar("INSERT INTO conversations DEFAULT VALUES RETURNING id")
            .fetch_one(&db.pool)
            .await
            .expect("failed to create a test conversation");
        for user in [owner, other] {
            sqlx::query("INSERT INTO conversation_participants (conversation_id, user_id) VALUES ($1, $2)")
                .bind(conversation_id)
                .bind(user)
                .execute(&db.pool)
                .await
                .expect("failed to add a conversation participant");
        }

        let old_at = Utc::now() - chrono::Duration::days(UNREAD_GRACE_DAYS + 100);
        for _ in 0..5 {
            sqlx::query("INSERT INTO messages (conversation_id, user_id, content, created_at) VALUES ($1, $2, 'dm', $3)")
                .bind(conversation_id)
                .bind(owner)
                .bind(old_at)
                .execute(&db.pool)
                .await
                .expect("failed to insert a test DM message");
        }

        sweep_once(&db).await.expect("sweep should succeed");

        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE conversation_id = $1")
            .bind(conversation_id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to count DM messages");
        assert_eq!(remaining, 5, "DM messages have no server_id and must never be touched by the per-server sweep");

        let _ = sqlx::query("DELETE FROM conversations WHERE id = $1").bind(conversation_id).execute(&db.pool).await;
        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, other).await;
    }
}

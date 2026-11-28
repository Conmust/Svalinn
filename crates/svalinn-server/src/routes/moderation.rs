//! Read side of the moderation audit log (see `audit_log.rs` for the write
//! side and what each action means).

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::access::member_rank;
use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;

/// Same rank as `members::list_bans` and `invites::list_invites` -- the
/// audit log shows exactly the kind of thing moderators already see
/// elsewhere (who got banned, kicked, etc.), just gathered in one place.
const MODERATOR_RANK: u8 = 2;

const PAGE_SIZE: i64 = 50;
const MAX_PAGE_SIZE: i64 = 100;

#[derive(Serialize, sqlx::FromRow)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub action: String,
    pub actor_id: Option<Uuid>,
    /// `None` if the acting moderator's account has since been deleted.
    pub actor_username: Option<String>,
    pub target_user_id: Option<Uuid>,
    /// `None` either because this action had no target user, or because
    /// that account has since been deleted.
    pub target_username: Option<String>,
    pub target_channel_id: Option<Uuid>,
    pub target_channel_name: Option<String>,
    pub reason: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
pub struct AuditLogQuery {
    /// Load entries older than this one. Omit for the latest page.
    pub before: Option<Uuid>,
    pub limit: Option<i64>,
}

const AUDIT_LOG_COLUMNS: &str = r#"
    l.id, l.action, l.actor_id, actor.username AS actor_username,
    l.target_user_id, target.username AS target_username,
    l.target_channel_id, c.name AS target_channel_name,
    l.reason, l.metadata, l.created_at
"#;

/// GET /api/v1/servers/:server_id/audit-log?before=<entry_id>&limit=50
///
/// Returns a page of audit log entries, newest first. Fewer than `limit`
/// entries means there's no more history.
pub async fn get_audit_log(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<Vec<AuditLogEntry>>, AppError> {
    match member_rank(&db, server_id, user_id).await? {
        Some(rank) if rank >= MODERATOR_RANK => {}
        Some(_) => return Err(AppError::Forbidden("Only moderators and above can view the audit log".into())),
        None => return Err(AppError::Forbidden("You are not a member of this server".into())),
    }

    let limit = query.limit.unwrap_or(PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);

    let entries: Vec<AuditLogEntry> = if let Some(before) = query.before {
        let cursor: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT created_at FROM moderation_audit_log WHERE id = $1 AND server_id = $2")
                .bind(before)
                .bind(server_id)
                .fetch_optional(&db.pool)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        let cursor = cursor.ok_or_else(|| AppError::NotFound("Audit log entry not found in this server".into()))?;

        sqlx::query_as(&format!(
            r#"
            SELECT {AUDIT_LOG_COLUMNS}
            FROM moderation_audit_log l
            LEFT JOIN users actor ON actor.id = l.actor_id
            LEFT JOIN users target ON target.id = l.target_user_id
            LEFT JOIN channels c ON c.id = l.target_channel_id
            WHERE l.server_id = $1 AND (l.created_at, l.id) < ($2, $3)
            ORDER BY l.created_at DESC, l.id DESC
            LIMIT $4
            "#
        ))
        .bind(server_id)
        .bind(cursor)
        .bind(before)
        .bind(limit)
        .fetch_all(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
    } else {
        sqlx::query_as(&format!(
            r#"
            SELECT {AUDIT_LOG_COLUMNS}
            FROM moderation_audit_log l
            LEFT JOIN users actor ON actor.id = l.actor_id
            LEFT JOIN users target ON target.id = l.target_user_id
            LEFT JOIN channels c ON c.id = l.target_channel_id
            WHERE l.server_id = $1
            ORDER BY l.created_at DESC, l.id DESC
            LIMIT $2
            "#
        ))
        .bind(server_id)
        .bind(limit)
        .fetch_all(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
    };

    Ok(Json(entries))
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

    async fn create_test_server(db: &Database, owner: Uuid) -> Uuid {
        let server_id: Uuid = sqlx::query_scalar("INSERT INTO servers (name, owner_id) VALUES ($1, $2) RETURNING id")
            .bind(format!("Test Server {}", Uuid::new_v4()))
            .bind(owner)
            .fetch_one(&db.pool)
            .await
            .expect("failed to insert test server");
        join_server(db, server_id, owner, "owner").await;
        server_id
    }

    async fn join_server(db: &Database, server_id: Uuid, user_id: Uuid, role: &str) {
        sqlx::query("INSERT INTO server_members (server_id, user_id, role) VALUES ($1, $2, $3)")
            .bind(server_id)
            .bind(user_id)
            .bind(role)
            .execute(&db.pool)
            .await
            .expect("failed to insert test membership");
    }

    async fn cleanup(db: &Database, server_id: Uuid, user_ids: &[Uuid]) {
        let _ = sqlx::query("DELETE FROM servers WHERE id = $1").bind(server_id).execute(&db.pool).await;
        for user_id in user_ids {
            let _ = sqlx::query("DELETE FROM users WHERE id = $1").bind(user_id).execute(&db.pool).await;
        }
    }

    #[tokio::test]
    async fn plain_member_is_forbidden_from_viewing_the_audit_log() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server_id = create_test_server(&db, owner).await;
        let member = create_test_user(&db).await;
        join_server(&db, server_id, member, "member").await;

        let result = get_audit_log(
            State(db.clone()),
            CurrentUser(member),
            Path(server_id),
            Query(AuditLogQuery { before: None, limit: None }),
        )
        .await;
        assert!(matches!(result, Err(AppError::Forbidden(_))), "a plain member must not be able to view the audit log");

        cleanup(&db, server_id, &[owner, member]).await;
    }

    #[tokio::test]
    async fn moderator_sees_entries_newest_first() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server_id = create_test_server(&db, owner).await;
        let moderator = create_test_user(&db).await;
        join_server(&db, server_id, moderator, "moderator").await;
        let target = create_test_user(&db).await;
        join_server(&db, server_id, target, "member").await;

        crate::audit_log::record(&db, server_id, owner, crate::audit_log::MEMBER_KICKED, Some(target), None, None, serde_json::json!({}))
            .await;
        crate::audit_log::record(&db, server_id, owner, crate::audit_log::MEMBER_BANNED, Some(target), None, Some("again"), serde_json::json!({}))
            .await;

        let entries = get_audit_log(
            State(db.clone()),
            CurrentUser(moderator),
            Path(server_id),
            Query(AuditLogQuery { before: None, limit: None }),
        )
        .await
        .expect("a moderator should be able to view the audit log");
        let owner_username: String = sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
            .bind(owner)
            .fetch_one(&db.pool)
            .await
            .expect("fetching the owner's username failed");

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action, crate::audit_log::MEMBER_BANNED, "the most recent entry should come first");
        assert_eq!(entries[0].actor_username.as_deref(), Some(owner_username.as_str()), "the actor username should be joined in");
        assert_eq!(entries[0].target_user_id, Some(target));
        assert_eq!(entries[1].action, crate::audit_log::MEMBER_KICKED);

        cleanup(&db, server_id, &[owner, moderator, target]).await;
    }
}

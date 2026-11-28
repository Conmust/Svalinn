use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::access::{require_admin, require_member};
use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentSession;
use crate::files::{sign_opt, stored_path};

// ---------- REQUEST STRUCTS ----------

#[derive(Deserialize)]
pub struct CreateServerRequest {
    pub name: String,
}

#[derive(Deserialize)]
pub struct UpdateServerRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub icon_url: Option<String>,
}

// ---------- RESPONSE STRUCTS ----------

#[derive(Debug, Serialize, FromRow)]
pub struct Server {
    pub id: Uuid,
    pub name: String,
    pub owner_id: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub icon_url: Option<String>,
    pub description: Option<String>,
}

// ---------- GET USER SERVERS ----------

pub async fn get_user_servers(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
) -> Result<Json<Vec<Server>>, AppError> {
    let servers: Vec<Server> = sqlx::query_as(
        r#"
        SELECT s.id, s.name, s.owner_id, s.created_at, s.icon_url, s.description
        FROM servers s
        JOIN server_members sm ON s.id = sm.server_id
        WHERE sm.user_id = $1
        ORDER BY s.created_at ASC
        "#,
    )
    .bind(user_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut servers = servers;
    for server in &mut servers {
        sign_opt(&mut server.icon_url, user_id, session_id);
    }
    Ok(Json(servers))
}

// ---------- CREATE SERVER ----------

pub async fn create_server(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
    Json(payload): Json<CreateServerRequest>,
) -> Result<Json<Server>, AppError> {
    if payload.name.trim().is_empty() {
        return Err(AppError::BadRequest("Server name cannot be empty".into()));
    }

    let (patron_tier, is_site_owner): (String, bool) = sqlx::query_as(
        "SELECT patron_tier, COALESCE(site_role = 'owner', false) FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if !crate::tiers::can_create_server(&patron_tier, is_site_owner) {
        return Err(AppError::Forbidden(
            "Guild tier or higher is required to create a server".into(),
        ));
    }

    let server_id = Uuid::new_v4();
    
    let mut tx = db.pool.begin().await.map_err(|e| AppError::Database(e.to_string()))?;

    sqlx::query(
        "INSERT INTO servers (id, name, owner_id) VALUES ($1, $2, $3)",
    )
    .bind(server_id)
    .bind(&payload.name)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    sqlx::query(
        "INSERT INTO server_members (server_id, user_id, role) VALUES ($1, $2, 'admin')",
    )
    .bind(server_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Every server needs its default ("@everyone") role for
    // `permissions::resolve_server`/`resolve_channel` to grant anything
    // at all to a plain member -- see migrations/0036 for the bits this
    // mirrors for pre-existing servers.
    sqlx::query(
        "INSERT INTO roles (server_id, name, color, permissions, position, is_default) VALUES ($1, 'Member', '#99aab5', $2, 0, true)",
    )
    .bind(server_id)
    .bind(crate::permissions::Permission::VIEW_CHANNEL.0
        | crate::permissions::Permission::SEND_MESSAGES.0
        | crate::permissions::Permission::CREATE_INVITE.0
        | crate::permissions::Permission::ATTACH_FILES.0
        | crate::permissions::Permission::ADD_REACTIONS.0)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    tx.commit().await.map_err(|e| AppError::Database(e.to_string()))?;

    let server: Server = sqlx::query_as(
        "SELECT id, name, owner_id, created_at, icon_url, description FROM servers WHERE id = $1",
    )
    .bind(server_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut server = server;
    sign_opt(&mut server.icon_url, user_id, session_id);
    Ok(Json(server))
}

// ---------- GET SERVER ----------

pub async fn get_server(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
    Path(server_id): Path<Uuid>,
) -> Result<Json<Server>, AppError> {
    require_member(&db, server_id, user_id).await?;

    let server: Server = sqlx::query_as(
        "SELECT id, name, owner_id, created_at, icon_url, description FROM servers WHERE id = $1",
    )
    .bind(server_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut server = server;
    sign_opt(&mut server.icon_url, user_id, session_id);
    Ok(Json(server))
}

// ---------- UPDATE SERVER ----------

pub async fn update_server(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
    Path(server_id): Path<Uuid>,
    Json(payload): Json<UpdateServerRequest>,
) -> Result<Json<Server>, AppError> {
    require_admin(&db, server_id, user_id).await?;

    if let Some(name) = &payload.name {
        if name.trim().is_empty() {
            return Err(AppError::BadRequest("Server name cannot be empty".into()));
        }
    }

    let icon_url = payload.icon_url.as_deref().map(stored_path);
    if let Some(icon) = &icon_url {
        if !crate::files::is_safe_external_url(icon) {
            return Err(AppError::BadRequest(
                "icon_url must be one of your own uploaded files or an http(s) URL".into(),
            ));
        }
    }

    // Use COALESCE to update only the provided fields, keeping existing values for None
    sqlx::query(
        "UPDATE servers SET name = COALESCE($1, name), description = COALESCE($2, description), icon_url = COALESCE($3, icon_url) WHERE id = $4",
    )
    .bind(payload.name.as_deref().map(str::trim))
    .bind(&payload.description)
    .bind(&icon_url)
    .bind(server_id)
    .execute(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Fetch the updated server
    let server: Server = sqlx::query_as(
        "SELECT id, name, owner_id, created_at, icon_url, description FROM servers WHERE id = $1",
    )
    .bind(server_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut server = server;
    sign_opt(&mut server.icon_url, user_id, session_id);
    Ok(Json(server))
}
// ---------- USAGE ----------

/// GET /api/v1/servers/:server_id/usage
///
/// Owner/admin-only visibility into where this server stands against the
/// retention, pin and attachment-storage caps -- see `retention::ServerUsage`
/// for what each field means. Without this, a server's own owner has no way
/// to see "480/500 messages" or "4.2GB/5GB" before the hourly sweep or the
/// attachment quota's sliding-window eviction silently acts on their behalf.
pub async fn get_server_usage(
    State(db): State<Database>,
    CurrentSession { user_id, .. }: CurrentSession,
    Path(server_id): Path<Uuid>,
) -> Result<Json<crate::retention::ServerUsage>, AppError> {
    require_admin(&db, server_id, user_id).await?;
    Ok(Json(crate::retention::usage_summary(&db, server_id).await?))
}

#[derive(Deserialize)]
pub struct DeleteServerRequest {
    pub current_password: String,
}

/// DELETE /api/v1/servers/:server_id  `{ "current_password": "..." }`
///
/// Owner (or site owner) only. Deletes the server with its channels,
/// messages, emojis, invites and bans, and their uploaded files.
pub async fn delete_server(
    State(db): State<Database>,
    CurrentSession { user_id, .. }: CurrentSession,
    Path(server_id): Path<Uuid>,
    Json(payload): Json<DeleteServerRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    let db_err = |e: sqlx::Error| AppError::Database(e.to_string());

    let rank = crate::access::member_rank(&db, server_id, user_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("You are not a member of this server".into()))?;
    let (name, owner_id): (String, Uuid) = sqlx::query_as("SELECT name, owner_id FROM servers WHERE id = $1")
        .bind(server_id)
        .fetch_one(&db.pool)
        .await
        .map_err(db_err)?;
    if owner_id != user_id && rank < crate::access::SITE_OWNER_RANK {
        return Err(AppError::Forbidden("Only the owner can delete this server".into()));
    }

    crate::routes::users::verify_current_password(&db, user_id, &payload.current_password).await?;

    // Collect what the cascade won't clean up: members to notify and files on disk.
    let members: Vec<Uuid> = sqlx::query_scalar("SELECT user_id FROM server_members WHERE server_id = $1")
        .bind(server_id)
        .fetch_all(&db.pool)
        .await
        .map_err(db_err)?;
    let files: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT m.attachment_url FROM messages m JOIN channels c ON c.id = m.channel_id
        WHERE c.server_id = $1 AND m.attachment_url IS NOT NULL
        UNION ALL SELECT url FROM custom_emojis WHERE server_id = $1
        UNION ALL SELECT icon_url FROM servers WHERE id = $1 AND icon_url IS NOT NULL
        "#,
    )
    .bind(server_id)
    .fetch_all(&db.pool)
    .await
    .map_err(db_err)?;

    // Channels, messages, members, emojis, invites and bans cascade.
    sqlx::query("DELETE FROM servers WHERE id = $1")
        .bind(server_id)
        .execute(&db.pool)
        .await
        .map_err(db_err)?;

    crate::files::remove_stored_files(&files).await;

    for member in members {
        let _ = db.message_tx.send(crate::models::message::BroadcastMessage::to_user(
            "removed_from_server",
            serde_json::json!({ "server_id": server_id, "server_name": name, "reason": "deleted" }),
            member,
        ));
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
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

    async fn create_test_site_owner(db: &Database) -> Uuid {
        let unique = Uuid::new_v4();
        sqlx::query_scalar(
            "INSERT INTO users (username, email, password_hash, display_name, site_role) VALUES ($1, $2, $3, $4, 'owner') RETURNING id",
        )
        .bind(format!("test_{unique}"))
        .bind(format!("test_{unique}@example.invalid"))
        .bind("not-a-real-hash")
        .bind(format!("Test Owner {unique}"))
        .fetch_one(&db.pool)
        .await
        .expect("failed to insert test site owner")
    }

    async fn set_test_patron_tier(db: &Database, user_id: Uuid, tier: &str) {
        sqlx::query("UPDATE users SET patron_tier = $1 WHERE id = $2")
            .bind(tier)
            .bind(user_id)
            .execute(&db.pool)
            .await
            .expect("failed to set test user's patron_tier");
    }

    async fn cleanup_test_user(db: &Database, user_id: Uuid) {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1").bind(user_id).execute(&db.pool).await;
    }

    async fn cleanup_test_server(db: &Database, server_id: Uuid) {
        let _ = sqlx::query("DELETE FROM servers WHERE id = $1").bind(server_id).execute(&db.pool).await;
    }

    async fn create_test_server_with_admin(db: &Database, admin: Uuid) -> Uuid {
        let server_id = Uuid::new_v4();
        sqlx::query("INSERT INTO servers (id, name, owner_id) VALUES ($1, 'Test Server', $2)")
            .bind(server_id)
            .bind(admin)
            .execute(&db.pool)
            .await
            .expect("failed to insert test server");
        sqlx::query("INSERT INTO server_members (server_id, user_id, role) VALUES ($1, $2, 'admin')")
            .bind(server_id)
            .bind(admin)
            .execute(&db.pool)
            .await
            .expect("failed to insert test server membership");
        server_id
    }

    #[tokio::test]
    async fn update_server_rejects_a_javascript_icon_url() {
        // A server icon is rendered client-side straight into `fileUrl(...)`
        // with no scheme check of its own -- a `javascript:` icon_url would
        // be a stored-XSS payload against every member who ever loads this
        // server (see `files::is_safe_external_url`'s doc comment).
        let db = test_db().await;
        let admin = create_test_user(&db).await;
        let server_id = create_test_server_with_admin(&db, admin).await;

        let result = update_server(
            State(db.clone()),
            CurrentSession { user_id: admin, session_id: Uuid::new_v4() },
            Path(server_id),
            Json(UpdateServerRequest {
                name: None,
                description: None,
                icon_url: Some("javascript:alert(document.cookie)".into()),
            }),
        )
        .await;
        assert!(result.is_err(), "a javascript: icon_url must be rejected");

        cleanup_test_server(&db, server_id).await;
        cleanup_test_user(&db, admin).await;
    }

    #[tokio::test]
    async fn update_server_accepts_an_https_icon_url() {
        let db = test_db().await;
        let admin = create_test_user(&db).await;
        let server_id = create_test_server_with_admin(&db, admin).await;

        let result = update_server(
            State(db.clone()),
            CurrentSession { user_id: admin, session_id: Uuid::new_v4() },
            Path(server_id),
            Json(UpdateServerRequest {
                name: None,
                description: None,
                icon_url: Some("https://example.invalid/icon.png".into()),
            }),
        )
        .await
        .expect("an https icon_url should be accepted");
        assert_eq!(result.0.icon_url, Some("https://example.invalid/icon.png".to_string()));

        cleanup_test_server(&db, server_id).await;
        cleanup_test_user(&db, admin).await;
    }

    #[tokio::test]
    async fn free_tier_cannot_create_a_server() {
        let db = test_db().await;
        let user = create_test_user(&db).await;

        let result = create_server(
            State(db.clone()),
            CurrentSession { user_id: user, session_id: Uuid::new_v4() },
            Json(CreateServerRequest { name: "Nope".into() }),
        )
        .await;

        match result {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected AppError::Forbidden for a free-tier user, got {other:?}"),
        }

        cleanup_test_user(&db, user).await;
    }

    #[tokio::test]
    async fn patron_tier_cannot_create_a_server() {
        let db = test_db().await;
        let user = create_test_user(&db).await;
        set_test_patron_tier(&db, user, "patron").await;

        let result = create_server(
            State(db.clone()),
            CurrentSession { user_id: user, session_id: Uuid::new_v4() },
            Json(CreateServerRequest { name: "Still nope".into() }),
        )
        .await;

        match result {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected AppError::Forbidden for a patron-tier user, got {other:?}"),
        }

        cleanup_test_user(&db, user).await;
    }

    #[tokio::test]
    async fn guild_tier_can_create_a_server() {
        let db = test_db().await;
        let user = create_test_user(&db).await;
        set_test_patron_tier(&db, user, "guild").await;

        let result = create_server(
            State(db.clone()),
            CurrentSession { user_id: user, session_id: Uuid::new_v4() },
            Json(CreateServerRequest { name: "Guild server".into() }),
        )
        .await
        .expect("a guild-tier user should be able to create a server");

        assert_eq!(result.0.name, "Guild server");
        assert_eq!(result.0.owner_id, user);

        cleanup_test_server(&db, result.0.id).await;
        cleanup_test_user(&db, user).await;
    }

    #[tokio::test]
    async fn enterprise_tier_can_create_a_server() {
        let db = test_db().await;
        let user = create_test_user(&db).await;
        set_test_patron_tier(&db, user, "enterprise").await;

        let result = create_server(
            State(db.clone()),
            CurrentSession { user_id: user, session_id: Uuid::new_v4() },
            Json(CreateServerRequest { name: "Enterprise server".into() }),
        )
        .await
        .expect("an enterprise-tier user should be able to create a server");

        cleanup_test_server(&db, result.0.id).await;
        cleanup_test_user(&db, user).await;
    }

    #[tokio::test]
    async fn site_owner_can_create_a_server_regardless_of_tier() {
        let db = test_db().await;
        let owner = create_test_site_owner(&db).await;
        // Site owner defaults to 'free' patron_tier -- the bypass must not
        // depend on also being guild-tier.

        let result = create_server(
            State(db.clone()),
            CurrentSession { user_id: owner, session_id: Uuid::new_v4() },
            Json(CreateServerRequest { name: "Owner server".into() }),
        )
        .await
        .expect("the site owner should be able to create a server regardless of tier");

        cleanup_test_server(&db, result.0.id).await;
        cleanup_test_user(&db, owner).await;
    }

    // ---------- Server usage ----------

    async fn create_test_channel(db: &Database, server_id: Uuid) -> Uuid {
        sqlx::query_scalar("INSERT INTO channels (server_id, name, type) VALUES ($1, $2, 'text') RETURNING id")
            .bind(server_id)
            .bind(format!("general-{}", Uuid::new_v4()))
            .fetch_one(&db.pool)
            .await
            .expect("failed to insert test channel")
    }

    async fn insert_plain_message(db: &Database, channel_id: Uuid, user_id: Uuid, pinned: bool) {
        sqlx::query("INSERT INTO messages (channel_id, user_id, content, is_pinned) VALUES ($1, $2, 'hi', $3)")
            .bind(channel_id)
            .bind(user_id)
            .bind(pinned)
            .execute(&db.pool)
            .await
            .expect("failed to insert test message");
    }

    async fn insert_message_with_attachment(db: &Database, channel_id: Uuid, user_id: Uuid, size: i64, pinned: bool) {
        sqlx::query(
            "INSERT INTO messages (channel_id, user_id, content, attachment_url, attachment_filename, attachment_mime_type, attachment_size, is_pinned) \
             VALUES ($1, $2, '', '/uploads/test.bin', 'test.bin', 'application/octet-stream', $3, $4)",
        )
        .bind(channel_id)
        .bind(user_id)
        .bind(size)
        .bind(pinned)
        .execute(&db.pool)
        .await
        .expect("failed to insert test message with attachment");
    }

    #[tokio::test]
    async fn get_server_usage_counts_messages_pins_and_attachment_bytes() {
        let db = test_db().await;
        let admin = create_test_user(&db).await;
        let server_id = create_test_server_with_admin(&db, admin).await;
        let channel = create_test_channel(&db, server_id).await;

        insert_plain_message(&db, channel, admin, false).await;
        insert_plain_message(&db, channel, admin, false).await;
        insert_plain_message(&db, channel, admin, true).await;
        insert_message_with_attachment(&db, channel, admin, 1_000, false).await;
        insert_message_with_attachment(&db, channel, admin, 2_000, true).await;

        let usage = get_server_usage(State(db.clone()), CurrentSession { user_id: admin, session_id: Uuid::new_v4() }, Path(server_id))
            .await
            .expect("an admin should be able to read server usage")
            .0;

        assert_eq!(usage.message_count, 3, "3 non-pinned messages were inserted (2 plain + 1 with an attachment)");
        assert_eq!(usage.pinned_count, 2, "2 pinned messages were inserted (1 plain + 1 with an attachment)");
        assert_eq!(usage.message_cap, crate::retention::MESSAGE_CAP_PER_SERVER);
        assert_eq!(usage.pin_cap, crate::retention::PIN_CAP_PER_SERVER);
        assert_eq!(usage.attachment_bytes_used, 1_000, "only the non-pinned attachment should count toward the quota");
        assert_eq!(usage.attachment_quota_bytes, crate::access::MAX_SERVER_ATTACHMENT_STORAGE_BYTES);

        cleanup_test_server(&db, server_id).await;
        cleanup_test_user(&db, admin).await;
    }

    #[tokio::test]
    async fn get_server_usage_is_rejected_for_a_non_admin_member() {
        let db = test_db().await;
        let admin = create_test_user(&db).await;
        let server_id = create_test_server_with_admin(&db, admin).await;
        let member = create_test_user(&db).await;
        sqlx::query("INSERT INTO server_members (server_id, user_id, role) VALUES ($1, $2, 'member')")
            .bind(server_id)
            .bind(member)
            .execute(&db.pool)
            .await
            .expect("failed to insert member");

        let result = get_server_usage(State(db.clone()), CurrentSession { user_id: member, session_id: Uuid::new_v4() }, Path(server_id)).await;
        assert!(matches!(result, Err(AppError::Forbidden(_))), "an ordinary member must not see server usage, got {result:?}");

        cleanup_test_server(&db, server_id).await;
        cleanup_test_user(&db, admin).await;
        cleanup_test_user(&db, member).await;
    }
}

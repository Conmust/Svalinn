use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::access::{member_rank, require_admin, require_member, role_rank, SITE_OWNER_RANK};
use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::{CurrentSession, CurrentUser};
use crate::files::sign_opt;
use crate::models::message::BroadcastMessage;
use crate::presence::VISIBLE_STATUS_SQL;

/// Moderators and above can kick and ban.
const MODERATOR_RANK: u8 = 2;

/// Nicknames are a display label, not sensitive data, but still capped well
/// under the `users.username`/`VARCHAR(100)` nickname column width.
const MAX_NICKNAME_CHARS: usize = 64;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ServerMember {
    pub id: Uuid,
    pub username: String,
    /// This member's nickname in this one server, if they (or an admin) set
    /// one -- NULL means "show the username instead".
    pub nickname: Option<String>,
    pub is_online: bool,
    pub status: String,
    pub role: String,
    pub is_owner: bool,
    pub is_site_owner: bool,
    pub patron_tier: String,
    pub avatar_url: Option<String>,
    pub badge_emblem: Option<String>,
    pub has_beta_badge: bool,
    /// Every custom (non-default) role this member currently holds in this
    /// server, so a client can show which roles are already assigned
    /// before letting an admin add/remove one (see `routes::roles`). The
    /// server's default ("@everyone") role is implicit for every member
    /// and deliberately left out of this list -- there's nothing to
    /// assign or unassign about it.
    pub role_ids: Vec<Uuid>,
}

pub async fn get_server_members(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
    Path(server_id): Path<Uuid>,
) -> Result<Json<Vec<ServerMember>>, AppError> {
    require_member(&db, server_id, user_id).await?;

    let members: Vec<ServerMember> = sqlx::query_as(&format!(
        r#"
        SELECT * FROM (
            SELECT
                u.id,
                u.username,
                sm.nickname,
                COALESCE(u.is_online, false) AS is_online,
                {VISIBLE_STATUS_SQL} AS status,
                COALESCE(sm.role, 'member') AS role,
                s.owner_id = u.id AS is_owner,
                COALESCE(u.site_role = 'owner', false) AS is_site_owner,
                COALESCE(u.patron_tier, 'free') AS patron_tier,
                u.avatar_url,
                u.badge_emblem,
                u.has_beta_badge,
                COALESCE(
                    (SELECT ARRAY_AGG(mr.role_id) FROM member_roles mr
                     WHERE mr.server_id = sm.server_id AND mr.user_id = u.id),
                    ARRAY[]::uuid[]
                ) AS role_ids
            FROM server_members sm
            JOIN users u ON sm.user_id = u.id
            JOIN servers s ON s.id = sm.server_id
            WHERE sm.server_id = $1
        ) members
        ORDER BY
            CASE status
                WHEN 'online' THEN 1
                WHEN 'idle' THEN 2
                WHEN 'busy' THEN 3
                WHEN 'away' THEN 4
                ELSE 5
            END,
            username ASC
        "#
    ))
    .bind(server_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut members = members;
    for m in &mut members {
        sign_opt(&mut m.avatar_url, user_id, session_id);
    }
    Ok(Json(members))
}

#[derive(Deserialize)]
pub struct SetNicknameRequest {
    /// `None` or an empty/whitespace-only string clears the nickname.
    #[serde(default)]
    pub nickname: Option<String>,
}

/// Trims and validates a nickname, turning an empty string into `None`
/// (clearing it) the same way the rest of the app treats a blank optional
/// field.
fn normalize_nickname(nickname: Option<String>) -> Result<Option<String>, AppError> {
    let trimmed = nickname.as_deref().map(str::trim).filter(|s| !s.is_empty());
    match trimmed {
        None => Ok(None),
        Some(n) if n.chars().count() > MAX_NICKNAME_CHARS => {
            Err(AppError::BadRequest(format!("Nickname must be {MAX_NICKNAME_CHARS} characters or fewer")))
        }
        Some(n) => Ok(Some(n.to_string())),
    }
}

async fn set_nickname(db: &Database, server_id: Uuid, target: Uuid, nickname: Option<String>) -> Result<(), AppError> {
    let result = sqlx::query("UPDATE server_members SET nickname = $1 WHERE server_id = $2 AND user_id = $3")
        .bind(&nickname)
        .bind(server_id)
        .bind(target)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("That user isn't a member of this server".into()));
    }

    let payload = serde_json::json!({ "server_id": server_id, "user_id": target, "nickname": nickname });
    let _ = db.message_tx.send(BroadcastMessage::to_server("member_updated", payload, server_id));
    Ok(())
}

/// PATCH /api/v1/servers/:server_id/nickname — set or clear your own nickname.
pub async fn set_my_nickname(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
    Json(payload): Json<SetNicknameRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    require_member(&db, server_id, user_id).await?;
    let nickname = normalize_nickname(payload.nickname)?;
    set_nickname(&db, server_id, user_id, nickname.clone()).await?;
    Ok(Json(serde_json::json!({ "nickname": nickname })))
}

/// PATCH /api/v1/servers/:server_id/members/:user_id/nickname — admins and
/// owners can set or clear anyone's nickname (e.g. to enforce a naming
/// policy). Unlike roles/kicks/bans this isn't rank-gated beyond "is an
/// admin": renaming someone doesn't give or take away any power over them.
pub async fn admin_set_nickname(
    State(db): State<Database>,
    CurrentUser(actor): CurrentUser,
    Path((server_id, target)): Path<(Uuid, Uuid)>,
    Json(payload): Json<SetNicknameRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    require_admin(&db, server_id, actor).await?;
    let nickname = normalize_nickname(payload.nickname)?;
    set_nickname(&db, server_id, target, nickname.clone()).await?;
    Ok(Json(serde_json::json!({ "nickname": nickname })))
}

/// GET /api/v1/servers/:server_id/role — the current user's role and rank.
pub async fn get_user_role_in_server(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let role = require_member(&db, server_id, user_id).await?;
    let rank = member_rank(&db, server_id, user_id).await?.unwrap_or(1);
    let is_owner = is_server_owner(&db, server_id, user_id).await?;

    Ok(Json(serde_json::json!({
        "role": role,
        // Owner of this server (who can't leave it), as opposed to a site owner.
        "is_owner": is_owner,
        "is_site_owner": rank == crate::access::SITE_OWNER_RANK,
        "rank": rank,
    })))
}

async fn is_server_owner(db: &Database, server_id: Uuid, user_id: Uuid) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM servers WHERE id = $1 AND owner_id = $2)")
        .bind(server_id)
        .bind(user_id)
        .fetch_one(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
}

/// Checks that `actor` may remove `target` from the server: the actor must be
/// a moderator or above and outrank the target. Returns the server name.
async fn authorize_removal(db: &Database, server_id: Uuid, actor: Uuid, target: Uuid) -> Result<String, AppError> {
    if actor == target {
        return Err(AppError::BadRequest("You can't do that to yourself. Use Leave server instead.".into()));
    }
    let actor_rank = member_rank(db, server_id, actor)
        .await?
        .ok_or_else(|| AppError::Forbidden("You are not a member of this server".into()))?;
    if actor_rank < MODERATOR_RANK {
        return Err(AppError::Forbidden("Only moderators and above can do this".into()));
    }
    // Someone who isn't a member can still be banned (rank 0).
    let target_rank = member_rank(db, server_id, target).await?.unwrap_or(0);
    if target_rank >= actor_rank {
        return Err(AppError::Forbidden("You can only do this to members ranked below you".into()));
    }

    sqlx::query_scalar("SELECT name FROM servers WHERE id = $1")
        .bind(server_id)
        .fetch_one(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
}

/// Removes a membership and tells everyone affected. `reason` is "kicked",
/// "banned" or "left".
async fn remove_member(db: &Database, server_id: Uuid, server_name: &str, user_id: Uuid, reason: &str) -> Result<(), AppError> {
    sqlx::query("DELETE FROM server_members WHERE server_id = $1 AND user_id = $2")
        .bind(server_id)
        .bind(user_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    // Remaining members update their member list...
    let _ = db.message_tx.send(BroadcastMessage::to_server(
        "member_left",
        serde_json::json!({ "server_id": server_id, "user_id": user_id }),
        server_id,
    ));
    // ...and the removed user's app drops the server straight away. (Access
    // to the server's messages and files already ends with the membership.)
    let _ = db.message_tx.send(BroadcastMessage::to_user(
        "removed_from_server",
        serde_json::json!({ "server_id": server_id, "server_name": server_name, "reason": reason }),
        user_id,
    ));
    Ok(())
}

/// DELETE /api/v1/servers/:server_id/members/:user_id — kick (they can rejoin with an invite).
pub async fn kick_member(
    State(db): State<Database>,
    CurrentUser(actor): CurrentUser,
    Path((server_id, target)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let server_name = authorize_removal(&db, server_id, actor, target).await?;
    if member_rank(&db, server_id, target).await?.is_none() {
        return Err(AppError::NotFound("That user isn't a member of this server".into()));
    }
    remove_member(&db, server_id, &server_name, target, "kicked").await?;
    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /api/v1/servers/:server_id/members/me — leave a server.
pub async fn leave_server(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    member_rank(&db, server_id, user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("You aren't a member of this server".into()))?;
    if is_server_owner(&db, server_id, user_id).await? {
        return Err(AppError::BadRequest("The owner can't leave their own server.".into()));
    }
    let server_name: String = sqlx::query_scalar("SELECT name FROM servers WHERE id = $1")
        .bind(server_id)
        .fetch_one(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    remove_member(&db, server_id, &server_name, user_id, "left").await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct BanRequest {
    pub user_id: Uuid,
    pub reason: Option<String>,
}

/// POST /api/v1/servers/:server_id/bans — remove someone and stop them rejoining.
pub async fn ban_member(
    State(db): State<Database>,
    CurrentUser(actor): CurrentUser,
    Path(server_id): Path<Uuid>,
    Json(payload): Json<BanRequest>,
) -> Result<StatusCode, AppError> {
    let server_name = authorize_removal(&db, server_id, actor, payload.user_id).await?;
    let reason = payload.reason.as_deref().map(str::trim).filter(|r| !r.is_empty());
    if reason.is_some_and(|r| r.chars().count() > 500) {
        return Err(AppError::BadRequest("Reason must be at most 500 characters".into()));
    }

    sqlx::query(
        r#"
        INSERT INTO server_bans (server_id, user_id, banned_by, reason) VALUES ($1, $2, $3, $4)
        ON CONFLICT (server_id, user_id) DO UPDATE SET banned_by = $3, reason = $4, created_at = NOW()
        "#,
    )
    .bind(server_id)
    .bind(payload.user_id)
    .bind(actor)
    .bind(reason)
    .execute(&db.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_foreign_key_violation() => AppError::NotFound("User not found".into()),
        e => AppError::Database(e.to_string()),
    })?;

    // Also record the banned account's email hash against this server, so a
    // new account verified under the same real email can't just walk back
    // in via an invite (see `accept_invite`). Best-effort: a banned user
    // with no verified email yet (email_hash still NULL) has nothing to
    // record here, which is fine -- `accept_invite` already requires
    // verification before anyone can join at all.
    if let Some(email_hash) = email_hash_of(&db, payload.user_id).await? {
        sqlx::query(
            r#"
            INSERT INTO banned_emails (email_hash, server_id, reason) VALUES ($1, $2, $3)
            ON CONFLICT (email_hash, server_id) WHERE server_id IS NOT NULL DO UPDATE SET reason = $3
            "#,
        )
        .bind(&email_hash)
        .bind(server_id)
        .bind(reason)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    }

    remove_member(&db, server_id, &server_name, payload.user_id, "banned").await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn email_hash_of(db: &Database, user_id: Uuid) -> Result<Option<String>, AppError> {
    sqlx::query_scalar("SELECT email_hash FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&db.pool)
        .await
        .map(Option::flatten)
        .map_err(|e| AppError::Database(e.to_string()))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct ServerBan {
    pub user_id: Uuid,
    pub username: String,
    pub reason: Option<String>,
    pub banned_by: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

async fn require_moderator(db: &Database, server_id: Uuid, user_id: Uuid) -> Result<(), AppError> {
    match member_rank(db, server_id, user_id).await? {
        Some(rank) if rank >= MODERATOR_RANK => Ok(()),
        Some(_) => Err(AppError::Forbidden("Only moderators and above can do this".into())),
        None => Err(AppError::Forbidden("You are not a member of this server".into())),
    }
}

/// GET /api/v1/servers/:server_id/bans
pub async fn list_bans(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
) -> Result<Json<Vec<ServerBan>>, AppError> {
    require_moderator(&db, server_id, user_id).await?;
    let bans: Vec<ServerBan> = sqlx::query_as(
        r#"
        SELECT b.user_id, u.username, b.reason, by_user.username AS banned_by, b.created_at
        FROM server_bans b
        JOIN users u ON u.id = b.user_id
        LEFT JOIN users by_user ON by_user.id = b.banned_by
        WHERE b.server_id = $1
        ORDER BY b.created_at DESC
        "#,
    )
    .bind(server_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(Json(bans))
}

/// DELETE /api/v1/servers/:server_id/bans/:user_id — lift a server ban. They
/// need a new invite to come back.
pub async fn unban_member(
    State(db): State<Database>,
    CurrentUser(actor): CurrentUser,
    Path((server_id, target)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    require_moderator(&db, server_id, actor).await?;
    let removed = sqlx::query("DELETE FROM server_bans WHERE server_id = $1 AND user_id = $2")
        .bind(server_id)
        .bind(target)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .rows_affected();
    if removed == 0 {
        return Err(AppError::NotFound("That user isn't banned from this server".into()));
    }

    // ban_member also records the account's email hash in banned_emails, so
    // a new account under the same email can't evade the ban (see
    // `accept_invite`). Lifting the ban has to clear that too, or the
    // account we just unbanned still can't get back in through an invite
    // -- `banned_emails` would be blocking the very account `server_bans`
    // no longer does.
    if let Some(email_hash) = email_hash_of(&db, target).await? {
        sqlx::query("DELETE FROM banned_emails WHERE server_id = $1 AND email_hash = $2")
            .bind(server_id)
            .bind(&email_hash)
            .execute(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct SetRoleRequest {
    pub role: String,
}

/// PATCH /api/v1/servers/:server_id/members/:user_id/role  `{ "role": "moderator" }`
///
/// Admins and above can change the role of members ranked below them, to a
/// role below their own: admins make moderators; owners make admins.
pub async fn set_member_role(
    State(db): State<Database>,
    CurrentUser(actor): CurrentUser,
    Path((server_id, target)): Path<(Uuid, Uuid)>,
    Json(payload): Json<SetRoleRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let role = payload.role.as_str();
    if !matches!(role, "member" | "moderator" | "admin") {
        return Err(AppError::BadRequest("Role must be member, moderator or admin".into()));
    }
    if actor == target {
        return Err(AppError::BadRequest("You can't change your own role".into()));
    }

    let actor_rank = member_rank(&db, server_id, actor)
        .await?
        .ok_or_else(|| AppError::Forbidden("You are not a member of this server".into()))?;
    if actor_rank < 3 {
        return Err(AppError::Forbidden("Only admins and above can change roles".into()));
    }
    let target_rank = member_rank(&db, server_id, target)
        .await?
        .ok_or_else(|| AppError::NotFound("That user isn't a member of this server".into()))?;
    if target_rank >= actor_rank {
        return Err(AppError::Forbidden("You can only change the role of members ranked below you".into()));
    }
    if role_rank(role, false) >= actor_rank {
        return Err(AppError::Forbidden("You can only give roles below your own".into()));
    }

    sqlx::query("UPDATE server_members SET role = $1 WHERE server_id = $2 AND user_id = $3")
        .bind(role)
        .bind(server_id)
        .bind(target)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let payload = serde_json::json!({ "server_id": server_id, "user_id": target, "role": role });
    let _ = db.message_tx.send(BroadcastMessage::to_server("member_updated", payload.clone(), server_id));
    Ok(Json(payload))
}

#[derive(Deserialize)]
pub struct TransferRequest {
    pub user_id: Uuid,
    pub current_password: String,
}

/// POST /api/v1/servers/:server_id/transfer  `{ "user_id": "...", "current_password": "..." }`
///
/// The owner (or a site owner) hands the server to another member. The old
/// owner stays on as an admin.
pub async fn transfer_ownership(
    State(db): State<Database>,
    CurrentUser(actor): CurrentUser,
    Path(server_id): Path<Uuid>,
    Json(payload): Json<TransferRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    let actor_rank = member_rank(&db, server_id, actor)
        .await?
        .ok_or_else(|| AppError::Forbidden("You are not a member of this server".into()))?;
    let current_owner: Uuid = sqlx::query_scalar("SELECT owner_id FROM servers WHERE id = $1")
        .bind(server_id)
        .fetch_one(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    if current_owner != actor && actor_rank < SITE_OWNER_RANK {
        return Err(AppError::Forbidden("Only the owner can transfer the server".into()));
    }
    let new_owner = payload.user_id;
    if new_owner == current_owner {
        return Err(AppError::BadRequest("They already own this server".into()));
    }
    if member_rank(&db, server_id, new_owner).await?.is_none() {
        return Err(AppError::NotFound("The new owner must be a member of this server".into()));
    }

    crate::routes::users::verify_current_password(&db, actor, &payload.current_password).await?;

    let db_err = |e: sqlx::Error| AppError::Database(e.to_string());
    let mut tx = db.pool.begin().await.map_err(db_err)?;
    sqlx::query("UPDATE servers SET owner_id = $1 WHERE id = $2")
        .bind(new_owner)
        .bind(server_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    // Both end up as admins; ownership itself comes from servers.owner_id.
    sqlx::query("UPDATE server_members SET role = 'admin' WHERE server_id = $1 AND user_id IN ($2, $3)")
        .bind(server_id)
        .bind(current_owner)
        .bind(new_owner)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    for user_id in [current_owner, new_owner] {
        let _ = db.message_tx.send(BroadcastMessage::to_server(
            "member_updated",
            serde_json::json!({ "server_id": server_id, "user_id": user_id, "role": "admin" }),
            server_id,
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

    /// `email_privacy::init_keys` panics if a test calls encrypt/blind_index
    /// before it's run; it's idempotent-safe (OnceLock) across tests in this
    /// module, which all share one test binary. Needs EMAIL_ENCRYPTION_KEY /
    /// EMAIL_BLIND_INDEX_PEPPER set in the test environment's .env, same as
    /// DATABASE_URL already is.
    fn ensure_email_privacy_keys() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            dotenvy::dotenv().ok();
            crate::email_privacy::init_keys("development").expect("test .env must set EMAIL_ENCRYPTION_KEY/EMAIL_BLIND_INDEX_PEPPER");
        });
    }

    async fn create_test_user_with_verified_email(db: &Database, email: &str) -> Uuid {
        ensure_email_privacy_keys();
        let unique = Uuid::new_v4();
        sqlx::query_scalar(
            r#"
            INSERT INTO users (username, email_encrypted, email_hash, email_verified_at, password_hash, display_name)
            VALUES ($1, $2, $3, NOW(), $4, $1) RETURNING id
            "#,
        )
        .bind(format!("test_{unique}"))
        .bind(crate::email_privacy::encrypt(email))
        .bind(crate::email_privacy::blind_index(email))
        .bind("not-a-real-hash")
        .fetch_one(&db.pool)
        .await
        .expect("failed to insert test user with verified email")
    }

    async fn nickname_of(db: &Database, server_id: Uuid, user_id: Uuid) -> Option<String> {
        sqlx::query_scalar("SELECT nickname FROM server_members WHERE server_id = $1 AND user_id = $2")
            .bind(server_id)
            .bind(user_id)
            .fetch_one(&db.pool)
            .await
            .expect("fetching nickname failed")
    }

    #[tokio::test]
    async fn member_can_set_and_clear_their_own_nickname() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server_id = create_test_server(&db, owner).await;

        let result = set_my_nickname(
            State(db.clone()),
            CurrentUser(owner),
            Path(server_id),
            Json(SetNicknameRequest { nickname: Some("  Cap'n  ".into()) }),
        )
        .await
        .expect("a member should be able to set their own nickname");
        assert_eq!(result.0["nickname"], "Cap'n", "the nickname should be trimmed");
        assert_eq!(nickname_of(&db, server_id, owner).await, Some("Cap'n".to_string()));

        let cleared = set_my_nickname(
            State(db.clone()),
            CurrentUser(owner),
            Path(server_id),
            Json(SetNicknameRequest { nickname: Some("   ".into()) }),
        )
        .await
        .expect("a blank nickname should clear it rather than error");
        assert!(cleared.0["nickname"].is_null(), "a whitespace-only nickname should clear to null");
        assert_eq!(nickname_of(&db, server_id, owner).await, None);

        cleanup(&db, server_id, &[owner]).await;
    }

    #[tokio::test]
    async fn self_service_nickname_rejects_a_non_member() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let outsider = create_test_user(&db).await;
        let server_id = create_test_server(&db, owner).await;

        let result = set_my_nickname(
            State(db.clone()),
            CurrentUser(outsider),
            Path(server_id),
            Json(SetNicknameRequest { nickname: Some("Nope".into()) }),
        )
        .await;
        match result {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected AppError::Forbidden for a non-member, got {other:?}"),
        }

        cleanup(&db, server_id, &[owner, outsider]).await;
    }

    #[tokio::test]
    async fn self_service_nickname_rejects_names_over_the_length_limit() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server_id = create_test_server(&db, owner).await;

        let too_long = "x".repeat(MAX_NICKNAME_CHARS + 1);
        let result = set_my_nickname(
            State(db.clone()),
            CurrentUser(owner),
            Path(server_id),
            Json(SetNicknameRequest { nickname: Some(too_long) }),
        )
        .await;
        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for an over-length nickname, got {other:?}"),
        }
        assert_eq!(nickname_of(&db, server_id, owner).await, None, "a rejected nickname must not be stored");

        cleanup(&db, server_id, &[owner]).await;
    }

    #[tokio::test]
    async fn admin_can_set_and_clear_another_members_nickname() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let member = create_test_user(&db).await;
        let server_id = create_test_server(&db, owner).await;
        join_server(&db, server_id, member, "member").await;

        let _ = admin_set_nickname(
            State(db.clone()),
            CurrentUser(owner),
            Path((server_id, member)),
            Json(SetNicknameRequest { nickname: Some("House Name".into()) }),
        )
        .await
        .expect("an admin/owner should be able to set another member's nickname");
        assert_eq!(nickname_of(&db, server_id, member).await, Some("House Name".to_string()));

        let _ = admin_set_nickname(
            State(db.clone()),
            CurrentUser(owner),
            Path((server_id, member)),
            Json(SetNicknameRequest { nickname: None }),
        )
        .await
        .expect("an admin/owner should be able to clear another member's nickname");
        assert_eq!(nickname_of(&db, server_id, member).await, None);

        cleanup(&db, server_id, &[owner, member]).await;
    }

    #[tokio::test]
    async fn plain_member_cannot_set_another_members_nickname() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let member_a = create_test_user(&db).await;
        let member_b = create_test_user(&db).await;
        let server_id = create_test_server(&db, owner).await;
        join_server(&db, server_id, member_a, "member").await;
        join_server(&db, server_id, member_b, "member").await;

        let result = admin_set_nickname(
            State(db.clone()),
            CurrentUser(member_a),
            Path((server_id, member_b)),
            Json(SetNicknameRequest { nickname: Some("Nope".into()) }),
        )
        .await;
        match result {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected AppError::Forbidden for a non-admin caller, got {other:?}"),
        }
        assert_eq!(nickname_of(&db, server_id, member_b).await, None);

        cleanup(&db, server_id, &[owner, member_a, member_b]).await;
    }

    #[tokio::test]
    async fn admin_set_nickname_rejects_a_non_member_target() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let outsider = create_test_user(&db).await;
        let server_id = create_test_server(&db, owner).await;

        let result = admin_set_nickname(
            State(db.clone()),
            CurrentUser(owner),
            Path((server_id, outsider)),
            Json(SetNicknameRequest { nickname: Some("Ghost".into()) }),
        )
        .await;
        match result {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected AppError::NotFound for a target who isn't a member, got {other:?}"),
        }

        cleanup(&db, server_id, &[owner, outsider]).await;
    }

    #[tokio::test]
    async fn get_server_members_includes_nickname_and_avatar_url() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server_id = create_test_server(&db, owner).await;
        let _ = set_nickname(&db, server_id, owner, Some("Boss".into())).await;

        let members = get_server_members(
            State(db.clone()),
            CurrentSession { user_id: owner, session_id: Uuid::new_v4() },
            Path(server_id),
        )
        .await
        .expect("fetching server members should succeed");

        let me = members.0.iter().find(|m| m.id == owner).expect("owner should be in the member list");
        assert_eq!(me.nickname, Some("Boss".to_string()));

        cleanup(&db, server_id, &[owner]).await;
    }

    #[tokio::test]
    async fn ban_member_records_the_banned_email_hash_for_this_server() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let server_id = create_test_server(&db, owner).await;
        let email = format!("evader_{}@example.invalid", Uuid::new_v4());
        let evader = create_test_user_with_verified_email(&db, &email).await;
        join_server(&db, server_id, evader, "member").await;

        ban_member(
            State(db.clone()),
            CurrentUser(owner),
            Path(server_id),
            Json(BanRequest { user_id: evader, reason: Some("evasion test".into()) }),
        )
        .await
        .expect("owner should be able to ban a plain member");

        let email_hash = crate::email_privacy::blind_index(&email);
        let recorded: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM banned_emails WHERE server_id = $1 AND email_hash = $2)",
        )
        .bind(server_id)
        .bind(&email_hash)
        .fetch_one(&db.pool)
        .await
        .expect("querying banned_emails failed");
        assert!(recorded, "banning a member with a verified email should record its blind-index hash");

        cleanup(&db, server_id, &[owner, evader]).await;
    }
}

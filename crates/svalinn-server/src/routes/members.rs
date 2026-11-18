use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::access::{member_rank, require_member};
use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;
use crate::models::message::BroadcastMessage;
use crate::presence::VISIBLE_STATUS_SQL;

/// Moderators and above can kick and ban.
const MODERATOR_RANK: u8 = 2;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ServerMember {
    pub id: Uuid,
    pub username: String,
    pub is_online: bool,
    pub status: String,
    pub role: String,
    pub is_owner: bool,
    pub is_site_owner: bool,
    pub patron_tier: String,
}

pub async fn get_server_members(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
) -> Result<Json<Vec<ServerMember>>, AppError> {
    require_member(&db, server_id, user_id).await?;

    let members: Vec<ServerMember> = sqlx::query_as(&format!(
        r#"
        SELECT * FROM (
            SELECT
                u.id,
                u.username,
                COALESCE(u.is_online, false) AS is_online,
                {VISIBLE_STATUS_SQL} AS status,
                COALESCE(sm.role, 'member') AS role,
                s.owner_id = u.id AS is_owner,
                COALESCE(u.site_role = 'owner', false) AS is_site_owner,
                COALESCE(u.patron_tier, 'free') AS patron_tier
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

    Ok(Json(members))
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

    remove_member(&db, server_id, &server_name, payload.user_id, "banned").await?;
    Ok(StatusCode::NO_CONTENT)
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
    Ok(StatusCode::NO_CONTENT)
}

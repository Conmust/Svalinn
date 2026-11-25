//! Invite codes for joining servers.
//!
//! Moderators and above create invites, optionally expiring and/or limited to
//! a number of uses. Anyone logged in can look up a code and join with it,
//! unless they're banned from that server. Lookups and joins are rate limited
//! per user so codes can't be found by guessing.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::access::member_rank;
use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::{CurrentSession, CurrentUser};
use crate::files::sign_opt;
use crate::models::message::BroadcastMessage;
use crate::rate_limit::INVITES_PER_USER;
use crate::routes::servers::Server;

const CODE_LENGTH: usize = 10;
/// No 0/O or 1/l/I, so codes are easy to read out and type.
const CODE_ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const MAX_EXPIRY_HOURS: i64 = 24 * 30;
const MAX_USES: i32 = 1000;
const MODERATOR_RANK: u8 = 2;

fn new_code() -> String {
    let mut rng = rand::thread_rng();
    (0..CODE_LENGTH)
        .map(|_| CODE_ALPHABET[rng.gen_range(0..CODE_ALPHABET.len())] as char)
        .collect()
}

/// Accepts a bare code or anything ending in one, like a pasted link
/// ".../invite/AbCd234xyz".
fn normalize_code(input: &str) -> Option<String> {
    let code = input.trim().trim_end_matches('/').rsplit('/').next()?.trim();
    (code.len() == CODE_LENGTH && code.bytes().all(|b| CODE_ALPHABET.contains(&b))).then(|| code.to_string())
}

#[derive(Deserialize)]
pub struct CreateInviteRequest {
    /// Hours until the invite stops working; omit or null for never.
    pub expires_in_hours: Option<i64>,
    /// Number of joins allowed; omit or null for unlimited.
    pub max_uses: Option<i32>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Invite {
    pub code: String,
    pub server_id: Uuid,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub max_uses: Option<i32>,
    pub uses: i32,
}

/// Invites that can still be used.
const ACTIVE: &str = "i.revoked_at IS NULL AND (i.expires_at IS NULL OR i.expires_at > NOW()) AND (i.max_uses IS NULL OR i.uses < i.max_uses)";

async fn require_moderator(db: &Database, server_id: Uuid, user_id: Uuid) -> Result<(), AppError> {
    match member_rank(db, server_id, user_id).await? {
        Some(rank) if rank >= MODERATOR_RANK => Ok(()),
        Some(_) => Err(AppError::Forbidden("Only moderators and above can manage invites".into())),
        None => Err(AppError::Forbidden("You are not a member of this server".into())),
    }
}

/// POST /api/v1/servers/:server_id/invites
pub async fn create_invite(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
    Json(payload): Json<CreateInviteRequest>,
) -> Result<Json<Invite>, AppError> {
    require_moderator(&db, server_id, user_id).await?;

    if let Some(hours) = payload.expires_in_hours {
        if !(1..=MAX_EXPIRY_HOURS).contains(&hours) {
            return Err(AppError::BadRequest(format!("Expiry must be between 1 hour and {} days", MAX_EXPIRY_HOURS / 24)));
        }
    }
    if let Some(uses) = payload.max_uses {
        if !(1..=MAX_USES).contains(&uses) {
            return Err(AppError::BadRequest(format!("Max uses must be between 1 and {MAX_USES}")));
        }
    }

    // Codes are random; retry on the (very unlikely) collision.
    for _ in 0..5 {
        let result = sqlx::query_as::<_, Invite>(
            r#"
            WITH created AS (
                INSERT INTO server_invites (code, server_id, created_by, expires_at, max_uses)
                VALUES ($1, $2, $3, NOW() + make_interval(hours => $4::int), $5)
                RETURNING *
            )
            SELECT c.code, c.server_id, u.username AS created_by, c.created_at, c.expires_at, c.max_uses, c.uses
            FROM created c LEFT JOIN users u ON u.id = c.created_by
            "#,
        )
        .bind(new_code())
        .bind(server_id)
        .bind(user_id)
        .bind(payload.expires_in_hours.map(|h| h as i32))
        .bind(payload.max_uses)
        .fetch_one(&db.pool)
        .await;

        match result {
            Ok(invite) => return Ok(Json(invite)),
            Err(sqlx::Error::Database(d)) if d.is_unique_violation() => continue,
            Err(e) => return Err(AppError::Database(e.to_string())),
        }
    }
    Err(AppError::Internal("Couldn't generate an invite code".into()))
}

/// GET /api/v1/servers/:server_id/invites — invites that still work.
pub async fn list_invites(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
) -> Result<Json<Vec<Invite>>, AppError> {
    require_moderator(&db, server_id, user_id).await?;
    let invites: Vec<Invite> = sqlx::query_as(&format!(
        r#"
        SELECT i.code, i.server_id, u.username AS created_by, i.created_at, i.expires_at, i.max_uses, i.uses
        FROM server_invites i LEFT JOIN users u ON u.id = i.created_by
        WHERE i.server_id = $1 AND {ACTIVE}
        ORDER BY i.created_at DESC
        "#
    ))
    .bind(server_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(Json(invites))
}

/// DELETE /api/v1/servers/:server_id/invites/:code
pub async fn revoke_invite(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path((server_id, code)): Path<(Uuid, String)>,
) -> Result<StatusCode, AppError> {
    require_moderator(&db, server_id, user_id).await?;
    let revoked = sqlx::query(
        "UPDATE server_invites SET revoked_at = NOW() WHERE server_id = $1 AND code = $2 AND revoked_at IS NULL",
    )
    .bind(server_id)
    .bind(&code)
    .execute(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .rows_affected();
    if revoked == 0 {
        return Err(AppError::NotFound("Invite not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, sqlx::FromRow)]
pub struct InvitePreview {
    pub code: String,
    pub server_id: Uuid,
    pub server_name: String,
    pub member_count: i64,
    pub expires_at: Option<DateTime<Utc>>,
    pub already_member: bool,
}

fn invalid_invite() -> AppError {
    AppError::NotFound("This invite is invalid or has expired.".into())
}

/// GET /api/v1/invites/:code — what server an invite is for, before joining.
pub async fn preview_invite(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(code): Path<String>,
) -> Result<Json<InvitePreview>, AppError> {
    db.limits.hit(&INVITES_PER_USER, &user_id.to_string())?;
    let code = normalize_code(&code).ok_or_else(invalid_invite)?;

    let preview: Option<InvitePreview> = sqlx::query_as(&format!(
        r#"
        SELECT i.code, s.id AS server_id, s.name AS server_name,
               (SELECT COUNT(*) FROM server_members WHERE server_id = s.id) AS member_count,
               i.expires_at,
               EXISTS(SELECT 1 FROM server_members WHERE server_id = s.id AND user_id = $2) AS already_member
        FROM server_invites i JOIN servers s ON s.id = i.server_id
        WHERE i.code = $1 AND {ACTIVE}
        "#
    ))
    .bind(&code)
    .bind(user_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    preview.map(Json).ok_or_else(invalid_invite)
}

/// POST /api/v1/invites/:code — join the server. Returns the server.
pub async fn accept_invite(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
    Path(code): Path<String>,
) -> Result<Json<Server>, AppError> {
    db.limits.hit(&INVITES_PER_USER, &user_id.to_string())?;
    let code = normalize_code(&code).ok_or_else(invalid_invite)?;
    let db_err = |e: sqlx::Error| AppError::Database(e.to_string());

    let mut tx = db.pool.begin().await.map_err(db_err)?;

    // Lock the invite so two people can't both take its last use.
    let server_id: Option<Uuid> = sqlx::query_scalar(&format!(
        "SELECT i.server_id FROM server_invites i WHERE i.code = $1 AND {ACTIVE} FOR UPDATE"
    ))
    .bind(&code)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let server_id = server_id.ok_or_else(invalid_invite)?;

    let banned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM server_bans WHERE server_id = $1 AND user_id = $2)")
        .bind(server_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
    if banned {
        return Err(AppError::Forbidden("You are banned from this server.".into()));
    }

    // A brand-new account (different user_id) can't be matched above, but
    // if it's verified under an email that was already banned from this
    // server (see `members::ban_member`), it's almost certainly the same
    // person evading the ban -- block it the same way. A different real
    // email entirely isn't caught by this; that's a harder problem than an
    // email check alone can solve.
    let (email_hash, email_verified): (Option<String>, bool) =
        sqlx::query_as("SELECT email_hash, email_verified_at IS NOT NULL FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
    if !email_verified {
        return Err(AppError::Forbidden(
            "Verify your email before joining servers. Check your inbox for the verification link.".into(),
        ));
    }
    if let Some(email_hash) = email_hash {
        let email_banned: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM banned_emails WHERE server_id = $1 AND email_hash = $2)",
        )
        .bind(server_id)
        .bind(&email_hash)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
        if email_banned {
            return Err(AppError::Forbidden("You are banned from this server.".into()));
        }
    }

    let joined = sqlx::query(
        "INSERT INTO server_members (server_id, user_id, role) VALUES ($1, $2, 'member') ON CONFLICT (server_id, user_id) DO NOTHING",
    )
    .bind(server_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?
    .rows_affected()
        == 1;

    // Already a member: nothing to do, and don't use up the invite.
    if joined {
        sqlx::query("UPDATE server_invites SET uses = uses + 1 WHERE code = $1")
            .bind(&code)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
    }

    let mut server: Server = sqlx::query_as(
        "SELECT id, name, owner_id, created_at, icon_url, description FROM servers WHERE id = $1",
    )
    .bind(server_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;

    tx.commit().await.map_err(db_err)?;

    if joined {
        let _ = db.message_tx.send(BroadcastMessage::to_server(
            "member_joined",
            serde_json::json!({ "server_id": server_id, "user_id": user_id }),
            server_id,
        ));
    }

    sign_opt(&mut server.icon_url, user_id, session_id);
    Ok(Json(server))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_readable_and_parse_from_links() {
        let code = new_code();
        assert_eq!(code.len(), CODE_LENGTH);
        assert!(!code.contains(['0', 'O', '1', 'l', 'I']));
        assert_eq!(normalize_code(&code).as_deref(), Some(code.as_str()));
        assert_eq!(normalize_code(&format!("  https://example.com/invite/{code}/ ")).as_deref(), Some(code.as_str()));
        assert_eq!(normalize_code("short"), None);
        assert_eq!(normalize_code("0000000000"), None);
    }
}

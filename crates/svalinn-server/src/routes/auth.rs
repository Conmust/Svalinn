//! Registration, login and session tokens.
//!
//! A login session has two tokens:
//! - an **access token**: a JWT valid for 5 minutes, sent with every request;
//! - a **refresh token**: a random string valid for 90 days, used only to get
//!   new tokens from `POST /api/v1/auth/refresh`.
//!
//! Refresh tokens are stored hashed and rotated: each refresh returns a new
//! refresh token and retires the old one. The 90 days therefore count from the
//! last refresh. Presenting a retired token again means it was probably
//! copied, so the whole session (token family) is revoked.

use axum::{extract::State, http::StatusCode, Json};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use jsonwebtoken::{encode, Header, EncodingKey};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::jwt_secret;
use crate::sessions::AccessDenied;
use crate::models::user::{
    AuthResponse, Claims, LoginRequest, RefreshRequest, RegisterRequest, TokenResponse, User,
};

/// How long an access token (JWT) is valid.
pub const ACCESS_TOKEN_TTL_SECONDS: i64 = 5 * 60;
/// How long a refresh token is valid after it was issued.
pub const REFRESH_TOKEN_TTL_DAYS: i64 = 90;
/// A token replaced less than this long ago is treated as a harmless race (two
/// windows refreshing at once, or a retried request) rather than theft.
const REUSE_GRACE_SECONDS: i64 = 30;

pub async fn register(
    State(db): State<Database>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    // Validate input
    if payload.username.len() < 3 || payload.username.len() > 50 {
        return Err(AppError::BadRequest("Username must be 3-50 characters".into()));
    }
    if payload.password.len() < 6 {
        return Err(AppError::BadRequest("Password must be at least 6 characters".into()));
    }

    // Check if user already exists
    let existing: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE email = $1 OR username = $2"
    )
    .bind(&payload.email)
    .bind(&payload.username)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if existing > 0 {
        return Err(AppError::BadRequest("Email or username already exists".into()));
    }

    // Hash password
    let salt = SaltString::generate(&mut rand::thread_rng());
    let password_hash = Argon2::default()
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("Password hashing failed: {}", e)))?
        .to_string();

    // Insert user
    let user: User = sqlx::query_as(
        r#"
        INSERT INTO users (username, email, password_hash, display_name)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        "#
    )
    .bind(&payload.username)
    .bind(&payload.email)
    .bind(&password_hash)
    .bind(&payload.username)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    start_session(&db, user).await
}

pub async fn login(
    State(db): State<Database>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let user: User = sqlx::query_as("SELECT * FROM users WHERE email = $1")
        .bind(&payload.email)
        .fetch_optional(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::BadRequest("Invalid email or password".into()))?;

    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|e| AppError::Internal(format!("Invalid password hash: {}", e)))?;

    if Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return Err(AppError::BadRequest("Invalid email or password".into()));
    }

    // Only reveal a ban to someone who knows the password.
    let ban: Option<(Option<chrono::DateTime<Utc>>, Option<String>)> =
        sqlx::query_as("SELECT banned_at, ban_reason FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_optional(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    if let Some((Some(_), reason)) = ban {
        return Err(AppError::Forbidden(AccessDenied::Banned(reason).message()));
    }

    start_session(&db, user).await
}

/// POST /api/v1/auth/refresh  `{ "refresh_token": "..." }`
///
/// Returns a new access token and a new refresh token. The old refresh token
/// stops working.
pub async fn refresh(
    State(db): State<Database>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let token_hash = hash_token(&payload.refresh_token);
    let now = Utc::now();
    let db_err = |e: sqlx::Error| AppError::Database(e.to_string());

    let mut tx = db.pool.begin().await.map_err(db_err)?;

    // Lock the row so two refreshes with the same token can't both succeed.
    let row: Option<(Uuid, Uuid, Uuid, DateTime<Utc>, Option<DateTime<Utc>>, Option<DateTime<Utc>>)> =
        sqlx::query_as(
            r#"
            SELECT id, user_id, family_id, expires_at, revoked_at, replaced_at
            FROM refresh_tokens WHERE token_hash = $1
            FOR UPDATE
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;

    let Some((token_id, user_id, family_id, expires_at, revoked_at, replaced_at)) = row else {
        return Err(session_ended("Invalid refresh token. Please log in again."));
    };

    if revoked_at.is_some() {
        let recently_replaced =
            replaced_at.is_some_and(|at| now - at < Duration::seconds(REUSE_GRACE_SECONDS));
        if !recently_replaced {
            // An old token came back: assume it was stolen and end the session.
            revoke_family(&mut tx, family_id).await?;
            tx.commit().await.map_err(db_err)?;
            eprintln!("⚠️  Refresh token reused for user {user_id}; session {family_id} revoked");
        }
        // A ban revokes every session; say so rather than "session ended".
        if let Some(reason) = ban_reason_if_banned(&db, user_id).await? {
            return Err(session_ended(&AccessDenied::Banned(reason).message()));
        }
        return Err(session_ended("This session has ended. Please log in again."));
    }

    if expires_at <= now {
        return Err(session_ended("Your session has expired. Please log in again."));
    }

    let user: Option<(String, bool, Option<String>)> = sqlx::query_as(
        "SELECT username, banned_at IS NOT NULL, ban_reason FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;

    let Some((username, banned, ban_reason)) = user else {
        return Err(session_ended("Account no longer exists."));
    };
    if banned {
        revoke_family(&mut tx, family_id).await?;
        tx.commit().await.map_err(db_err)?;
        return Err(session_ended(&AccessDenied::Banned(ban_reason).message()));
    }

    // Rotate: retire the presented token and issue its replacement.
    sqlx::query("UPDATE refresh_tokens SET revoked_at = $1, replaced_at = $1 WHERE id = $2")
        .bind(now)
        .bind(token_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    let refresh_token = insert_refresh_token(&mut tx, user_id, family_id).await?;

    tx.commit().await.map_err(db_err)?;

    Ok(Json(TokenResponse {
        token: generate_jwt(user_id, &username, family_id)?,
        expires_in: ACCESS_TOKEN_TTL_SECONDS,
        refresh_token,
    }))
}

/// POST /api/v1/auth/logout  `{ "refresh_token": "..." }`
///
/// Ends the session the refresh token belongs to. Access tokens already
/// issued stay valid until they expire (at most 5 minutes).
pub async fn logout(
    State(db): State<Database>,
    Json(payload): Json<RefreshRequest>,
) -> Result<StatusCode, AppError> {
    let db_err = |e: sqlx::Error| AppError::Database(e.to_string());
    let mut tx = db.pool.begin().await.map_err(db_err)?;

    let family_id: Option<Uuid> =
        sqlx::query_scalar("SELECT family_id FROM refresh_tokens WHERE token_hash = $1")
            .bind(hash_token(&payload.refresh_token))
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;

    if let Some(family_id) = family_id {
        revoke_family(&mut tx, family_id).await?;
    }
    tx.commit().await.map_err(db_err)?;

    // Same response whether or not the token existed.
    Ok(StatusCode::NO_CONTENT)
}

/// Issues both tokens for a newly logged-in user, starting a new token family.
async fn start_session(db: &Database, user: User) -> Result<Json<AuthResponse>, AppError> {
    let db_err = |e: sqlx::Error| AppError::Database(e.to_string());
    let mut tx = db.pool.begin().await.map_err(db_err)?;

    // Housekeeping: expired tokens can't be used any more, so drop them.
    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1 AND expires_at < NOW()")
        .bind(user.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

    let session_id = Uuid::new_v4();
    let refresh_token = insert_refresh_token(&mut tx, user.id, session_id).await?;
    tx.commit().await.map_err(db_err)?;

    Ok(Json(AuthResponse {
        token: generate_jwt(user.id, &user.username, session_id)?,
        expires_in: ACCESS_TOKEN_TTL_SECONDS,
        refresh_token,
        user: user.into(),
    }))
}

async fn insert_refresh_token(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    family_id: Uuid,
) -> Result<String, AppError> {
    let token = new_refresh_token();
    sqlx::query(
        r#"
        INSERT INTO refresh_tokens (user_id, family_id, token_hash, expires_at)
        VALUES ($1, $2, $3, NOW() + make_interval(days => $4))
        "#,
    )
    .bind(user_id)
    .bind(family_id)
    .bind(hash_token(&token))
    .bind(REFRESH_TOKEN_TTL_DAYS as i32)
    .execute(&mut **tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(token)
}

async fn revoke_family(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    family_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE family_id = $1 AND revoked_at IS NULL")
        .bind(family_id)
        .execute(&mut **tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

/// `Some(reason)` if the user is banned (the reason itself may be empty).
async fn ban_reason_if_banned(db: &Database, user_id: Uuid) -> Result<Option<Option<String>>, AppError> {
    let row: Option<(bool, Option<String>)> =
        sqlx::query_as("SELECT banned_at IS NOT NULL, ban_reason FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(row.and_then(|(banned, reason)| banned.then_some(reason)))
}

fn session_ended(message: &str) -> AppError {
    AppError::Auth(message.into())
}

/// 256 random bits, hex encoded.
fn new_refresh_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    to_hex(&bytes)
}

/// Tokens are stored as SHA-256 hashes, so a database leak doesn't hand out
/// working tokens. A fast hash is fine here: the tokens are random, not passwords.
fn hash_token(token: &str) -> String {
    to_hex(&Sha256::digest(token.as_bytes()))
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn generate_jwt(user_id: Uuid, username: &str, session_id: Uuid) -> Result<String, AppError> {
    let expiration = (Utc::now() + Duration::seconds(ACCESS_TOKEN_TTL_SECONDS)).timestamp();

    let claims = Claims {
        sub: user_id,
        username: username.to_string(),
        exp: expiration as usize,
        sid: Some(session_id),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret()),
    )
    .map_err(|e| AppError::Internal(format!("JWT generation failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_tokens_are_random_and_hashed() {
        let a = new_refresh_token();
        let b = new_refresh_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert_eq!(hash_token(&a), hash_token(&a));
        assert_ne!(hash_token(&a), a);
    }
}

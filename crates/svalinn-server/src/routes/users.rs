use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;
use serde::Deserialize;
use uuid::Uuid;
use sqlx::FromRow;

use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::{CurrentSession, CurrentUser};
use crate::files::{sign_opt, stored_path};
use crate::models::user::{PublicUser, User};

#[derive(Deserialize)]
pub struct UpdatePatronRequest {
    pub patron_tier: String,
}

#[derive(Deserialize)]
pub struct AdminUpdatePatronRequest {
    pub user_id: Uuid,
    pub patron_tier: String,
}

#[derive(Deserialize)]
pub struct UpdateStatusRequest {
    pub status: String,
}

pub async fn get_all_users(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
) -> Result<Json<Vec<PublicUser>>, AppError> {
    let users: Vec<User> = sqlx::query_as(
        r#"
        SELECT id, username, email, password_hash, is_online, status, created_at, patron_tier, bio, public_key, avatar_url
        FROM users
        WHERE banned_at IS NULL
        ORDER BY username ASC
        "#,
    )
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Avatars are public to any logged-in viewer (see files.rs's access
    // check), but the link itself is still viewer-signed like any other
    // served file, so it has to be signed per request rather than once.
    let mut public_users: Vec<PublicUser> = users.into_iter().map(PublicUser::from).collect();
    for u in &mut public_users {
        sign_opt(&mut u.avatar_url, user_id, session_id);
    }
    Ok(Json(public_users))
}

pub async fn get_current_user(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
) -> Result<Json<PublicUser>, AppError> {
    let user: User = sqlx::query_as(
        r#"
        SELECT id, username, email, password_hash, is_online, status, created_at, patron_tier, bio, public_key, avatar_url
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut public_user = PublicUser::from(user);
    sign_opt(&mut public_user.avatar_url, user_id, session_id);
    Ok(Json(public_user))
}

pub async fn update_patron_tier(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
    Json(payload): Json<UpdatePatronRequest>,
) -> Result<Json<PublicUser>, AppError> {
    if !["free", "patron", "guild", "enterprise"].contains(&payload.patron_tier.as_str()) {
        return Err(AppError::BadRequest("Invalid patron tier".into()));
    }

    let user: User = sqlx::query_as(
        r#"
        UPDATE users
        SET patron_tier = $1
        WHERE id = $2
        RETURNING id, username, email, password_hash, is_online, status, created_at, patron_tier, bio, public_key, avatar_url
        "#,
    )
    .bind(&payload.patron_tier)
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut public_user = PublicUser::from(user);
    sign_opt(&mut public_user.avatar_url, user_id, session_id);
    Ok(Json(public_user))
}

#[derive(Deserialize)]
pub struct UpdateAvatarRequest {
    /// The `url` from `POST /api/v1/upload`, a signed file link, or an
    /// external image URL -- same flexibility `servers.icon_url` already
    /// has. `None`/omitted (or an empty string) clears the avatar back to
    /// the initial-letter default.
    #[serde(default)]
    pub avatar_url: Option<String>,
}

/// PATCH /api/v1/users/me/avatar
pub async fn update_avatar(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
    Json(payload): Json<UpdateAvatarRequest>,
) -> Result<Json<PublicUser>, AppError> {
    let avatar_url = payload.avatar_url.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(stored_path);

    // Reject a stored path that's already in use as a channel/DM attachment,
    // a custom emoji, or a server icon. Those are only visible to people who
    // share a server/conversation with the uploader; an avatar is visible to
    // every logged-in user (see `files::serve_file`'s avatar branch), so
    // accepting a path like that here -- which a legitimate recipient of
    // such a file could do just by knowing its name -- would make a private
    // file public for everyone, permanently, bypassing that access control.
    // A path not of ours (an external URL) or a freshly-uploaded one that
    // isn't referenced anywhere yet is unaffected.
    if let Some(path) = &avatar_url {
        if crate::files::is_stored_path(path)
            && crate::files::is_file_used_elsewhere(&db, path).await.map_err(|e| AppError::Database(e.to_string()))?
        {
            return Err(AppError::BadRequest(
                "That file is already in use elsewhere and can't be set as an avatar".into(),
            ));
        }
    }

    let user: User = sqlx::query_as(
        r#"
        UPDATE users
        SET avatar_url = $1
        WHERE id = $2
        RETURNING id, username, email, password_hash, is_online, status, created_at, patron_tier, bio, public_key, avatar_url
        "#,
    )
    .bind(&avatar_url)
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut public_user = PublicUser::from(user);
    sign_opt(&mut public_user.avatar_url, user_id, session_id);
    Ok(Json(public_user))
}

/// PATCH /api/v1/admin/patron-tier — site owners only.
pub async fn admin_update_patron_tier(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
    Json(payload): Json<AdminUpdatePatronRequest>,
) -> Result<Json<PublicUser>, AppError> {
    let is_site_owner: bool = sqlx::query_scalar(
        "SELECT COALESCE(site_role = 'owner', false) FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    if !is_site_owner {
        return Err(AppError::Forbidden(
            "Only site owners can change another user's patron tier".into(),
        ));
    }

    if !["free", "patron", "guild", "enterprise"].contains(&payload.patron_tier.as_str()) {
        return Err(AppError::BadRequest("Invalid patron tier".into()));
    }

    let user: User = sqlx::query_as(
        r#"
        UPDATE users
        SET patron_tier = $1
        WHERE id = $2
        RETURNING id, username, email, password_hash, is_online, status, created_at, patron_tier, bio, public_key, avatar_url
        "#,
    )
    .bind(&payload.patron_tier)
    .bind(payload.user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut public_user = PublicUser::from(user);
    sign_opt(&mut public_user.avatar_url, user_id, session_id);
    Ok(Json(public_user))
}

pub async fn update_status(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Json(payload): Json<UpdateStatusRequest>,
) -> Result<Json<PublicUser>, AppError> {
    let valid_statuses = ["online", "idle", "busy", "away", "invisible", "offline"];
    if !valid_statuses.contains(&payload.status.as_str()) {
        return Err(AppError::BadRequest("Invalid status".into()));
    }

    let is_online = !matches!(payload.status.as_str(), "offline" | "invisible");

    let user: User = sqlx::query_as(
        r#"
        UPDATE users
        SET status = $1, is_online = $2, last_activity = CURRENT_TIMESTAMP
        WHERE id = $3
        RETURNING id, username, email, password_hash, is_online, status, created_at, patron_tier, bio, public_key, avatar_url
        "#,
    )
    .bind(&payload.status)
    .bind(is_online)
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let visible = if is_online { payload.status.as_str() } else { "offline" };
    crate::presence::broadcast_status(&db, user_id, visible).await;

    Ok(Json(PublicUser::from(user)))
}

/// Decoded length of a valid X25519 public key, in bytes.
const PUBLIC_KEY_BYTES: usize = 32;

#[derive(Deserialize)]
pub struct UpdatePublicKeyRequest {
    pub public_key: String,
}

/// PATCH /api/v1/users/me/public-key
///
/// Sets (overwriting any existing value) the base64-encoded X25519 public
/// key for the current user's device, used for end-to-end encrypting direct
/// messages. The server only ever stores/relays this public key -- it never
/// sees the matching private key.
///
/// Single-device model: uploading a new key replaces the old one outright.
/// There's no multi-device key management here (e.g. keeping multiple
/// devices' keys, or letting a device trust another device's key) -- that's
/// out of scope for this pass.
pub async fn update_public_key(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Json(payload): Json<UpdatePublicKeyRequest>,
) -> Result<Json<PublicUser>, AppError> {
    use base64::Engine;

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(payload.public_key.trim())
        .map_err(|_| AppError::BadRequest("public_key must be valid base64".into()))?;
    if decoded.len() != PUBLIC_KEY_BYTES {
        return Err(AppError::BadRequest(format!(
            "public_key must decode to exactly {PUBLIC_KEY_BYTES} bytes (an X25519 public key)"
        )));
    }

    let user: User = sqlx::query_as(
        r#"
        UPDATE users
        SET public_key = $1
        WHERE id = $2
        RETURNING id, username, email, password_hash, is_online, status, created_at, patron_tier, bio, public_key, avatar_url
        "#,
    )
    .bind(payload.public_key.trim())
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(PublicUser::from(user)))
}

pub async fn heartbeat(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
) -> Result<Json<()>, AppError> {
    sqlx::query("UPDATE users SET last_activity = CURRENT_TIMESTAMP WHERE id = $1")
        .bind(user_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(()))
}

// ... (keep your existing user functions above this) ...

#[derive(Serialize, FromRow)]
pub struct UserProfile {
    pub id: Uuid,
    pub username: String,
    pub patron_tier: Option<String>,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub avatar_url: Option<String>,
    /// The viewer's nickname for this user in `server_id`, if that query
    /// param was given and the viewer is actually a member there -- NULL
    /// otherwise, including when no nickname is set.
    pub nickname: Option<String>,
}

#[derive(Deserialize)]
pub struct UserProfileQuery {
    /// Optional: when the profile is opened from within a server (e.g. the
    /// member roster), pass that server's id so the response can include
    /// this user's nickname there.
    pub server_id: Option<Uuid>,
}

pub async fn get_user_profile(
    State(db): State<Database>,
    CurrentSession { user_id: caller_id, session_id }: CurrentSession,
    Path(user_id): Path<Uuid>,
    axum::extract::Query(query): axum::extract::Query<UserProfileQuery>,
) -> Result<Json<UserProfile>, AppError> {
    // Only honor server_id if the caller is actually a member there --
    // otherwise this would let anyone probe which servers a user belongs to
    // one guess at a time by checking whether a nickname comes back.
    let server_id = match query.server_id {
        Some(id) if crate::access::require_member(&db, id, caller_id).await.is_ok() => Some(id),
        _ => None,
    };

    let user: Option<UserProfile> = sqlx::query_as(
        r#"
        SELECT u.id, u.username, u.patron_tier, u.status, u.created_at, u.avatar_url,
               sm.nickname
        FROM users u
        LEFT JOIN server_members sm ON sm.server_id = $2 AND sm.user_id = u.id
        WHERE u.id = $1
        "#,
    )
    .bind(user_id)
    .bind(server_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    match user {
        Some(mut u) => {
            sign_opt(&mut u.avatar_url, caller_id, session_id);
            Ok(Json(u))
        }
        None => Err(AppError::NotFound("User not found".into())),
    }
}
// ---------- Account settings ----------

use crate::rate_limit::REAUTH_FAILURES_PER_USER;

#[derive(Serialize)]
pub struct Account {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub is_site_owner: bool,
}

/// GET /api/v1/users/me/account — private details for the account settings screen.
pub async fn get_account(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
) -> Result<Json<Account>, AppError> {
    let (username, email, is_site_owner): (String, String, bool) = sqlx::query_as(
        "SELECT username, email, COALESCE(site_role = 'owner', false) FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(Json(Account { id: user_id, username, email, is_site_owner }))
}

/// Checks the user's current password before a sensitive change. Wrong
/// guesses are rate limited per user.
pub(crate) async fn verify_current_password(db: &Database, user_id: Uuid, password: &str) -> Result<(), AppError> {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};

    let key = user_id.to_string();
    db.limits.check(&REAUTH_FAILURES_PER_USER, &key)?;

    let hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    let parsed = PasswordHash::new(&hash).map_err(|e| AppError::Internal(format!("Invalid password hash: {e}")))?;

    if Argon2::default().verify_password(password.as_bytes(), &parsed).is_err() {
        db.limits.record(&REAUTH_FAILURES_PER_USER, &key);
        return Err(AppError::BadRequest("Your current password is incorrect".into()));
    }
    db.limits.reset(&REAUTH_FAILURES_PER_USER, &key);
    Ok(())
}

#[derive(Deserialize)]
pub struct ChangeEmailRequest {
    pub email: String,
    pub current_password: String,
}

/// PATCH /api/v1/users/me/email
pub async fn change_email(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Json(payload): Json<ChangeEmailRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let email = payload.email.trim();
    let valid = email.len() <= 255
        && email.split_once('@').is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.'))
        && !email.contains(char::is_whitespace);
    if !valid {
        return Err(AppError::BadRequest("Enter a valid email address".into()));
    }

    verify_current_password(&db, user_id, &payload.current_password).await?;

    sqlx::query("UPDATE users SET email = $1, updated_at = NOW() WHERE id = $2")
        .bind(email)
        .bind(user_id)
        .execute(&db.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(d) if d.is_unique_violation() => AppError::BadRequest("That email is already in use".into()),
            e => AppError::Database(e.to_string()),
        })?;

    Ok(Json(serde_json::json!({ "email": email })))
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// PUT /api/v1/users/me/password — also logs out every other device.
pub async fn change_password(
    State(db): State<Database>,
    CurrentSession { user_id, session_id }: CurrentSession,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    use argon2::password_hash::{PasswordHasher, SaltString};

    if payload.new_password.len() < 6 {
        return Err(AppError::BadRequest("New password must be at least 6 characters".into()));
    }
    if payload.new_password == payload.current_password {
        return Err(AppError::BadRequest("Choose a password different from your current one".into()));
    }

    verify_current_password(&db, user_id, &payload.current_password).await?;

    let salt = SaltString::generate(&mut rand::thread_rng());
    let hash = argon2::Argon2::default()
        .hash_password(payload.new_password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("Password hashing failed: {e}")))?
        .to_string();

    let mut tx = db.pool.begin().await.map_err(|e| AppError::Database(e.to_string()))?;
    sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
        .bind(&hash)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    // End every other session; the database tells running servers to close
    // those connections straight away.
    let ended = sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND family_id <> $2 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .bind(session_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .rows_affected();
    tx.commit().await.map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({ "other_sessions_ended": ended })))
}

// ---------- Passphrase-based key recovery backup ----------
//
// Opt-in only: a user who never calls `PUT .../key-backup` has a row here
// that never exists, and every other code path (new-device key generation,
// message encryption/decryption) is completely unaffected. The server only
// ever stores/relays the opaque blob the client already encrypted --
// `encrypted_blob`/`salt`/`kdf_params` are never used here to derive or
// inspect anything, and the passphrase itself and the derived symmetric key
// never appear in any request this server handles.

/// A few KB is generously more than enough for one passphrase-encrypted
/// X25519 private key (32 raw bytes, base64'd, plus a small JSON envelope
/// and libsodium's secretbox overhead) -- this is just a ceiling to reject
/// abuse, not a realistic size.
const MAX_KEY_BACKUP_BLOB_CHARS: usize = 8192;
const MAX_KEY_BACKUP_SALT_CHARS: usize = 512;
const MAX_KEY_BACKUP_KDF_PARAMS_CHARS: usize = 1024;

/// `kdf_params` is opaque in the sense that this server never uses it to
/// derive or inspect anything (see the comment above) -- but it IS stored
/// and relayed back verbatim, and by the time any check runs here axum's
/// `Json` extractor has already fully parsed whatever shape of JSON the
/// caller sent. The size cap above keeps a wildly oversized body from
/// getting this far at all; this check goes further and pins the actual
/// SHAPE down to exactly what `apps/desktop/src/lib/recovery.ts`'s
/// `KdfParams` sends -- a flat object with only `algorithm` (a string),
/// `opslimit`/`memlimit` (required numbers) and an optional `version`
/// number -- so nothing else (nested objects/arrays, unexpected keys,
/// wrong types for a known key) is ever accepted or stored, rather than
/// trusting an arbitrary `serde_json::Value`.
fn validate_kdf_params(value: &serde_json::Value) -> Result<(), AppError> {
    const REQUIRED_STRING_KEYS: &[&str] = &["algorithm"];
    const REQUIRED_NUMBER_KEYS: &[&str] = &["opslimit", "memlimit"];
    const OPTIONAL_NUMBER_KEYS: &[&str] = &["version"];

    let obj = value
        .as_object()
        .ok_or_else(|| AppError::BadRequest("kdf_params must be a flat JSON object".into()))?;

    for (key, val) in obj {
        if REQUIRED_STRING_KEYS.contains(&key.as_str()) {
            if !val.is_string() {
                return Err(AppError::BadRequest(format!("kdf_params.{key} must be a string")));
            }
        } else if REQUIRED_NUMBER_KEYS.contains(&key.as_str()) || OPTIONAL_NUMBER_KEYS.contains(&key.as_str()) {
            if !val.is_number() {
                return Err(AppError::BadRequest(format!("kdf_params.{key} must be a number")));
            }
        } else {
            return Err(AppError::BadRequest(format!(
                "kdf_params has an unexpected field: {key}"
            )));
        }
    }

    for required in REQUIRED_STRING_KEYS.iter().chain(REQUIRED_NUMBER_KEYS.iter()) {
        if !obj.contains_key(*required) {
            return Err(AppError::BadRequest(format!(
                "kdf_params is missing required field: {required}"
            )));
        }
    }

    Ok(())
}

#[derive(Deserialize)]
pub struct PutKeyBackupRequest {
    pub encrypted_blob: String,
    pub salt: String,
    pub kdf_params: serde_json::Value,
}

#[derive(Debug, Serialize, FromRow)]
pub struct KeyBackup {
    pub encrypted_blob: String,
    pub salt: String,
    pub kdf_params: serde_json::Value,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// PUT /api/v1/users/me/key-backup
///
/// Upserts (inserts, or replaces if one already exists) the caller's OWN
/// recovery backup. There is at most one backup per user (see migration
/// 0031) -- a second `PUT` overwrites the first outright rather than
/// keeping both, which is an accepted limitation of this simple one-slot
/// design (only one device's key can usefully be backed up at a time).
pub async fn put_key_backup(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Json(payload): Json<PutKeyBackupRequest>,
) -> Result<Json<KeyBackup>, AppError> {
    let blob = payload.encrypted_blob.trim();
    if blob.is_empty() {
        return Err(AppError::BadRequest("encrypted_blob is required".into()));
    }
    if blob.len() > MAX_KEY_BACKUP_BLOB_CHARS {
        return Err(AppError::BadRequest(format!(
            "encrypted_blob can be at most {MAX_KEY_BACKUP_BLOB_CHARS} characters"
        )));
    }

    let salt = payload.salt.trim();
    if salt.is_empty() {
        return Err(AppError::BadRequest("salt is required".into()));
    }
    if salt.len() > MAX_KEY_BACKUP_SALT_CHARS {
        return Err(AppError::BadRequest(format!(
            "salt can be at most {MAX_KEY_BACKUP_SALT_CHARS} characters"
        )));
    }

    if payload.kdf_params.is_null() {
        return Err(AppError::BadRequest("kdf_params is required".into()));
    }
    if payload.kdf_params.to_string().len() > MAX_KEY_BACKUP_KDF_PARAMS_CHARS {
        return Err(AppError::BadRequest("kdf_params is too large".into()));
    }
    validate_kdf_params(&payload.kdf_params)?;

    let backup: KeyBackup = sqlx::query_as(
        r#"
        INSERT INTO key_backups (user_id, encrypted_blob, salt, kdf_params)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (user_id) DO UPDATE
            SET encrypted_blob = EXCLUDED.encrypted_blob,
                salt = EXCLUDED.salt,
                kdf_params = EXCLUDED.kdf_params,
                updated_at = NOW()
        RETURNING encrypted_blob, salt, kdf_params, updated_at
        "#,
    )
    .bind(user_id)
    .bind(blob)
    .bind(salt)
    .bind(&payload.kdf_params)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(backup))
}

/// GET /api/v1/users/me/key-backup
///
/// Returns the caller's OWN backup, or 404 if they don't have one. Scoped
/// to `CurrentUser` exactly like the device endpoints -- there is no way to
/// fetch another user's backup through this handler, since the query is
/// always `WHERE user_id = <the authenticated caller>`, never a
/// caller-supplied id.
pub async fn get_key_backup(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
) -> Result<Json<KeyBackup>, AppError> {
    let backup: Option<KeyBackup> = sqlx::query_as(
        "SELECT encrypted_blob, salt, kdf_params, updated_at FROM key_backups WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    backup.map(Json).ok_or_else(|| AppError::NotFound("No key backup set up".into()))
}

/// DELETE /api/v1/users/me/key-backup
///
/// Removes the caller's own backup, e.g. if they no longer want this
/// recovery option enabled. Idempotent-ish: deleting when none exists is
/// treated as success (204) rather than an error, since the end state the
/// caller wants ("no backup exists") is already true.
pub async fn delete_key_backup(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
) -> Result<axum::http::StatusCode, AppError> {
    sqlx::query("DELETE FROM key_backups WHERE user_id = $1")
        .bind(user_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Inserts a throwaway non-site-owner user with a randomly-generated
    /// unique username/email, so concurrent/test runs never collide. The
    /// password hash is a dummy value: these users never log in.
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

    /// Like `create_test_user`, but sets `site_role = 'owner'` directly via
    /// SQL (see migrations/0026_site_owner.sql), matching how
    /// `svalinn-admin set-site-owner` promotes an account in production.
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

    /// Deletes a test user by id. Best-effort / happy-path only: called at
    /// the end of each test's function body, so a panicking `assert!`
    /// earlier in the test will skip it and leave that test's row behind.
    async fn cleanup_test_user(db: &Database, user_id: Uuid) {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1").bind(user_id).execute(&db.pool).await;
    }

    #[tokio::test]
    async fn non_site_owner_is_forbidden_from_admin_patron_tier() {
        let db = test_db().await;
        let caller = create_test_user(&db).await;
        let target = create_test_user(&db).await;

        let result = admin_update_patron_tier(
            State(db.clone()),
            CurrentSession { user_id: caller, session_id: Uuid::new_v4() },
            Json(AdminUpdatePatronRequest { user_id: target, patron_tier: "enterprise".into() }),
        )
        .await;

        match result {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected AppError::Forbidden for a non-site-owner caller, got {other:?}"),
        }

        let patron_tier: String =
            sqlx::query_scalar("SELECT patron_tier FROM users WHERE id = $1").bind(target).fetch_one(&db.pool).await.expect("fetching target's patron_tier failed");
        assert_eq!(patron_tier, "free", "a forbidden call must not change the target's patron tier");

        cleanup_test_user(&db, caller).await;
        cleanup_test_user(&db, target).await;
    }

    #[tokio::test]
    async fn site_owner_can_update_another_users_patron_tier() {
        let db = test_db().await;
        let owner = create_test_site_owner(&db).await;
        let target = create_test_user(&db).await;

        let result = admin_update_patron_tier(
            State(db.clone()),
            CurrentSession { user_id: owner, session_id: Uuid::new_v4() },
            Json(AdminUpdatePatronRequest { user_id: target, patron_tier: "patron".into() }),
        )
        .await
        .expect("a site owner should be able to update another user's patron tier");

        assert_eq!(result.0.patron_tier, "patron");

        let patron_tier: String =
            sqlx::query_scalar("SELECT patron_tier FROM users WHERE id = $1").bind(target).fetch_one(&db.pool).await.expect("fetching target's patron_tier failed");
        assert_eq!(patron_tier, "patron", "the database row should reflect the update");

        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, target).await;
    }

    #[tokio::test]
    async fn self_service_update_patron_tier_changes_own_tier() {
        let db = test_db().await;
        let user = create_test_user(&db).await;

        let result = update_patron_tier(
            State(db.clone()),
            CurrentSession { user_id: user, session_id: Uuid::new_v4() },
            Json(UpdatePatronRequest { patron_tier: "guild".into() }),
        )
        .await
        .expect("a user should be able to set their own patron tier");

        assert_eq!(result.0.patron_tier, "guild");

        let patron_tier: String =
            sqlx::query_scalar("SELECT patron_tier FROM users WHERE id = $1").bind(user).fetch_one(&db.pool).await.expect("fetching the user's patron_tier failed");
        assert_eq!(patron_tier, "guild", "the database row should reflect the self-service update");

        cleanup_test_user(&db, user).await;
    }

    #[tokio::test]
    async fn self_service_update_patron_tier_rejects_unknown_tier() {
        let db = test_db().await;
        let user = create_test_user(&db).await;

        let result = update_patron_tier(
            State(db.clone()),
            CurrentSession { user_id: user, session_id: Uuid::new_v4() },
            Json(UpdatePatronRequest { patron_tier: "super-ultra-vip".into() }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for an unknown tier, got {other:?}"),
        }

        let patron_tier: String =
            sqlx::query_scalar("SELECT patron_tier FROM users WHERE id = $1").bind(user).fetch_one(&db.pool).await.expect("fetching the user's patron_tier failed");
        assert_eq!(patron_tier, "free", "a rejected tier name must not change the stored value");

        cleanup_test_user(&db, user).await;
    }

    #[tokio::test]
    async fn self_service_update_patron_tier_cannot_target_another_user() {
        // There's no `user_id` field on `UpdatePatronRequest` at all -- unlike
        // `admin_update_patron_tier`, the self-service endpoint always acts on
        // the caller's own `CurrentUser` id, so there's no request field that
        // could let one user change another's tier. This test pins that
        // shape down: if a `user_id` field is ever added to
        // `UpdatePatronRequest`, this won't catch a regression, but changing
        // who it updates without changing the type would fail to compile
        // against the call in `update_patron_tier`'s body.
        let db = test_db().await;
        let caller = create_test_user(&db).await;
        let other = create_test_user(&db).await;

        let _ = update_patron_tier(
            State(db.clone()),
            CurrentSession { user_id: caller, session_id: Uuid::new_v4() },
            Json(UpdatePatronRequest { patron_tier: "patron".into() }),
        )
        .await
        .expect("updating the caller's own tier should succeed");

        let other_tier: String =
            sqlx::query_scalar("SELECT patron_tier FROM users WHERE id = $1").bind(other).fetch_one(&db.pool).await.expect("fetching the other user's patron_tier failed");
        assert_eq!(other_tier, "free", "updating the caller's tier must not affect a different user's row");

        cleanup_test_user(&db, caller).await;
        cleanup_test_user(&db, other).await;
    }

    #[tokio::test]
    async fn get_user_profile_returns_expected_fields() {
        let db = test_db().await;
        let viewer = create_test_user(&db).await;
        let target = create_test_user(&db).await;

        let profile = get_user_profile(
            State(db.clone()),
            CurrentSession { user_id: viewer, session_id: Uuid::new_v4() },
            Path(target),
            axum::extract::Query(UserProfileQuery { server_id: None }),
        )
            .await
            .expect("fetching an existing user's profile should succeed");

        assert_eq!(profile.0.id, target);
        assert_eq!(profile.0.patron_tier, Some("free".to_string()));
        assert_eq!(profile.0.status, "offline");

        cleanup_test_user(&db, viewer).await;
        cleanup_test_user(&db, target).await;
    }

    #[tokio::test]
    async fn key_backup_upsert_replaces_previous_backup() {
        let db = test_db().await;
        let user = create_test_user(&db).await;

        let first = put_key_backup(
            State(db.clone()),
            CurrentUser(user),
            Json(PutKeyBackupRequest {
                encrypted_blob: "first-blob".into(),
                salt: "first-salt".into(),
                kdf_params: serde_json::json!({"algorithm": "argon2id13", "opslimit": 3, "memlimit": 268435456}),
            }),
        )
        .await
        .expect("creating a key backup should succeed")
        .0;
        assert_eq!(first.encrypted_blob, "first-blob");

        let fetched = get_key_backup(State(db.clone()), CurrentUser(user))
            .await
            .expect("fetching the backup should succeed")
            .0;
        assert_eq!(fetched.encrypted_blob, "first-blob");

        let second = put_key_backup(
            State(db.clone()),
            CurrentUser(user),
            Json(PutKeyBackupRequest {
                encrypted_blob: "second-blob".into(),
                salt: "second-salt".into(),
                kdf_params: serde_json::json!({"algorithm": "argon2id13", "opslimit": 3, "memlimit": 268435456}),
            }),
        )
        .await
        .expect("replacing a key backup should succeed")
        .0;
        assert_eq!(second.encrypted_blob, "second-blob");

        let refetched = get_key_backup(State(db.clone()), CurrentUser(user))
            .await
            .expect("fetching the backup should succeed")
            .0;
        assert_eq!(refetched.encrypted_blob, "second-blob", "a second PUT must replace, not duplicate, the backup");
        assert_eq!(refetched.salt, "second-salt");

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM key_backups WHERE user_id = $1")
            .bind(user)
            .fetch_one(&db.pool)
            .await
            .expect("counting backups failed");
        assert_eq!(count, 1, "there must only ever be one backup row per user");

        cleanup_test_user(&db, user).await;
    }

    #[tokio::test]
    async fn get_key_backup_returns_not_found_when_none_exists() {
        let db = test_db().await;
        let user = create_test_user(&db).await;

        let result = get_key_backup(State(db.clone()), CurrentUser(user)).await;
        match result {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected AppError::NotFound when no backup exists, got {other:?}"),
        }

        cleanup_test_user(&db, user).await;
    }

    #[tokio::test]
    async fn cannot_fetch_another_users_key_backup() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let other = create_test_user(&db).await;

        let _ = put_key_backup(
            State(db.clone()),
            CurrentUser(owner),
            Json(PutKeyBackupRequest {
                encrypted_blob: "owners-blob".into(),
                salt: "owners-salt".into(),
                kdf_params: serde_json::json!({"algorithm": "argon2id13", "opslimit": 3, "memlimit": 268435456}),
            }),
        )
        .await
        .expect("creating a key backup should succeed");

        // `other` fetching "their own" backup (there is no way to pass
        // `owner`'s id in -- CurrentUser always scopes to the caller) must
        // see "no backup", never the owner's.
        let result = get_key_backup(State(db.clone()), CurrentUser(other)).await;
        match result {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected AppError::NotFound for a user with no backup of their own, got {other:?}"),
        }

        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, other).await;
    }

    #[tokio::test]
    async fn delete_key_backup_removes_it_and_is_idempotent() {
        let db = test_db().await;
        let user = create_test_user(&db).await;

        let _ = put_key_backup(
            State(db.clone()),
            CurrentUser(user),
            Json(PutKeyBackupRequest {
                encrypted_blob: "a-blob".into(),
                salt: "a-salt".into(),
                kdf_params: serde_json::json!({"algorithm": "argon2id13", "opslimit": 3, "memlimit": 268435456}),
            }),
        )
        .await
        .expect("creating a key backup should succeed");

        let status = delete_key_backup(State(db.clone()), CurrentUser(user))
            .await
            .expect("deleting own backup should succeed");
        assert_eq!(status, axum::http::StatusCode::NO_CONTENT);

        let result = get_key_backup(State(db.clone()), CurrentUser(user)).await;
        match result {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected AppError::NotFound after deletion, got {other:?}"),
        }

        // Deleting again (no backup left) should still succeed, not error.
        let status_again = delete_key_backup(State(db.clone()), CurrentUser(user))
            .await
            .expect("deleting when no backup exists should still succeed");
        assert_eq!(status_again, axum::http::StatusCode::NO_CONTENT);

        cleanup_test_user(&db, user).await;
    }

    #[tokio::test]
    async fn put_key_backup_rejects_empty_fields() {
        let db = test_db().await;
        let user = create_test_user(&db).await;

        let result = put_key_backup(
            State(db.clone()),
            CurrentUser(user),
            Json(PutKeyBackupRequest {
                encrypted_blob: "   ".into(),
                salt: "some-salt".into(),
                kdf_params: serde_json::json!({"algorithm": "argon2id13"}),
            }),
        )
        .await;
        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for an empty encrypted_blob, got {other:?}"),
        }

        let result = put_key_backup(
            State(db.clone()),
            CurrentUser(user),
            Json(PutKeyBackupRequest {
                encrypted_blob: "a-blob".into(),
                salt: "   ".into(),
                kdf_params: serde_json::json!({"algorithm": "argon2id13"}),
            }),
        )
        .await;
        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for an empty salt, got {other:?}"),
        }

        let result = put_key_backup(
            State(db.clone()),
            CurrentUser(user),
            Json(PutKeyBackupRequest {
                encrypted_blob: "a-blob".into(),
                salt: "a-salt".into(),
                kdf_params: serde_json::Value::Null,
            }),
        )
        .await;
        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for null kdf_params, got {other:?}"),
        }

        cleanup_test_user(&db, user).await;
    }

    #[tokio::test]
    async fn put_key_backup_rejects_malformed_kdf_params_shape() {
        let db = test_db().await;
        let user = create_test_user(&db).await;

        // Not an object at all.
        let result = put_key_backup(
            State(db.clone()),
            CurrentUser(user),
            Json(PutKeyBackupRequest {
                encrypted_blob: "a-blob".into(),
                salt: "a-salt".into(),
                kdf_params: serde_json::json!("argon2id13"),
            }),
        )
        .await;
        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for a non-object kdf_params, got {other:?}"),
        }

        // Missing a required field.
        let result = put_key_backup(
            State(db.clone()),
            CurrentUser(user),
            Json(PutKeyBackupRequest {
                encrypted_blob: "a-blob".into(),
                salt: "a-salt".into(),
                kdf_params: serde_json::json!({"algorithm": "argon2id13", "opslimit": 3}),
            }),
        )
        .await;
        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for kdf_params missing memlimit, got {other:?}"),
        }

        // An unexpected extra field.
        let result = put_key_backup(
            State(db.clone()),
            CurrentUser(user),
            Json(PutKeyBackupRequest {
                encrypted_blob: "a-blob".into(),
                salt: "a-salt".into(),
                kdf_params: serde_json::json!({
                    "algorithm": "argon2id13",
                    "opslimit": 3,
                    "memlimit": 268435456,
                    "nested": {"not": "expected"},
                }),
            }),
        )
        .await;
        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for kdf_params with an unexpected field, got {other:?}"),
        }

        // Right keys, wrong type.
        let result = put_key_backup(
            State(db.clone()),
            CurrentUser(user),
            Json(PutKeyBackupRequest {
                encrypted_blob: "a-blob".into(),
                salt: "a-salt".into(),
                kdf_params: serde_json::json!({
                    "algorithm": "argon2id13",
                    "opslimit": "3",
                    "memlimit": 268435456,
                }),
            }),
        )
        .await;
        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for opslimit as a string, got {other:?}"),
        }

        // A well-formed shape (with the optional `version` field) must
        // still succeed.
        let ok = put_key_backup(
            State(db.clone()),
            CurrentUser(user),
            Json(PutKeyBackupRequest {
                encrypted_blob: "a-blob".into(),
                salt: "a-salt".into(),
                kdf_params: serde_json::json!({
                    "algorithm": "argon2id13",
                    "opslimit": 3,
                    "memlimit": 268435456,
                    "version": 1,
                }),
            }),
        )
        .await;
        assert!(ok.is_ok(), "a well-formed kdf_params shape should still be accepted: {ok:?}");

        cleanup_test_user(&db, user).await;
    }

    #[tokio::test]
    async fn update_avatar_sets_and_clears_and_response_is_signed() {
        let db = test_db().await;
        let user = create_test_user(&db).await;

        let set = update_avatar(
            State(db.clone()),
            CurrentSession { user_id: user, session_id: Uuid::new_v4() },
            Json(UpdateAvatarRequest { avatar_url: Some("/uploads/avatar123.png".into()) }),
        )
        .await
        .expect("setting an avatar should succeed");
        // The response is signed for the viewer (query params attached),
        // not the bare stored path.
        assert!(set.0.avatar_url.as_deref().unwrap_or("").starts_with("/api/v1/files/avatar123.png"));

        let stored: Option<String> =
            sqlx::query_scalar("SELECT avatar_url FROM users WHERE id = $1").bind(user).fetch_one(&db.pool).await.expect("fetching stored avatar_url failed");
        assert_eq!(stored, Some("/uploads/avatar123.png".to_string()), "the DB should hold the canonical unsigned path");

        let cleared = update_avatar(
            State(db.clone()),
            CurrentSession { user_id: user, session_id: Uuid::new_v4() },
            Json(UpdateAvatarRequest { avatar_url: None }),
        )
        .await
        .expect("clearing an avatar should succeed");
        assert_eq!(cleared.0.avatar_url, None);

        let stored_after_clear: Option<String> =
            sqlx::query_scalar("SELECT avatar_url FROM users WHERE id = $1").bind(user).fetch_one(&db.pool).await.expect("fetching stored avatar_url failed");
        assert_eq!(stored_after_clear, None);

        cleanup_test_user(&db, user).await;
    }

    #[tokio::test]
    async fn update_avatar_accepts_an_external_url_unsigned() {
        let db = test_db().await;
        let user = create_test_user(&db).await;

        let result = update_avatar(
            State(db.clone()),
            CurrentSession { user_id: user, session_id: Uuid::new_v4() },
            Json(UpdateAvatarRequest { avatar_url: Some("https://example.invalid/pic.png".into()) }),
        )
        .await
        .expect("an external avatar URL should be accepted, same as servers' icon_url");
        assert_eq!(result.0.avatar_url, Some("https://example.invalid/pic.png".to_string()), "an external URL is returned as-is, not signed");

        cleanup_test_user(&db, user).await;
    }

    #[tokio::test]
    async fn update_avatar_rejects_a_path_already_used_as_a_private_dm_attachment() {
        // A user who legitimately receives a private DM attachment knows
        // its exact `/uploads/<name>` path. Setting that same path as their
        // own avatar must be rejected -- otherwise it would become globally
        // visible via `files::serve_file`'s avatar branch, bypassing the DM
        // participant check that's supposed to gate it.
        let db = test_db().await;
        let sender = create_test_user(&db).await;
        let recipient = create_test_user(&db).await;

        let conversation_id: Uuid = sqlx::query_scalar("INSERT INTO conversations DEFAULT VALUES RETURNING id")
            .fetch_one(&db.pool)
            .await
            .expect("failed to insert test conversation");
        sqlx::query("INSERT INTO conversation_participants (conversation_id, user_id) VALUES ($1, $2), ($1, $3)")
            .bind(conversation_id)
            .bind(sender)
            .bind(recipient)
            .execute(&db.pool)
            .await
            .expect("failed to insert test participants");
        let private_path = format!("/uploads/private_{}.png", Uuid::new_v4());
        sqlx::query("INSERT INTO messages (conversation_id, user_id, content, attachment_url) VALUES ($1, $2, $3, $4)")
            .bind(conversation_id)
            .bind(sender)
            .bind("")
            .bind(&private_path)
            .execute(&db.pool)
            .await
            .expect("failed to insert test DM attachment message");

        let result = update_avatar(
            State(db.clone()),
            CurrentSession { user_id: recipient, session_id: Uuid::new_v4() },
            Json(UpdateAvatarRequest { avatar_url: Some(private_path.clone()) }),
        )
        .await;
        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for a path already used as a DM attachment, got {other:?}"),
        }

        let stored: Option<String> =
            sqlx::query_scalar("SELECT avatar_url FROM users WHERE id = $1").bind(recipient).fetch_one(&db.pool).await.expect("fetching stored avatar_url failed");
        assert_eq!(stored, None, "a rejected avatar path must not be stored");

        cleanup_test_user(&db, sender).await;
        cleanup_test_user(&db, recipient).await;
    }

    #[tokio::test]
    async fn get_all_users_and_get_current_user_include_signed_avatar() {
        let db = test_db().await;
        let user = create_test_user(&db).await;
        let _ = update_avatar(
            State(db.clone()),
            CurrentSession { user_id: user, session_id: Uuid::new_v4() },
            Json(UpdateAvatarRequest { avatar_url: Some("/uploads/pic.png".into()) }),
        )
        .await
        .expect("setting an avatar should succeed");

        let me = get_current_user(State(db.clone()), CurrentSession { user_id: user, session_id: Uuid::new_v4() })
            .await
            .expect("fetching self should succeed");
        assert!(me.0.avatar_url.as_deref().unwrap_or("").starts_with("/api/v1/files/pic.png"));

        let all = get_all_users(State(db.clone()), CurrentSession { user_id: user, session_id: Uuid::new_v4() })
            .await
            .expect("listing users should succeed");
        let me_in_list = all.0.iter().find(|u| u.id == user).expect("self should be in the all-users list");
        assert!(me_in_list.avatar_url.as_deref().unwrap_or("").starts_with("/api/v1/files/pic.png"));

        cleanup_test_user(&db, user).await;
    }
}

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
use crate::extractors::auth::CurrentUser;
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
    CurrentUser(_user_id): CurrentUser,
) -> Result<Json<Vec<PublicUser>>, AppError> {
    let users: Vec<User> = sqlx::query_as(
        r#"
        SELECT id, username, email, password_hash, is_online, status, created_at, patron_tier, bio
        FROM users
        WHERE banned_at IS NULL
        ORDER BY username ASC
        "#,
    )
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let public_users: Vec<PublicUser> = users.into_iter().map(PublicUser::from).collect();
    Ok(Json(public_users))
}

pub async fn get_current_user(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
) -> Result<Json<PublicUser>, AppError> {
    let user: User = sqlx::query_as(
        r#"
        SELECT id, username, email, password_hash, is_online, status, created_at, patron_tier, bio
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(PublicUser::from(user)))
}

pub async fn update_patron_tier(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
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
        RETURNING id, username, email, password_hash, is_online, status, created_at, patron_tier, bio
        "#,
    )
    .bind(&payload.patron_tier)
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(PublicUser::from(user)))
}

/// PATCH /api/v1/admin/patron-tier — site owners only.
pub async fn admin_update_patron_tier(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
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
        RETURNING id, username, email, password_hash, is_online, status, created_at, patron_tier, bio
        "#,
    )
    .bind(&payload.patron_tier)
    .bind(payload.user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(PublicUser::from(user)))
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
        RETURNING id, username, email, password_hash, is_online, status, created_at, patron_tier, bio
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
}

pub async fn get_user_profile(
    State(db): State<Database>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<UserProfile>, AppError> {
    let user: Option<UserProfile> = sqlx::query_as(
        "SELECT id, username, patron_tier, status, created_at FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    match user {
        Some(u) => Ok(Json(u)),
        None => Err(AppError::NotFound("User not found".into())),
    }
}
// ---------- Account settings ----------

use crate::extractors::auth::CurrentSession;
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
            CurrentUser(caller),
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
            CurrentUser(owner),
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
}

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

pub async fn admin_update_patron_tier(
    State(db): State<Database>,
    CurrentUser(_user_id): CurrentUser,
    Json(payload): Json<AdminUpdatePatronRequest>,
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
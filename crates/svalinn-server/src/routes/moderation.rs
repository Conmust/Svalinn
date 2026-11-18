use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;

#[derive(Deserialize)]
pub struct BanUserRequest {
    pub reason: Option<String>,
}

pub async fn ban_user(
    State(db): State<Database>,
    CurrentUser(moderator_id): CurrentUser,
    Path(target_user_id): Path<Uuid>,
    Json(payload): Json<BanUserRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Check if the moderator has permission (must be mod/admin in at least one server with the target)
    let is_mod: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM server_members sm
            WHERE sm.user_id = $1 AND sm.role IN ('moderator', 'admin')
            AND sm.server_id IN (
                SELECT server_id FROM server_members WHERE user_id = $2
            )
        )
        "#,
    )
    .bind(moderator_id)
    .bind(target_user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if !is_mod {
        return Err(AppError::Forbidden(
            "You don't have permission to ban this user".into(),
        ));
    }

    // Set banned_at
    sqlx::query("UPDATE users SET banned_at = CURRENT_TIMESTAMP WHERE id = $1")
        .bind(target_user_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    // Delete all messages by the user (using rows_affected is much cleaner than RETURNING)
    let result = sqlx::query("DELETE FROM messages WHERE user_id = $1")
        .bind(target_user_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let deleted = result.rows_affected() as i64;

    // Remove from all servers
    sqlx::query("DELETE FROM server_members WHERE user_id = $1")
        .bind(target_user_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "messages_deleted": deleted,
        "reason": payload.reason
    })))
}
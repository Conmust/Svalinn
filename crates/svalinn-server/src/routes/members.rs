use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;

use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct ServerMember {
    pub id: Uuid,
    pub username: String,
    pub is_online: bool,
    pub status: String,
    pub role: String,
    pub patron_tier: String,
}

pub async fn get_server_members(
    State(db): State<Database>,
    CurrentUser(_user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
) -> Result<Json<Vec<ServerMember>>, AppError> {
    let members: Vec<ServerMember> = sqlx::query_as(
        r#"
        SELECT 
            u.id,
            u.username,
            u.is_online,
            u.status,
            sm.role,
            u.patron_tier
        FROM server_members sm
        JOIN users u ON sm.user_id = u.id
        WHERE sm.server_id = $1
        ORDER BY 
            CASE u.status
                WHEN 'online' THEN 1
                WHEN 'idle' THEN 2
                WHEN 'busy' THEN 3
                WHEN 'away' THEN 4
                WHEN 'invisible' THEN 5
                WHEN 'offline' THEN 6
                ELSE 7
            END,
            u.username ASC
        "#,
    )
    .bind(server_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(members))
}

// Get current user's role in a server
pub async fn get_user_role_in_server(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let role: Option<String> = sqlx::query_scalar(
        "SELECT role FROM server_members WHERE server_id = $1 AND user_id = $2",
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "role": role.unwrap_or_else(|| "member".to_string())
    })))
}
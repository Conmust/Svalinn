use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode, header},
    Json,
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde_json::json;
use uuid::Uuid;

use crate::db::Database;
use crate::models::user::Claims;

/// Extractor that validates the JWT and provides the current user's ID.
/// Use it in route handlers like: `CurrentUser(user_id): CurrentUser`
pub struct CurrentUser(pub Uuid);

#[axum::async_trait]
impl FromRequestParts<Database> for CurrentUser {
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(parts: &mut Parts, state: &Database) -> Result<Self, Self::Rejection> {
        // 1. Get the Authorization header
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| unauthorized("Missing Authorization header"))?;

        // 2. Expect "Bearer <token>"
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| unauthorized("Invalid Authorization header format"))?;

        // 3. Get the JWT secret from environment
        let secret = std::env::var("JWT_SECRET")
            .unwrap_or_else(|_| "dev-secret-change-me-in-production".into());

        // 4. Decode and validate the token
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|_| unauthorized("Invalid or expired token"))?;

        let user_id = token_data.claims.sub;

        // 5. Check if user exists in the database to prevent FK errors on deleted accounts
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)"
        )
        .bind(user_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|_| unauthorized("Internal server error"))?;

        if !exists {
            return Err(unauthorized("Account no longer exists"));
        }

        Ok(CurrentUser(user_id))
    }
}

fn unauthorized(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": message })),
    )
}
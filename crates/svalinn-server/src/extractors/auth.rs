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

/// The secret used to sign and verify login tokens. Set once at startup by
/// `init_jwt_secret`; there is deliberately no built-in default.
static JWT_SECRET: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// The secret that older versions fell back to. It's public, so never accept it.
const OLD_DEFAULT_SECRET: &str = "dev-secret-change-me-in-production";
const MIN_PRODUCTION_LENGTH: usize = 32;

/// Checks a JWT secret. Returns an optional warning, or an error if the server
/// must not start with it.
pub fn validate_jwt_secret(secret: &str, app_env: &str) -> Result<Option<String>, String> {
    let secret = secret.trim();
    if secret.is_empty() {
        return Err("JWT_SECRET is not set. Add a long random value to your .env file.".into());
    }
    if secret == OLD_DEFAULT_SECRET {
        return Err("JWT_SECRET is set to the old built-in default, which is public. Choose a new random value.".into());
    }
    if secret.chars().count() < MIN_PRODUCTION_LENGTH {
        let msg = format!("JWT_SECRET is shorter than {MIN_PRODUCTION_LENGTH} characters.");
        if app_env == "development" {
            return Ok(Some(format!("{msg} That's fine for local development, but use a long random value anywhere else.")));
        }
        return Err(format!("{msg} Use a long random value (APP_ENV is not \"development\")."));
    }
    Ok(None)
}

/// Reads JWT_SECRET from the environment and stores it. Call once at startup.
pub fn init_jwt_secret() -> Result<Option<String>, String> {
    let secret = std::env::var("JWT_SECRET").unwrap_or_default();
    let app_env = std::env::var("APP_ENV").unwrap_or_default();
    let warning = validate_jwt_secret(&secret, &app_env)?;
    let _ = JWT_SECRET.set(secret.trim().to_string());
    Ok(warning)
}

/// Verifies an access token's signature and expiry.
pub fn decode_access_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::HS256);
    // The library allows tokens 60s past expiry by default. Access tokens only
    // live 5 minutes, so keep just a few seconds for clock differences.
    validation.leeway = 5;
    decode::<Claims>(token, &DecodingKey::from_secret(jwt_secret()), &validation).map(|data| data.claims)
}

pub fn jwt_secret() -> &'static [u8] {
    JWT_SECRET
        .get()
        .expect("init_jwt_secret must be called at startup")
        .as_bytes()
}

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

        // 3. Decode and validate the token
        let claims = decode_access_token(token)
            .map_err(|_| unauthorized("Invalid or expired token"))?;

        let user_id = claims.sub;

        // 4. Check if user exists in the database to prevent FK errors on deleted accounts
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
#[cfg(test)]
mod tests {
    use super::validate_jwt_secret;

    #[test]
    fn rejects_missing_and_old_default_secrets() {
        assert!(validate_jwt_secret("", "development").is_err());
        assert!(validate_jwt_secret("   ", "production").is_err());
        assert!(validate_jwt_secret("dev-secret-change-me-in-production", "development").is_err());
    }

    #[test]
    fn short_secrets_only_allowed_in_development() {
        assert!(matches!(validate_jwt_secret("change-me", "development"), Ok(Some(_))));
        assert!(validate_jwt_secret("change-me", "production").is_err());
        assert!(validate_jwt_secret("change-me", "").is_err());
    }

    #[test]
    fn accepts_long_secrets() {
        let long = "x".repeat(40);
        assert_eq!(validate_jwt_secret(&long, "production"), Ok(None));
    }
}

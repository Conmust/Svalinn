use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub is_online: bool,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub patron_tier: String,
    pub bio: Option<String>,
    /// Base64-encoded X25519 public key for this user's (single) device, used
    /// for end-to-end encrypting direct messages. NULL until the user has
    /// logged in on an E2EE-aware client -- the normal state for most
    /// existing accounts.
    pub public_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicUser {
    pub id: Uuid,
    pub username: String,
    pub is_online: bool,
    pub status: String,
    pub patron_tier: String,
    pub bio: Option<String>,
    pub public_key: Option<String>,
}

impl From<User> for PublicUser {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            is_online: user.is_online,
            status: user.status,
            patron_tier: user.patron_tier,
            bio: user.bio,
            public_key: user.public_key,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    /// Short-lived access token (JWT). Send as `Authorization: Bearer ...`.
    pub token: String,
    /// Seconds until `token` expires.
    pub expires_in: i64,
    /// Long-lived token for `POST /api/v1/auth/refresh`.
    pub refresh_token: String,
    pub user: PublicUser,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub expires_in: i64,
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub username: String,
    pub exp: usize,
    /// Login session (refresh-token family). Revoking it ends access at once.
    /// Tokens issued before sessions existed lack it and are rejected.
    #[serde(default)]
    pub sid: Option<Uuid>,
}
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    /// Legacy plaintext column. NULL for every account going forward (and
    /// for any pre-existing account after the startup backfill clears it)
    /// -- see `email_privacy` and `main::backfill_email_privacy`. Kept as
    /// `Option` (not read anywhere) purely so `SELECT *`/`RETURNING *`
    /// against `users` still decodes into this struct.
    #[serde(skip_serializing)]
    pub email: Option<String>,
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
    /// Stored `/uploads/...` path to the user's profile picture, or an
    /// external URL. Signed into a viewer-specific link before being sent
    /// to a client -- see `routes::users::sign_avatar`.
    pub avatar_url: Option<String>,
    /// This user's chosen tier-badge emblem id (e.g. "crown", "ruby",
    /// "fehu_rune"), or NULL if they haven't picked one -- the client falls
    /// back to that tier's default emblem. See `crate::badges`.
    pub badge_emblem: Option<String>,
    /// Raw `users.site_role` column ("owner" or NULL). Kept as the raw
    /// column (rather than a computed `is_site_owner: bool`, as
    /// `PublicUser` has) so this struct still matches plain `SELECT *` /
    /// `RETURNING *` queries against `users` -- see e.g.
    /// `routes::auth::register`/`login`, which construct a `User` that way
    /// and have no `is_site_owner` column to select.
    pub site_role: Option<String>,
    /// Owner-granted badge, independent of `patron_tier`/`site_role` --
    /// a real non-nullable `NOT NULL DEFAULT false` column (see
    /// `migrations/0035_beta_badge.sql`), so unlike `site_role` it's safe
    /// to keep as a plain field here: every `SELECT */RETURNING *` against
    /// `users` always returns it.
    pub has_beta_badge: bool,
}

impl User {
    pub fn is_site_owner(&self) -> bool {
        self.site_role.as_deref() == Some("owner")
    }
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
    pub avatar_url: Option<String>,
    pub badge_emblem: Option<String>,
    pub is_site_owner: bool,
    pub has_beta_badge: bool,
}

impl From<User> for PublicUser {
    fn from(user: User) -> Self {
        let is_site_owner = user.is_site_owner();
        Self {
            id: user.id,
            username: user.username,
            is_online: user.is_online,
            status: user.status,
            patron_tier: user.patron_tier,
            bio: user.bio,
            public_key: user.public_key,
            avatar_url: user.avatar_url,
            badge_emblem: user.badge_emblem,
            is_site_owner,
            has_beta_badge: user.has_beta_badge,
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
    /// The verification link, present only when `APP_ENV=development` and
    /// only right after registration -- there's no real email provider
    /// wired up yet (see `routes::auth::send_verification_email`), so this
    /// is how a local dev/test client gets at it without one. Never set in
    /// any other environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_verification_link: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
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
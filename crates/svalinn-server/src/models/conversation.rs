use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Conversation {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ConversationWithParticipant {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub participant_id: Uuid,
    pub participant_username: String,
    pub participant_is_online: bool,
    pub participant_status: String,
    pub participant_patron_tier: String,
    /// Base64-encoded X25519 public key for the *other* participant's
    /// device, if they've set one up. The client needs this to encrypt
    /// messages to them; a missing key means sending must be blocked
    /// client-side rather than falling back to plaintext.
    pub participant_public_key: Option<String>,
    pub participant_avatar_url: Option<String>,
    pub participant_badge_emblem: Option<String>,
    pub participant_is_site_owner: bool,
    pub has_unread: bool,
}
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
    pub has_unread: bool,
}
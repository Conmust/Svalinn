use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct BroadcastMessage {
    pub event_type: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct NewMessagePayload {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub content: String,
    pub attachment_url: Option<String>,
    pub attachment_filename: Option<String>,
    pub attachment_mime_type: Option<String>,
    pub attachment_size: Option<i64>,
    pub is_edited: bool,
    pub is_locked: bool,
    pub is_pinned: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// UPDATED REACTION STRUCT WITH AGGREGATED FIELDS
#[derive(Debug, Clone, Serialize)]
pub struct Reaction {
    pub id: Uuid,
    pub message_id: Uuid,
    pub user_id: Uuid,
    pub emoji: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    
    // Aggregated fields (computed in Rust, not stored directly in the DB row)
    #[serde(default)]
    pub count: i64,
    #[serde(default)]
    pub user_ids: Vec<Uuid>,
    #[serde(default)]
    pub current_user_reacted: bool,
}
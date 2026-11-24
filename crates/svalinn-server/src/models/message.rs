use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct BroadcastMessage {
    /// Sent as `type`, which is the field the desktop client's WebSocket
    /// handler reads (`data.type`).
    #[serde(rename = "type")]
    pub event_type: String,
    pub payload: serde_json::Value,
    /// Server the event belongs to. Only members of this server receive it.
    /// Not sent to clients.
    #[serde(skip)]
    pub server_id: Option<Uuid>,
    /// If set, only this user receives the event (whether or not they're a
    /// member of `server_id`), e.g. to tell someone they were kicked.
    /// Not sent to clients.
    #[serde(skip)]
    pub to_user: Option<Uuid>,
    /// If set, only these users receive the event -- e.g. a channel event
    /// where the recipient list has already been filtered down to members
    /// who can see that channel (`VIEW_CHANNEL`), computed by the caller
    /// since by delivery time (especially for a deleted channel) there
    /// may be no channel left to re-check permissions against. Not sent
    /// to clients.
    #[serde(skip)]
    pub to_users: Option<Vec<Uuid>>,
}

impl BroadcastMessage {
    /// An event for every member of a server.
    pub fn to_server(event_type: &str, payload: serde_json::Value, server_id: Uuid) -> Self {
        Self { event_type: event_type.to_string(), payload, server_id: Some(server_id), to_user: None, to_users: None }
    }

    /// An event for one user only.
    pub fn to_user(event_type: &str, payload: serde_json::Value, user_id: Uuid) -> Self {
        Self { event_type: event_type.to_string(), payload, server_id: None, to_user: Some(user_id), to_users: None }
    }

    /// An event for a specific, already-computed set of users -- e.g. only
    /// the members who can see the channel an event is about.
    pub fn to_users(event_type: &str, payload: serde_json::Value, user_ids: Vec<Uuid>) -> Self {
        Self { event_type: event_type.to_string(), payload, server_id: None, to_user: None, to_users: Some(user_ids) }
    }
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

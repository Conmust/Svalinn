use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

/// A device's own view of itself, for the devices-management UI. Never
/// carries the public key back out -- not because it's secret (it isn't),
/// but because the owning client already has it and no caller needs it
/// here.
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct DeviceKey {
    pub id: Uuid,
    pub device_label: String,
    pub created_at: DateTime<Utc>,
}

/// One recipient device's ciphertext for a single fan-out message -- one
/// `message_recipients` row, minus the `message_id` (the caller already
/// knows which message this belongs to from context: either it's one
/// entry in that message's own `recipients` list, or it was just looked up
/// for a specific message).
///
/// `sender_public_key` is the public key of the device that *encrypted*
/// this message (see migration 0030's comment on why recipients need this,
/// not just their own key) -- a recipient decrypts with
/// `(my own private key, sender_public_key)`.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct MessageRecipientPayload {
    pub device_id: Uuid,
    pub ciphertext: String,
    pub nonce: String,
    pub sender_public_key: String,
    /// This device's own wrapped copy of the message's attachment
    /// symmetric key (`crypto_box_easy`, unwrapped with `sender_public_key`
    /// above and this device's own private key), when the message has an
    /// encrypted attachment. `None` for a message with no attachment, and
    /// for every row of a message that predates this feature.
    pub attachment_key_ciphertext: Option<String>,
    /// Nonce for `attachment_key_ciphertext`. Always present together with
    /// it, never alone.
    pub attachment_key_nonce: Option<String>,
}

/// One entry of a fan-out send request: the server-assigned encrypting
/// device ciphertext for one specific recipient device.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct EncryptedRecipient {
    pub device_id: Uuid,
    pub ciphertext: String,
    pub nonce: String,
    /// This recipient device's wrapped copy of the attachment's symmetric
    /// key, when this send has an attachment. Required (and must be
    /// non-empty) for every entry when `SendDirectMessageRequest::
    /// attachment_url` is set; must be absent otherwise -- see
    /// `send_fanout_message`'s validation.
    #[serde(default)]
    pub attachment_key_ciphertext: Option<String>,
    #[serde(default)]
    pub attachment_key_nonce: Option<String>,
}

/// One of a conversation's two participants' devices, as seen by a client
/// composing a send: who the device belongs to, and the public key to
/// encrypt with. `is_me` lets the sending client tell apart "my other
/// devices" (which it also encrypts a copy to, so its own other sessions
/// can read what it sent) from the recipient's devices.
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct ParticipantDevice {
    pub device_id: Uuid,
    pub user_id: Uuid,
    pub public_key: String,
    pub device_label: String,
    pub is_me: bool,
}

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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
    /// This entry's Double Ratchet envelope metadata (`ratchet.ts`'s
    /// `RatchetEnvelope` minus `ciphertext`/`nonce`, which already have
    /// their own columns), as an opaque JSON string the server never
    /// parses -- only stores and hands back verbatim. `None` for a message
    /// sent via the legacy stateless per-device path (`crypto.ts`), and for
    /// every row that predates this feature. See migration 0040.
    pub ratchet_header_json: Option<String>,
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
    /// See `MessageRecipientPayload::ratchet_header_json` -- the same
    /// opaque JSON blob, supplied by the client when this entry was
    /// encrypted via `ratchet.ts` rather than `crypto.ts`.
    #[serde(default)]
    pub ratchet_header_json: Option<String>,
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

// --- Double Ratchet prekey bundles & session pickles (migration 0038) -----
//
// These support an X3DH-style bootstrap for a Double Ratchet session,
// additive alongside the stateless per-device model above. A device never
// uploads anything private here either -- only public prekeys and, for
// session pickles, ciphertext the device itself encrypted before upload
// (see migration 0038's comment on `ratchet_sessions.pickle_ciphertext`).

/// One row of `device_prekeys`, as uploaded by a device. `signature` is
/// required for `key_type = "signed"` (an Ed25519 signature over
/// `public_key`'s bytes, by the device's identity signing key) and must be
/// absent for `key_type = "one_time"` -- see `upload_prekeys`'s validation.
#[derive(Debug, Clone, Deserialize)]
pub struct PrekeyUpload {
    pub key_type: String,
    pub public_key: String,
    #[serde(default)]
    pub signature: Option<String>,
}

/// A device's active signed prekey plus (if any remained) one freshly
/// consumed one-time prekey, returned to whoever is bootstrapping a new
/// session with this device. `one_time_prekey_id` lets the caller do
/// nothing further -- the prekey is marked consumed server-side, atomically,
/// as part of producing this response (see `fetch_prekey_bundle`) -- it's
/// returned only so a client can log/debug which one it used.
#[derive(Debug, Clone, Serialize)]
pub struct PrekeyBundle {
    pub device_id: Uuid,
    pub identity_public_key: String,
    /// This device's Ed25519 signing public key (migration 0039),
    /// needed to verify `signed_prekey_signature` below. Always present --
    /// `fetch_prekey_bundle` refuses to return a bundle for a device that
    /// hasn't registered one, rather than returning an unverifiable bundle.
    pub identity_signing_public_key: String,
    pub signed_prekey_public_key: String,
    pub signed_prekey_signature: String,
    pub one_time_prekey_id: Option<Uuid>,
    pub one_time_prekey_public_key: Option<String>,
}

/// A device's own view of its remaining one-time prekey count, so its
/// client can tell when it's running low and should upload more -- see
/// `ratchet.ts`'s replenishment check.
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct PrekeyCounts {
    pub unconsumed_one_time_prekeys: i64,
    pub has_signed_prekey: bool,
}

/// One device's own encrypted backup of its session with one specific peer
/// device (a `ratchet_sessions` row, keyed by the owning device's id and
/// the peer device's id -- see migration 0038's doc comment on why this is
/// directed, not a row shared between the two devices in a conversation).
/// This struct carries the opaque, client-encrypted state plus enough to
/// detect a concurrent write (`updated_at`, checked by the client before
/// overwriting -- see `ratchet.ts`'s `saveSession`).
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct RatchetSessionPickle {
    pub pickle_ciphertext: String,
    pub pickle_nonce: String,
    pub updated_at: DateTime<Utc>,
}

/// Request body for upserting a session pickle -- see `put_ratchet_session`.
#[derive(Debug, Clone, Deserialize)]
pub struct PutRatchetSessionRequest {
    pub pickle_ciphertext: String,
    pub pickle_nonce: String,
    /// The `updated_at` this client last read for this session (`None` if
    /// it believes no session exists yet). If another of the user's own
    /// devices has written a newer pickle in the meantime, the write is
    /// rejected with a conflict rather than silently clobbering it -- see
    /// `put_ratchet_session`'s optimistic-concurrency check.
    #[serde(default)]
    pub expected_updated_at: Option<DateTime<Utc>>,
}

/// Request body for reporting one skipped message key as consumed --
/// see `report_consumed_skipped_key` and migration 0041's doc comment on
/// why this ledger exists alongside the whole-session backup above.
#[derive(Debug, Clone, Deserialize)]
pub struct ReportConsumedSkippedKeyRequest {
    pub dh_public_key: String,
    pub message_number: i32,
}

/// One row of the consumed-skipped-key ledger, as returned to the owning
/// device during recovery -- see `list_consumed_skipped_keys`.
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct ConsumedSkippedKey {
    pub dh_public_key: String,
    pub message_number: i32,
}

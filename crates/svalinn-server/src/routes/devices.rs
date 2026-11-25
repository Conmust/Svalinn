//! Per-device key management for E2EE direct messages (the multi-device
//! successor to the single `users.public_key` field from
//! `routes::users::update_public_key`). Each device a user logs in on
//! generates its own X25519 keypair and registers only the public half
//! here -- the server never sees a private key for any device, ever.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;
use crate::models::device::{DeviceKey, PrekeyCounts, PrekeyUpload};

/// Decoded length of a valid X25519 public key, in bytes. Mirrors
/// `routes::users::PUBLIC_KEY_BYTES`.
const PUBLIC_KEY_BYTES: usize = 32;
/// Longest accepted device label.
const MAX_DEVICE_LABEL_CHARS: usize = 100;
/// Devices a single user may register. Enforced here at the application
/// layer (not a DB constraint) so a clear, friendly error can be returned
/// instead of a bare constraint-violation.
const MAX_DEVICES_PER_USER: i64 = 10;

fn decode_public_key(public_key: &str) -> Result<String, AppError> {
    use base64::Engine;
    let trimmed = public_key.trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|_| AppError::BadRequest("public_key must be valid base64".into()))?;
    if decoded.len() != PUBLIC_KEY_BYTES {
        return Err(AppError::BadRequest(format!(
            "public_key must decode to exactly {PUBLIC_KEY_BYTES} bytes (an X25519 public key)"
        )));
    }
    Ok(trimmed.to_string())
}

#[derive(Deserialize)]
pub struct RegisterDeviceRequest {
    pub public_key: String,
    pub device_label: String,
    /// Optional Ed25519 signing public key (base64), decoded length
    /// checked the same way as `public_key` below. Only present from a
    /// ratchet-capable client -- see migration 0039's comment on why this
    /// is a second, separate keypair from the X25519 agreement key above,
    /// and `routes::ratchet::fetch_prekey_bundle` for how its absence is
    /// treated (not an error -- just "this device hasn't opted in yet").
    #[serde(default)]
    pub signing_public_key: Option<String>,
}

/// Decoded length of a valid Ed25519 public key, in bytes.
const SIGNING_PUBLIC_KEY_BYTES: usize = 32;

fn decode_signing_public_key(signing_public_key: &str) -> Result<String, AppError> {
    use base64::Engine;
    let trimmed = signing_public_key.trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|_| AppError::BadRequest("signing_public_key must be valid base64".into()))?;
    if decoded.len() != SIGNING_PUBLIC_KEY_BYTES {
        return Err(AppError::BadRequest(format!(
            "signing_public_key must decode to exactly {SIGNING_PUBLIC_KEY_BYTES} bytes (an Ed25519 public key)"
        )));
    }
    Ok(trimmed.to_string())
}

#[derive(Debug, Serialize)]
pub struct RegisterDeviceResponse {
    pub id: Uuid,
}

/// POST /api/v1/users/me/devices  `{ "public_key": "...", "device_label": "..." }`
///
/// Registers a new device for the current user and returns its id. The
/// caller stores this id locally (alongside its own keypair) so it can
/// later identify itself when fetching/receiving messages, and so it can
/// delete itself from the device list.
pub async fn register_device(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Json(payload): Json<RegisterDeviceRequest>,
) -> Result<Json<RegisterDeviceResponse>, AppError> {
    let public_key = decode_public_key(&payload.public_key)?;
    let signing_public_key = payload
        .signing_public_key
        .as_deref()
        .map(decode_signing_public_key)
        .transpose()?;

    let label = payload.device_label.trim();
    if label.is_empty() {
        return Err(AppError::BadRequest("device_label is required".into()));
    }
    if label.chars().count() > MAX_DEVICE_LABEL_CHARS {
        return Err(AppError::BadRequest(format!(
            "device_label can be at most {MAX_DEVICE_LABEL_CHARS} characters"
        )));
    }

    let mut tx = db.pool.begin().await.map_err(|e| AppError::Database(e.to_string()))?;

    // Serializes concurrent registrations for this user, so two devices
    // registering at once can't both pass the count check below and push
    // the user over the cap.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(user_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let device_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_keys WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    if device_count >= MAX_DEVICES_PER_USER {
        return Err(AppError::BadRequest(format!(
            "You can have at most {MAX_DEVICES_PER_USER} devices registered. Remove an old device before adding a new one."
        )));
    }

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO device_keys (user_id, public_key, device_label, signing_public_key) VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(user_id)
    .bind(&public_key)
    .bind(label)
    .bind(&signing_public_key)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    tx.commit().await.map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(RegisterDeviceResponse { id }))
}

/// GET /api/v1/users/me/devices
///
/// Lists the current user's own registered devices (never the public keys
/// themselves -- the owning client already has those).
pub async fn list_my_devices(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
) -> Result<Json<Vec<DeviceKey>>, AppError> {
    let devices: Vec<DeviceKey> = sqlx::query_as(
        "SELECT id, device_label, created_at FROM device_keys WHERE user_id = $1 ORDER BY created_at ASC",
    )
    .bind(user_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(devices))
}

/// DELETE /api/v1/users/me/devices/:device_id
///
/// Removes one of the current user's own devices. Only ever deletes a
/// device owned by the caller -- the WHERE clause checks `user_id` too, so
/// this can't be used to delete someone else's device by guessing an id.
/// Any `message_recipients` rows already addressed to this device are left
/// in place (cascaded away only if the *message* itself is deleted); they
/// simply become permanently undecryptable orphans, which is expected.
pub async fn delete_device(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(device_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let result = sqlx::query("DELETE FROM device_keys WHERE id = $1 AND user_id = $2")
        .bind(device_id)
        .bind(user_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Device not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct RenameDeviceRequest {
    pub device_label: String,
}

/// PATCH /api/v1/users/me/devices/:device_id
///
/// Renames one of the current user's own devices.
pub async fn rename_device(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(device_id): Path<Uuid>,
    Json(payload): Json<RenameDeviceRequest>,
) -> Result<Json<DeviceKey>, AppError> {
    let label = payload.device_label.trim();
    if label.is_empty() {
        return Err(AppError::BadRequest("device_label is required".into()));
    }
    if label.chars().count() > MAX_DEVICE_LABEL_CHARS {
        return Err(AppError::BadRequest(format!(
            "device_label can be at most {MAX_DEVICE_LABEL_CHARS} characters"
        )));
    }

    let device: DeviceKey = sqlx::query_as(
        r#"
        UPDATE device_keys SET device_label = $1
        WHERE id = $2 AND user_id = $3
        RETURNING id, device_label, created_at
        "#,
    )
    .bind(label)
    .bind(device_id)
    .bind(user_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Device not found".into()))?;

    Ok(Json(device))
}

#[derive(Deserialize)]
pub struct SetSigningKeyRequest {
    pub signing_public_key: String,
}

/// PUT /api/v1/users/me/devices/:device_id/signing-key
///
/// Sets (or replaces) one of the current user's own devices' Ed25519
/// signing public key -- see migration 0039. Separate from
/// `register_device` because most devices already exist by the time
/// `ratchet.ts`'s identity setup runs on them for the first time; this is
/// how an already-registered device opts into the Double Ratchet
/// retroactively, without re-registering (which would mean a new
/// `device_id` and orphaning every `message_recipients` row already
/// addressed to the old one).
pub async fn set_signing_key(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(device_id): Path<Uuid>,
    Json(payload): Json<SetSigningKeyRequest>,
) -> Result<StatusCode, AppError> {
    let signing_public_key = decode_signing_public_key(&payload.signing_public_key)?;

    let result = sqlx::query("UPDATE device_keys SET signing_public_key = $1 WHERE id = $2 AND user_id = $3")
        .bind(&signing_public_key)
        .bind(device_id)
        .bind(user_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Device not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}

// --- Double Ratchet prekey bundles (migration 0038) ------------------------
//
// Additive alongside the identity-key registration above: a device
// uploads these separately, any time after it's registered, so it can be
// found with a signed prekey + one-time prekeys to bootstrap a Double
// Ratchet session with it even while it's offline. See `ratchet.rs` for
// the fetch/consume side and `models::device` for the shared types.

/// Longest accepted base64 string for a prekey public key or an Ed25519
/// signature. These are opaque to the server -- a malformed one just makes
/// a session bootstrap fail harmlessly client-side -- so this is a sanity
/// bound against abuse, not a strict decode-and-check like
/// `decode_public_key` above (which is used for the identity key, where a
/// wrong length would silently break every future message).
const MAX_PREKEY_FIELD_B64_CHARS: usize = 128;
/// Most one-time prekeys accepted in a single upload call.
const MAX_ONE_TIME_PREKEYS_PER_UPLOAD: usize = 100;
/// Most unconsumed one-time prekeys a device may have outstanding at once --
/// generous for weeks of normal session-bootstrap volume without letting a
/// single device flood the table.
const MAX_UNCONSUMED_ONE_TIME_PREKEYS: i64 = 200;

#[derive(Deserialize)]
pub struct UploadPrekeysRequest {
    pub prekeys: Vec<PrekeyUpload>,
}

#[derive(Debug, Serialize)]
pub struct UploadPrekeysResponse {
    pub accepted: usize,
}

/// POST /api/v1/users/me/devices/:device_id/prekeys
///
/// Uploads one or more prekeys for one of the current user's own devices: a
/// signed prekey (replaces this device's previous active one, if any -- see
/// below) and/or a batch of one-time prekeys (always additive, never
/// replacing existing unconsumed ones). Only ever touches a device owned by
/// the caller -- same ownership check as `delete_device`/`rename_device`.
pub async fn upload_prekeys(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(device_id): Path<Uuid>,
    Json(payload): Json<UploadPrekeysRequest>,
) -> Result<Json<UploadPrekeysResponse>, AppError> {
    if payload.prekeys.is_empty() {
        return Err(AppError::BadRequest("prekeys must not be empty".into()));
    }

    let owns_device: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM device_keys WHERE id = $1 AND user_id = $2)")
            .bind(device_id)
            .bind(user_id)
            .fetch_one(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    if !owns_device {
        return Err(AppError::NotFound("Device not found".into()));
    }

    let mut signed: Option<&PrekeyUpload> = None;
    let mut one_time: Vec<&PrekeyUpload> = Vec::new();
    for entry in &payload.prekeys {
        if entry.public_key.trim().is_empty() || entry.public_key.len() > MAX_PREKEY_FIELD_B64_CHARS {
            return Err(AppError::BadRequest(format!(
                "public_key must be 1-{MAX_PREKEY_FIELD_B64_CHARS} characters"
            )));
        }
        match entry.key_type.as_str() {
            "signed" => {
                let sig = entry.signature.as_deref().unwrap_or("").trim();
                if sig.is_empty() || sig.len() > MAX_PREKEY_FIELD_B64_CHARS {
                    return Err(AppError::BadRequest("a signed prekey requires a signature".into()));
                }
                if signed.is_some() {
                    return Err(AppError::BadRequest(
                        "at most one signed prekey may be uploaded per call".into(),
                    ));
                }
                signed = Some(entry);
            }
            "one_time" => {
                if entry.signature.is_some() {
                    return Err(AppError::BadRequest("a one-time prekey must not carry a signature".into()));
                }
                one_time.push(entry);
            }
            other => {
                return Err(AppError::BadRequest(format!(
                    "key_type must be \"signed\" or \"one_time\", got \"{other}\""
                )));
            }
        }
    }
    if one_time.len() > MAX_ONE_TIME_PREKEYS_PER_UPLOAD {
        return Err(AppError::BadRequest(format!(
            "at most {MAX_ONE_TIME_PREKEYS_PER_UPLOAD} one-time prekeys may be uploaded per call"
        )));
    }

    let mut tx = db.pool.begin().await.map_err(|e| AppError::Database(e.to_string()))?;

    if !one_time.is_empty() {
        let unconsumed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM device_prekeys WHERE device_id = $1 AND key_type = 'one_time' AND consumed_at IS NULL",
        )
        .bind(device_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        if unconsumed + one_time.len() as i64 > MAX_UNCONSUMED_ONE_TIME_PREKEYS {
            return Err(AppError::BadRequest(format!(
                "this device already has {unconsumed} unconsumed one-time prekeys; at most {MAX_UNCONSUMED_ONE_TIME_PREKEYS} may be outstanding at once"
            )));
        }
    }

    let mut accepted = 0usize;

    // A freshly uploaded signed prekey replaces the previous one outright
    // (rather than accumulating alongside it) -- there is only ever one
    // "active" signed prekey per device, matching how the prekey-bundle
    // fetch in `ratchet.rs` always selects the single newest row.
    if let Some(entry) = signed {
        sqlx::query("INSERT INTO device_prekeys (device_id, key_type, public_key, signature) VALUES ($1, 'signed', $2, $3)")
            .bind(device_id)
            .bind(entry.public_key.trim())
            .bind(entry.signature.as_deref().unwrap_or("").trim())
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        accepted += 1;
    }

    for entry in &one_time {
        sqlx::query("INSERT INTO device_prekeys (device_id, key_type, public_key) VALUES ($1, 'one_time', $2)")
            .bind(device_id)
            .bind(entry.public_key.trim())
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        accepted += 1;
    }

    tx.commit().await.map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(UploadPrekeysResponse { accepted }))
}

/// GET /api/v1/users/me/devices/:device_id/prekeys/count
///
/// Lets a device check its own remaining one-time-prekey count (and
/// whether it has an active signed prekey at all), so its client knows when
/// to top up -- see `ratchet.ts`'s replenishment check, which runs this
/// after every session bootstrap it serves to someone else.
pub async fn get_prekey_counts(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(device_id): Path<Uuid>,
) -> Result<Json<PrekeyCounts>, AppError> {
    let owns_device: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM device_keys WHERE id = $1 AND user_id = $2)")
            .bind(device_id)
            .bind(user_id)
            .fetch_one(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    if !owns_device {
        return Err(AppError::NotFound("Device not found".into()));
    }

    let unconsumed_one_time_prekeys: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM device_prekeys WHERE device_id = $1 AND key_type = 'one_time' AND consumed_at IS NULL",
    )
    .bind(device_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let has_signed_prekey: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM device_prekeys WHERE device_id = $1 AND key_type = 'signed')")
            .bind(device_id)
            .fetch_one(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(PrekeyCounts { unconsumed_one_time_prekeys, has_signed_prekey }))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> Database {
        dotenvy::dotenv().ok();
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is required for tests");
        Database::new(&database_url).await.expect("failed to connect to test database")
    }

    async fn create_test_user(db: &Database) -> Uuid {
        let unique = Uuid::new_v4();
        sqlx::query_scalar(
            "INSERT INTO users (username, email, password_hash, display_name) VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(format!("test_{unique}"))
        .bind(format!("test_{unique}@example.invalid"))
        .bind("not-a-real-hash")
        .bind(format!("Test User {unique}"))
        .fetch_one(&db.pool)
        .await
        .expect("failed to insert test user")
    }

    async fn cleanup_test_user(db: &Database, user_id: Uuid) {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1").bind(user_id).execute(&db.pool).await;
    }

    fn fake_public_key(byte: u8) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [byte; 32])
    }

    #[tokio::test]
    async fn register_list_and_delete_device_round_trip() {
        let db = test_db().await;
        let user = create_test_user(&db).await;

        let registered = register_device(
            State(db.clone()),
            CurrentUser(user),
            Json(RegisterDeviceRequest { public_key: fake_public_key(1), device_label: "My Laptop".into(), signing_public_key: None }),
        )
        .await
        .expect("registering a device should succeed")
        .0;

        let devices = list_my_devices(State(db.clone()), CurrentUser(user)).await.expect("listing devices failed").0;
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, registered.id);
        assert_eq!(devices[0].device_label, "My Laptop");

        let delete_result = delete_device(State(db.clone()), CurrentUser(user), Path(registered.id))
            .await
            .expect("deleting own device should succeed");
        assert_eq!(delete_result, StatusCode::NO_CONTENT);

        let devices_after = list_my_devices(State(db.clone()), CurrentUser(user)).await.expect("listing devices failed").0;
        assert!(devices_after.is_empty());

        cleanup_test_user(&db, user).await;
    }

    #[tokio::test]
    async fn cannot_delete_another_users_device() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let other = create_test_user(&db).await;

        let registered = register_device(
            State(db.clone()),
            CurrentUser(owner),
            Json(RegisterDeviceRequest { public_key: fake_public_key(2), device_label: "Owner's Phone".into(), signing_public_key: None }),
        )
        .await
        .expect("registering a device should succeed")
        .0;

        let result = delete_device(State(db.clone()), CurrentUser(other), Path(registered.id)).await;
        match result {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected AppError::NotFound when deleting someone else's device, got {other:?}"),
        }

        let devices = list_my_devices(State(db.clone()), CurrentUser(owner)).await.expect("listing devices failed").0;
        assert_eq!(devices.len(), 1, "the device must still exist after the forbidden delete attempt");

        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, other).await;
    }

    #[tokio::test]
    async fn device_cap_is_enforced() {
        let db = test_db().await;
        let user = create_test_user(&db).await;

        for i in 0..MAX_DEVICES_PER_USER {
            let _ = register_device(
                State(db.clone()),
                CurrentUser(user),
                Json(RegisterDeviceRequest { public_key: fake_public_key(i as u8), device_label: format!("Device {i}"), signing_public_key: None }),
            )
            .await
            .unwrap_or_else(|e| panic!("registering device {i} (within the cap) should succeed, got {e:?}"));
        }

        let result = register_device(
            State(db.clone()),
            CurrentUser(user),
            Json(RegisterDeviceRequest { public_key: fake_public_key(99), device_label: "One too many".into(), signing_public_key: None }),
        )
        .await;
        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest once the device cap is reached, got {other:?}"),
        }

        let devices = list_my_devices(State(db.clone()), CurrentUser(user)).await.expect("listing devices failed").0;
        assert_eq!(devices.len() as i64, MAX_DEVICES_PER_USER, "the rejected registration must not have been inserted");

        cleanup_test_user(&db, user).await;
    }

    #[tokio::test]
    async fn register_device_rejects_wrong_key_length() {
        let db = test_db().await;
        let user = create_test_user(&db).await;

        let too_short = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [1u8; 16]);
        let result = register_device(
            State(db.clone()),
            CurrentUser(user),
            Json(RegisterDeviceRequest { public_key: too_short, device_label: "Bad Key Device".into(), signing_public_key: None }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for a too-short public key, got {other:?}"),
        }

        cleanup_test_user(&db, user).await;
    }

    #[tokio::test]
    async fn upload_prekeys_accepts_a_signed_and_one_time_batch_and_counts_them() {
        let db = test_db().await;
        let user = create_test_user(&db).await;
        let device = register_device(
            State(db.clone()),
            CurrentUser(user),
            Json(RegisterDeviceRequest { public_key: fake_public_key(50), device_label: "Laptop".into(), signing_public_key: None }),
        )
        .await
        .expect("registering a device should succeed")
        .0
        .id;

        let result = upload_prekeys(
            State(db.clone()),
            CurrentUser(user),
            Path(device),
            Json(UploadPrekeysRequest {
                prekeys: vec![
                    PrekeyUpload { key_type: "signed".into(), public_key: fake_public_key(51), signature: Some(fake_public_key(52)) },
                    PrekeyUpload { key_type: "one_time".into(), public_key: fake_public_key(53), signature: None },
                    PrekeyUpload { key_type: "one_time".into(), public_key: fake_public_key(54), signature: None },
                ],
            }),
        )
        .await
        .expect("uploading a valid prekey batch should succeed")
        .0;
        assert_eq!(result.accepted, 3);

        let counts = get_prekey_counts(State(db.clone()), CurrentUser(user), Path(device))
            .await
            .expect("fetching prekey counts should succeed")
            .0;
        assert!(counts.has_signed_prekey);
        assert_eq!(counts.unconsumed_one_time_prekeys, 2);

        cleanup_test_user(&db, user).await;
    }

    #[tokio::test]
    async fn upload_prekeys_rejects_a_signed_prekey_with_no_signature() {
        let db = test_db().await;
        let user = create_test_user(&db).await;
        let device = register_device(
            State(db.clone()),
            CurrentUser(user),
            Json(RegisterDeviceRequest { public_key: fake_public_key(60), device_label: "Laptop".into(), signing_public_key: None }),
        )
        .await
        .expect("registering a device should succeed")
        .0
        .id;

        let result = upload_prekeys(
            State(db.clone()),
            CurrentUser(user),
            Path(device),
            Json(UploadPrekeysRequest {
                prekeys: vec![PrekeyUpload { key_type: "signed".into(), public_key: fake_public_key(61), signature: None }],
            }),
        )
        .await;
        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected BadRequest for a signed prekey missing its signature, got {other:?}"),
        }

        cleanup_test_user(&db, user).await;
    }

    #[tokio::test]
    async fn cannot_upload_prekeys_to_another_users_device() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let other = create_test_user(&db).await;
        let device = register_device(
            State(db.clone()),
            CurrentUser(owner),
            Json(RegisterDeviceRequest { public_key: fake_public_key(70), device_label: "Owner's Phone".into(), signing_public_key: None }),
        )
        .await
        .expect("registering a device should succeed")
        .0
        .id;

        let result = upload_prekeys(
            State(db.clone()),
            CurrentUser(other),
            Path(device),
            Json(UploadPrekeysRequest {
                prekeys: vec![PrekeyUpload { key_type: "one_time".into(), public_key: fake_public_key(71), signature: None }],
            }),
        )
        .await;
        match result {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected NotFound when uploading prekeys to someone else's device, got {other:?}"),
        }

        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, other).await;
    }

    #[tokio::test]
    async fn set_signing_key_opts_an_existing_device_into_the_ratchet() {
        let db = test_db().await;
        let user = create_test_user(&db).await;
        let device = register_device(
            State(db.clone()),
            CurrentUser(user),
            Json(RegisterDeviceRequest { public_key: fake_public_key(80), device_label: "Laptop".into(), signing_public_key: None }),
        )
        .await
        .expect("registering a device should succeed")
        .0
        .id;

        let status = set_signing_key(
            State(db.clone()),
            CurrentUser(user),
            Path(device),
            Json(SetSigningKeyRequest { signing_public_key: fake_public_key(81) }),
        )
        .await
        .expect("setting a signing key on one's own device should succeed");
        assert_eq!(status, StatusCode::NO_CONTENT);

        let stored: Option<String> = sqlx::query_scalar("SELECT signing_public_key FROM device_keys WHERE id = $1")
            .bind(device)
            .fetch_one(&db.pool)
            .await
            .expect("failed to read back signing_public_key");
        assert_eq!(stored, Some(fake_public_key(81)));

        cleanup_test_user(&db, user).await;
    }

    #[tokio::test]
    async fn cannot_set_signing_key_on_another_users_device() {
        let db = test_db().await;
        let owner = create_test_user(&db).await;
        let other = create_test_user(&db).await;
        let device = register_device(
            State(db.clone()),
            CurrentUser(owner),
            Json(RegisterDeviceRequest { public_key: fake_public_key(82), device_label: "Owner's Phone".into(), signing_public_key: None }),
        )
        .await
        .expect("registering a device should succeed")
        .0
        .id;

        let result = set_signing_key(
            State(db.clone()),
            CurrentUser(other),
            Path(device),
            Json(SetSigningKeyRequest { signing_public_key: fake_public_key(83) }),
        )
        .await;
        match result {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected NotFound when setting a signing key on someone else's device, got {other:?}"),
        }

        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, other).await;
    }
}

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
use crate::models::device::DeviceKey;

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
        "INSERT INTO device_keys (user_id, public_key, device_label) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(user_id)
    .bind(&public_key)
    .bind(label)
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
            Json(RegisterDeviceRequest { public_key: fake_public_key(1), device_label: "My Laptop".into() }),
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
            Json(RegisterDeviceRequest { public_key: fake_public_key(2), device_label: "Owner's Phone".into() }),
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
                Json(RegisterDeviceRequest { public_key: fake_public_key(i as u8), device_label: format!("Device {i}") }),
            )
            .await
            .unwrap_or_else(|e| panic!("registering device {i} (within the cap) should succeed, got {e:?}"));
        }

        let result = register_device(
            State(db.clone()),
            CurrentUser(user),
            Json(RegisterDeviceRequest { public_key: fake_public_key(99), device_label: "One too many".into() }),
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
            Json(RegisterDeviceRequest { public_key: too_short, device_label: "Bad Key Device".into() }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected AppError::BadRequest for a too-short public key, got {other:?}"),
        }

        cleanup_test_user(&db, user).await;
    }
}

//! Double Ratchet session bootstrap and session-state sync (migration
//! 0038), additive alongside the stateless per-device `crypto_box` model in
//! `routes::devices`/`routes::conversations`. Two things live here:
//!
//! - **Prekey bundle fetch-and-consume** (`fetch_prekey_bundle`): how a
//!   sender gets what it needs to bootstrap a brand-new ratchet session
//!   with a device it's never talked to before, including while that
//!   device is offline (the X3DH-style part).
//! - **Session pickle sync** (`get_ratchet_session`/`put_ratchet_session`):
//!   lets a user's OTHER devices pick up a ratchet session's current state,
//!   since the actual ratchet math and the plaintext session state live
//!   entirely client-side -- the server only ever stores and returns an
//!   opaque, client-encrypted blob. See `ratchet.ts` for the client side.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use uuid::Uuid;

use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;
use crate::models::device::{
    ConsumedSkippedKey, PrekeyBundle, PutRatchetSessionRequest, RatchetSessionPickle, ReportConsumedSkippedKeyRequest,
};
use crate::rate_limit::PREKEY_BUNDLE_FETCH_PER_TARGET_DEVICE;

/// GET /api/v1/devices/:device_id/prekey-bundle
///
/// Fetches `device_id`'s active signed prekey, plus one freshly consumed
/// one-time prekey if any remain (there may be none left -- a bootstrap can
/// still proceed with just the signed prekey, at a small cost to forward
/// secrecy for that one session, same tradeoff Signal/X3DH make). Any
/// authenticated user may call this for any device id: this exposes
/// nothing a caller couldn't already get from `GET
/// /conversations/:id/participant-devices` or `GET
/// /channels/:id/member-devices` (which hand out `public_key` freely to
/// conversation/channel participants already) -- a prekey is just as
/// public as an identity key, by design.
///
/// Consuming a one-time prekey (marking it `consumed_at`) happens
/// atomically with reading it, inside one transaction with a row lock, so
/// two concurrent bootstraps can never be handed the same one-time prekey.
pub async fn fetch_prekey_bundle(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(device_id): Path<Uuid>,
) -> Result<Json<PrekeyBundle>, AppError> {
    // See `PREKEY_BUNDLE_FETCH_PER_TARGET_DEVICE`'s doc comment: this
    // endpoint is open to any authenticated caller by design, but a
    // successful fetch consumes a one-time prekey, so unlimited repeat
    // fetches against the SAME target device would let any account drain
    // that device's whole stash. Scoped per (caller, target device), so
    // bootstrapping sessions with many different devices at once (joining
    // a large channel) is never affected.
    db.limits
        .hit(&PREKEY_BUNDLE_FETCH_PER_TARGET_DEVICE, &format!("{user_id}:{device_id}"))?;

    let device_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM device_keys WHERE id = $1)")
        .bind(device_id)
        .fetch_one(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    if !device_exists {
        return Err(AppError::NotFound("Device not found".into()));
    }

    let (identity_public_key, identity_signing_public_key): (String, Option<String>) =
        sqlx::query_as("SELECT public_key, signing_public_key FROM device_keys WHERE id = $1")
            .bind(device_id)
            .fetch_one(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    let identity_signing_public_key = identity_signing_public_key.ok_or_else(|| {
        AppError::NotFound(
            "This device hasn't registered a signing key yet, so a ratchet session can't be verified -- it hasn't opted into the Double Ratchet.".into(),
        )
    })?;

    let signed_row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT public_key, signature FROM device_prekeys
         WHERE device_id = $1 AND key_type = 'signed'
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(device_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let (signed_prekey_public_key, signed_prekey_signature) = signed_row.ok_or_else(|| {
        AppError::NotFound(
            "This device has not published a signed prekey yet, so a new session can't be started with it.".into(),
        )
    })?;
    let signed_prekey_signature = signed_prekey_signature
        .ok_or_else(|| AppError::Internal("a signed prekey row is missing its signature".into()))?;

    // Atomically claim one unconsumed one-time prekey, if any -- `FOR
    // UPDATE SKIP LOCKED` means two concurrent bootstraps race for
    // DIFFERENT rows rather than blocking on or double-claiming the same
    // one.
    let mut tx = db.pool.begin().await.map_err(|e| AppError::Database(e.to_string()))?;
    let one_time: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, public_key FROM device_prekeys
         WHERE device_id = $1 AND key_type = 'one_time' AND consumed_at IS NULL
         ORDER BY created_at ASC LIMIT 1
         FOR UPDATE SKIP LOCKED",
    )
    .bind(device_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let (one_time_prekey_id, one_time_prekey_public_key) = if let Some((id, public_key)) = one_time {
        sqlx::query("UPDATE device_prekeys SET consumed_at = now() WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        (Some(id), Some(public_key))
    } else {
        (None, None)
    };

    tx.commit().await.map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(PrekeyBundle {
        device_id,
        identity_public_key,
        identity_signing_public_key,
        signed_prekey_public_key,
        signed_prekey_signature,
        one_time_prekey_id,
        one_time_prekey_public_key,
    }))
}

/// Confirms the current user owns `device_id` -- the only party who should
/// ever read or write THIS device's own backup of its session with some
/// peer is this device's own owner. `peer_device_id` needs no ownership
/// check at all: it's just an opaque label for which session this is (the
/// peer device doesn't have to exist, be real, or belong to anyone in
/// particular, from this endpoint's point of view -- see migration 0038's
/// doc comment on why a session row is never shared between two devices).
async fn require_owns_device(db: &Database, user_id: Uuid, device_id: Uuid) -> Result<(), AppError> {
    let owns_it: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM device_keys WHERE id = $1 AND user_id = $2)")
        .bind(device_id)
        .bind(user_id)
        .fetch_one(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    if !owns_it {
        return Err(AppError::Forbidden(
            "You can only read or write a ratchet session backup for one of your own devices.".into(),
        ));
    }
    Ok(())
}

/// GET /api/v1/ratchet-sessions/:device_id/:peer_device_id
///
/// Fetches `device_id`'s own backup of its session with `peer_device_id`.
/// `device_id` must belong to the caller. Returns 404 if no backup has
/// been saved yet (the caller should bootstrap a session via
/// `fetch_prekey_bundle` instead).
pub async fn get_ratchet_session(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path((device_id, peer_device_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RatchetSessionPickle>, AppError> {
    require_owns_device(&db, user_id, device_id).await?;

    let pickle: RatchetSessionPickle = sqlx::query_as(
        "SELECT pickle_ciphertext, pickle_nonce, updated_at FROM ratchet_sessions WHERE device_id = $1 AND peer_device_id = $2",
    )
    .bind(device_id)
    .bind(peer_device_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("No ratchet session backup exists yet for this device pair".into()))?;

    Ok(Json(pickle))
}

/// PUT /api/v1/ratchet-sessions/:device_id/:peer_device_id
///
/// Upserts `device_id`'s own backup of its session with `peer_device_id`,
/// after the caller's client has advanced the ratchet (encrypted or
/// decrypted a message). `device_id` must belong to the caller.
/// `expected_updated_at` guards against two concurrent writes from the
/// SAME device (e.g. two browser tabs) clobbering each other: if provided
/// and it doesn't match what's actually stored, the write is rejected as a
/// conflict rather than silently overwritten -- the caller should re-fetch
/// via `get_ratchet_session` and reconcile.
pub async fn put_ratchet_session(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path((device_id, peer_device_id)): Path<(Uuid, Uuid)>,
    Json(payload): Json<PutRatchetSessionRequest>,
) -> Result<Json<RatchetSessionPickle>, AppError> {
    require_owns_device(&db, user_id, device_id).await?;

    if payload.pickle_ciphertext.trim().is_empty() || payload.pickle_nonce.trim().is_empty() {
        return Err(AppError::BadRequest("pickle_ciphertext and pickle_nonce are required".into()));
    }

    let mut tx = db.pool.begin().await.map_err(|e| AppError::Database(e.to_string()))?;

    let existing: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT updated_at FROM ratchet_sessions WHERE device_id = $1 AND peer_device_id = $2 FOR UPDATE",
    )
    .bind(device_id)
    .bind(peer_device_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if let Some(expected) = payload.expected_updated_at {
        match existing {
            Some(actual) if actual == expected => {}
            _ => {
                return Err(AppError::Forbidden(
                    "This session backup has changed since you last read it (likely a concurrent write from this same device); re-fetch and reconcile before writing again.".into(),
                ));
            }
        }
    } else if existing.is_some() {
        return Err(AppError::Forbidden(
            "A session backup already exists for this device pair; pass expected_updated_at to update it.".into(),
        ));
    }

    let pickle: RatchetSessionPickle = sqlx::query_as(
        r#"
        INSERT INTO ratchet_sessions (device_id, peer_device_id, pickle_ciphertext, pickle_nonce)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (device_id, peer_device_id)
        DO UPDATE SET pickle_ciphertext = EXCLUDED.pickle_ciphertext,
                      pickle_nonce = EXCLUDED.pickle_nonce,
                      updated_at = now()
        RETURNING pickle_ciphertext, pickle_nonce, updated_at
        "#,
    )
    .bind(device_id)
    .bind(peer_device_id)
    .bind(&payload.pickle_ciphertext)
    .bind(&payload.pickle_nonce)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    tx.commit().await.map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(pickle))
}

/// POST /api/v1/ratchet-sessions/:device_id/:peer_device_id/consumed-skipped-keys
///
/// Records that `device_id` has consumed one specific skipped message key
/// from `peer_device_id` -- see migration 0041's doc comment for why this
/// ledger exists independently of the whole-session backup above. Called
/// right alongside (not instead of) the usual eager session backup
/// (`ratchet.ts`'s `saveSessionEagerly`) whenever a decrypt is satisfied by
/// a cached skipped key, so that even a backup that hasn't caught up yet
/// can't reintroduce a key this device already knows it used.
///
/// Idempotent: reporting the same `(dh_public_key, message_number)` twice
/// (e.g. a retried request after a dropped response) is a no-op, not an
/// error -- there's nothing more to record the second time. `device_id`
/// must belong to the caller, same ownership rule as the session backup
/// endpoints: only a device's own owner should be able to write (or read)
/// what that device has consumed.
pub async fn report_consumed_skipped_key(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path((device_id, peer_device_id)): Path<(Uuid, Uuid)>,
    Json(payload): Json<ReportConsumedSkippedKeyRequest>,
) -> Result<StatusCode, AppError> {
    require_owns_device(&db, user_id, device_id).await?;

    if payload.dh_public_key.trim().is_empty() {
        return Err(AppError::BadRequest("dh_public_key is required".into()));
    }

    sqlx::query(
        r#"
        INSERT INTO ratchet_consumed_skipped_keys (device_id, peer_device_id, dh_public_key, message_number)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (device_id, peer_device_id, dh_public_key, message_number) DO NOTHING
        "#,
    )
    .bind(device_id)
    .bind(peer_device_id)
    .bind(&payload.dh_public_key)
    .bind(payload.message_number)
    .execute(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/v1/ratchet-sessions/:device_id/:peer_device_id/consumed-skipped-keys
///
/// Lists every skipped key `device_id` has ever reported consuming from
/// `peer_device_id`, so a client recovering from a (possibly stale)
/// session backup can strip any of these out of the restored
/// `skippedKeys` map before trusting it. `device_id` must belong to the
/// caller.
pub async fn list_consumed_skipped_keys(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path((device_id, peer_device_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<ConsumedSkippedKey>>, AppError> {
    require_owns_device(&db, user_id, device_id).await?;

    let rows: Vec<ConsumedSkippedKey> = sqlx::query_as(
        "SELECT dh_public_key, message_number FROM ratchet_consumed_skipped_keys WHERE device_id = $1 AND peer_device_id = $2",
    )
    .bind(device_id)
    .bind(peer_device_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::device::PrekeyUpload;
    use crate::routes::devices::{register_device, upload_prekeys, RegisterDeviceRequest, UploadPrekeysRequest};

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

    async fn register_test_device(db: &Database, user_id: Uuid, byte: u8, label: &str) -> Uuid {
        register_device(
            State(db.clone()),
            CurrentUser(user_id),
            Json(RegisterDeviceRequest {
                public_key: fake_public_key(byte),
                device_label: label.into(),
                // Registered with a signing key by default -- most of
                // these tests exercise `fetch_prekey_bundle`, which now
                // requires one (see migration 0039).
                signing_public_key: Some(fake_public_key(byte.wrapping_add(100))),
            }),
        )
        .await
        .expect("registering a device should succeed")
        .0
        .id
    }

    #[tokio::test]
    async fn fetch_prekey_bundle_consumes_one_time_prekey_exactly_once() {
        let db = test_db().await;
        let alice = create_test_user(&db).await;
        let bob = create_test_user(&db).await;
        let bob_device = register_test_device(&db, bob, 10, "Bob's Phone").await;

        let _ = upload_prekeys(
            State(db.clone()),
            CurrentUser(bob),
            Path(bob_device),
            Json(UploadPrekeysRequest {
                prekeys: vec![
                    PrekeyUpload { key_type: "signed".into(), public_key: fake_public_key(11), signature: Some(fake_public_key(12)) },
                    PrekeyUpload { key_type: "one_time".into(), public_key: fake_public_key(13), signature: None },
                ],
            }),
        )
        .await
        .expect("uploading prekeys should succeed");

        let bundle = fetch_prekey_bundle(State(db.clone()), CurrentUser(alice), Path(bob_device))
            .await
            .expect("fetching a prekey bundle should succeed")
            .0;
        assert!(bundle.one_time_prekey_id.is_some(), "the only unconsumed one-time prekey should be handed out");

        // A second fetch gets the signed prekey again (reusable) but no
        // one-time prekey this time -- there was only one, and it's consumed.
        let second = fetch_prekey_bundle(State(db.clone()), CurrentUser(alice), Path(bob_device))
            .await
            .expect("a second fetch should still succeed, just without a one-time prekey")
            .0;
        assert!(second.one_time_prekey_id.is_none(), "the one-time prekey must not be handed out twice");
        assert_eq!(second.signed_prekey_public_key, bundle.signed_prekey_public_key);

        cleanup_test_user(&db, alice).await;
        cleanup_test_user(&db, bob).await;
    }

    #[tokio::test]
    async fn fetch_prekey_bundle_is_rate_limited_per_target_device() {
        // Any authenticated caller may fetch any device's bundle (by
        // design), but each fetch that finds a one-time prekey consumes
        // it, so unlimited repeat fetches against the SAME target device
        // would let an attacker drain its whole stash. This proves the
        // limiter actually kicks in, and that it's scoped tightly enough
        // (per caller+target device) to leave a DIFFERENT target
        // completely unaffected.
        let db = test_db().await;
        let alice = create_test_user(&db).await;
        let bob = create_test_user(&db).await;
        let carol = create_test_user(&db).await;
        let bob_device = register_test_device(&db, bob, 30, "Bob's Laptop").await;
        let carol_device = register_test_device(&db, carol, 31, "Carol's Laptop").await;

        let _ = upload_prekeys(
            State(db.clone()),
            CurrentUser(bob),
            Path(bob_device),
            Json(UploadPrekeysRequest {
                prekeys: vec![PrekeyUpload { key_type: "signed".into(), public_key: fake_public_key(32), signature: Some(fake_public_key(33)) }],
            }),
        )
        .await
        .expect("uploading prekeys should succeed");

        // Exhaust the per-(caller, target device) limit against Bob's device.
        for i in 0..PREKEY_BUNDLE_FETCH_PER_TARGET_DEVICE.limit {
            let _ = fetch_prekey_bundle(State(db.clone()), CurrentUser(alice), Path(bob_device))
                .await
                .unwrap_or_else(|e| panic!("fetch {i} should still be under the limit, got {e:?}"));
        }
        let blocked = fetch_prekey_bundle(State(db.clone()), CurrentUser(alice), Path(bob_device)).await;
        assert!(
            matches!(blocked, Err(AppError::TooManyRequests { .. })),
            "the fetch just past the limit should be rate-limited, got {blocked:?}"
        );

        // The same caller fetching a DIFFERENT target device is a different
        // subject key and must be completely unaffected.
        let _ = upload_prekeys(
            State(db.clone()),
            CurrentUser(carol),
            Path(carol_device),
            Json(UploadPrekeysRequest {
                prekeys: vec![PrekeyUpload { key_type: "signed".into(), public_key: fake_public_key(34), signature: Some(fake_public_key(35)) }],
            }),
        )
        .await
        .expect("uploading prekeys should succeed");
        let _ = fetch_prekey_bundle(State(db.clone()), CurrentUser(alice), Path(carol_device))
            .await
            .expect("a different target device must not be affected by Bob's device being rate-limited");

        cleanup_test_user(&db, alice).await;
        cleanup_test_user(&db, bob).await;
        cleanup_test_user(&db, carol).await;
    }

    #[tokio::test]
    async fn fetch_prekey_bundle_fails_without_a_signed_prekey() {
        let db = test_db().await;
        let alice = create_test_user(&db).await;
        let bob = create_test_user(&db).await;
        let bob_device = register_test_device(&db, bob, 20, "Bob's Tablet").await;

        let result = fetch_prekey_bundle(State(db.clone()), CurrentUser(alice), Path(bob_device)).await;
        match result {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected NotFound when a device has no signed prekey yet, got {other:?}"),
        }

        cleanup_test_user(&db, alice).await;
        cleanup_test_user(&db, bob).await;
    }

    #[tokio::test]
    async fn ratchet_session_backup_round_trips_and_detects_concurrent_writes() {
        let db = test_db().await;
        let alice = create_test_user(&db).await;
        let bob = create_test_user(&db).await;
        let alice_device = register_test_device(&db, alice, 30, "Alice's Laptop").await;
        let bob_device = register_test_device(&db, bob, 31, "Bob's Phone").await;

        let created = put_ratchet_session(
            State(db.clone()),
            CurrentUser(alice),
            Path((alice_device, bob_device)),
            Json(PutRatchetSessionRequest { pickle_ciphertext: "ct-v1".into(), pickle_nonce: "n1".into(), expected_updated_at: None }),
        )
        .await
        .expect("creating a session backup should succeed")
        .0;

        let fetched = get_ratchet_session(State(db.clone()), CurrentUser(alice), Path((alice_device, bob_device)))
            .await
            .expect("fetching this device's own backup should succeed")
            .0;
        assert_eq!(fetched.pickle_ciphertext, "ct-v1");
        assert_eq!(fetched.updated_at, created.updated_at);

        // Bob's own backup of the SAME logical conversation is a totally
        // separate row (different owning device) -- it doesn't exist just
        // because Alice's does.
        let bobs_view =
            get_ratchet_session(State(db.clone()), CurrentUser(bob), Path((bob_device, alice_device))).await;
        match bobs_view {
            Err(AppError::NotFound(_)) => {}
            other => panic!("Bob's own session backup must be independent of Alice's, got {other:?}"),
        }

        // Advancing Alice's own backup with the correct expected_updated_at
        // succeeds...
        let advanced = put_ratchet_session(
            State(db.clone()),
            CurrentUser(alice),
            Path((alice_device, bob_device)),
            Json(PutRatchetSessionRequest {
                pickle_ciphertext: "ct-v2".into(),
                pickle_nonce: "n2".into(),
                expected_updated_at: Some(created.updated_at),
            }),
        )
        .await
        .expect("advancing with the correct expected_updated_at should succeed")
        .0;
        assert_eq!(advanced.pickle_ciphertext, "ct-v2");

        // ...but writing again with the NOW-STALE expected_updated_at is
        // rejected as a conflict, rather than clobbering the advanced state
        // (simulating two concurrent writers on Alice's own device).
        let conflict = put_ratchet_session(
            State(db.clone()),
            CurrentUser(alice),
            Path((alice_device, bob_device)),
            Json(PutRatchetSessionRequest {
                pickle_ciphertext: "ct-stale".into(),
                pickle_nonce: "n-stale".into(),
                expected_updated_at: Some(created.updated_at),
            }),
        )
        .await;
        match conflict {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected a conflict error when writing with a stale expected_updated_at, got {other:?}"),
        }

        cleanup_test_user(&db, alice).await;
        cleanup_test_user(&db, bob).await;
    }

    #[tokio::test]
    async fn cannot_read_or_write_another_users_device_session_backup() {
        let db = test_db().await;
        let alice = create_test_user(&db).await;
        let bob = create_test_user(&db).await;
        let alice_device = register_test_device(&db, alice, 40, "Alice's Laptop").await;
        let bob_device = register_test_device(&db, bob, 41, "Bob's Phone").await;

        // Bob tries to read/write a backup "as if" he owned Alice's device.
        let result = get_ratchet_session(State(db.clone()), CurrentUser(bob), Path((alice_device, bob_device))).await;
        match result {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected Forbidden for a user who doesn't own device_id, got {other:?}"),
        }

        let write_result = put_ratchet_session(
            State(db.clone()),
            CurrentUser(bob),
            Path((alice_device, bob_device)),
            Json(PutRatchetSessionRequest { pickle_ciphertext: "ct".into(), pickle_nonce: "n".into(), expected_updated_at: None }),
        )
        .await;
        match write_result {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected Forbidden for a write to a device_id the caller doesn't own, got {other:?}"),
        }

        cleanup_test_user(&db, alice).await;
        cleanup_test_user(&db, bob).await;
    }

    #[tokio::test]
    async fn consumed_skipped_key_ledger_is_append_only_and_idempotent() {
        let db = test_db().await;
        let alice = create_test_user(&db).await;
        let bob = create_test_user(&db).await;
        let alice_device = register_test_device(&db, alice, 50, "Alice's Laptop").await;
        let bob_device = register_test_device(&db, bob, 51, "Bob's Phone").await;

        // Nothing reported yet -- an empty list, not an error.
        let empty = list_consumed_skipped_keys(State(db.clone()), CurrentUser(alice), Path((alice_device, bob_device)))
            .await
            .expect("listing with nothing recorded yet should still succeed")
            .0;
        assert!(empty.is_empty());

        let report = |dh: &str, n: i32| {
            report_consumed_skipped_key(
                State(db.clone()),
                CurrentUser(alice),
                Path((alice_device, bob_device)),
                Json(ReportConsumedSkippedKeyRequest { dh_public_key: dh.into(), message_number: n }),
            )
        };

        report("dh-key-a", 3).await.expect("reporting a consumed skipped key should succeed");
        report("dh-key-a", 7).await.expect("a second, different slot under the same dh key should also succeed");
        // Reporting the exact same slot again (e.g. a retried request after
        // a dropped response) must be a harmless no-op, not an error and
        // not a duplicate row.
        report("dh-key-a", 3).await.expect("reporting the same slot twice should be idempotent, not an error");

        let recorded = list_consumed_skipped_keys(State(db.clone()), CurrentUser(alice), Path((alice_device, bob_device)))
            .await
            .expect("listing should succeed")
            .0;
        assert_eq!(recorded.len(), 2, "the duplicate report must not have created a third row");
        let slots: std::collections::HashSet<(String, i32)> =
            recorded.into_iter().map(|r| (r.dh_public_key, r.message_number)).collect();
        assert!(slots.contains(&("dh-key-a".to_string(), 3)));
        assert!(slots.contains(&("dh-key-a".to_string(), 7)));

        // Bob's own ledger for the same directed pair label is independent
        // -- nothing Alice reported leaks into a query under Bob's device.
        let bobs_view =
            list_consumed_skipped_keys(State(db.clone()), CurrentUser(bob), Path((bob_device, alice_device)))
                .await
                .expect("Bob listing his own (empty) ledger should succeed")
                .0;
        assert!(bobs_view.is_empty(), "Bob's ledger must not see what Alice reported for her own device");

        cleanup_test_user(&db, alice).await;
        cleanup_test_user(&db, bob).await;
    }

    #[tokio::test]
    async fn cannot_read_or_report_another_users_device_consumed_skipped_keys() {
        let db = test_db().await;
        let alice = create_test_user(&db).await;
        let bob = create_test_user(&db).await;
        let alice_device = register_test_device(&db, alice, 60, "Alice's Laptop").await;
        let bob_device = register_test_device(&db, bob, 61, "Bob's Phone").await;

        let read_result =
            list_consumed_skipped_keys(State(db.clone()), CurrentUser(bob), Path((alice_device, bob_device))).await;
        match read_result {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected Forbidden for a user who doesn't own device_id, got {other:?}"),
        }

        let write_result = report_consumed_skipped_key(
            State(db.clone()),
            CurrentUser(bob),
            Path((alice_device, bob_device)),
            Json(ReportConsumedSkippedKeyRequest { dh_public_key: "dh-key".into(), message_number: 1 }),
        )
        .await;
        match write_result {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected Forbidden for a report against a device_id the caller doesn't own, got {other:?}"),
        }

        cleanup_test_user(&db, alice).await;
        cleanup_test_user(&db, bob).await;
    }
}

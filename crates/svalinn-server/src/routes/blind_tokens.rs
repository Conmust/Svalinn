//! HTTP surface for anonymous patron-tier redemption. See
//! `crate::blind_tokens` for the cryptographic design.

use axum::extract::{Json, State};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::blind_tokens::{self, TIERS};
use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::{CurrentSession, CurrentUser};

#[derive(Serialize, Debug)]
pub struct SkuInfo {
    pub tier: String,
    /// DER-encoded (SPKI) RSA public key, base64. Importable directly via
    /// WebCrypto's `crypto.subtle.importKey('spki', ..., {name: 'RSA-PSS',
    /// hash: 'SHA-384'}, true, ['verify'])`.
    pub public_key_der: String,
}

/// GET /api/v1/blind-tokens/skus
///
/// Public: a client has to know every tier's public key before it can
/// blind anything against it.
pub async fn list_skus() -> Json<Vec<SkuInfo>> {
    let skus = TIERS
        .iter()
        .filter_map(|&tier| {
            blind_tokens::public_key_der(tier)
                .map(|der| SkuInfo { tier: tier.to_string(), public_key_der: B64.encode(der) })
        })
        .collect();
    Json(skus)
}

#[derive(Deserialize)]
pub struct MintReceiptRequest {
    pub tier: String,
}

#[derive(Serialize, Debug)]
pub struct MintReceiptResponse {
    pub tier: String,
    /// Hand this to whoever paid. It's single-use and unlocks exactly one
    /// blind-signing call for this tier -- nothing else.
    pub receipt_token: String,
}

/// POST /api/v1/admin/blind-token-receipts
///
/// Site-owner only, same guard as `routes::users::admin_update_patron_tier`.
/// This is the one deliberately non-anonymous step: today a human (the site
/// owner) confirms a payment happened and mints a receipt for it. Swap this
/// out for a payment-processor webhook later without touching anything else
/// -- the blind-sign/redeem endpoints below don't care where the receipt
/// came from.
pub async fn mint_receipt(
    State(db): State<Database>,
    CurrentSession { user_id, .. }: CurrentSession,
    Json(payload): Json<MintReceiptRequest>,
) -> Result<Json<MintReceiptResponse>, AppError> {
    let is_site_owner: bool =
        sqlx::query_scalar("SELECT COALESCE(site_role = 'owner', false) FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    if !is_site_owner {
        return Err(AppError::Forbidden("Only the site owner can mint blind-token receipts".into()));
    }

    if !blind_tokens::is_valid_tier(&payload.tier) {
        return Err(AppError::BadRequest("Invalid tier".into()));
    }

    let token = blind_tokens::new_receipt_token();
    let token_hash = blind_tokens::hash_receipt_token(&token);

    sqlx::query("INSERT INTO blind_token_receipts (tier, token_hash) VALUES ($1, $2)")
        .bind(&payload.tier)
        .bind(&token_hash)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(MintReceiptResponse { tier: payload.tier, receipt_token: token }))
}

#[derive(Deserialize)]
pub struct BlindSignRequest {
    pub tier: String,
    pub receipt_token: String,
    /// The client's blinded message, base64.
    pub blinded_message: String,
}

#[derive(Serialize, Debug)]
pub struct BlindSignResponse {
    /// The blind signature, base64. Meaningless to the server itself --
    /// only the client, holding the unblinding secret, can turn this into
    /// a usable (serial, signature) pair.
    pub blind_signature: String,
}

const MAX_BLINDED_MESSAGE_B64_CHARS: usize = 2000;

/// POST /api/v1/blind-tokens/blind-sign
///
/// Deliberately public -- no `CurrentUser`. Anyone holding a valid receipt
/// can call this from a fresh, unauthenticated context (ideally not even
/// the same session that will eventually redeem the token), which is what
/// keeps the eventual redemption from being linkable back to this moment.
pub async fn blind_sign(
    State(db): State<Database>,
    Json(payload): Json<BlindSignRequest>,
) -> Result<Json<BlindSignResponse>, AppError> {
    if !blind_tokens::is_valid_tier(&payload.tier) {
        return Err(AppError::BadRequest("Invalid tier".into()));
    }
    if payload.blinded_message.len() > MAX_BLINDED_MESSAGE_B64_CHARS {
        return Err(AppError::BadRequest("blinded_message is too large".into()));
    }
    let blinded_message = B64
        .decode(&payload.blinded_message)
        .map_err(|_| AppError::BadRequest("blinded_message is not valid base64".into()))?;

    let receipt_hash = blind_tokens::hash_receipt_token(&payload.receipt_token);

    // Atomically spend the receipt: this UPDATE only touches a row that is
    // still unconsumed, so two concurrent requests for the same receipt
    // can't both succeed.
    let consumed: Option<(uuid::Uuid,)> = sqlx::query_as(
        r#"
        UPDATE blind_token_receipts
        SET consumed_at = now()
        WHERE token_hash = $1 AND tier = $2 AND consumed_at IS NULL
        RETURNING id
        "#,
    )
    .bind(&receipt_hash)
    .bind(&payload.tier)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if consumed.is_none() {
        return Err(AppError::Forbidden("That receipt is invalid or has already been used".into()));
    }

    let blind_signature = blind_tokens::blind_sign(&payload.tier, &blinded_message)
        .map_err(AppError::Internal)?;

    Ok(Json(BlindSignResponse { blind_signature: B64.encode(blind_signature) }))
}

#[derive(Deserialize)]
pub struct RedeemRequest {
    pub tier: String,
    /// The client's finalized "prepared message" (message randomizer +
    /// original serial), base64.
    pub prepared_message: String,
    pub signature: String,
}

const MAX_PREPARED_MESSAGE_B64_CHARS: usize = 500;
const MAX_SIGNATURE_B64_CHARS: usize = 500;

/// POST /api/v1/blind-tokens/redeem
///
/// Requires login, because the tier has to land on some account -- but
/// nothing here or anywhere else records which receipt produced this
/// token, so there is no link back to whoever minted or paid for it.
pub async fn redeem(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Json(payload): Json<RedeemRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !blind_tokens::is_valid_tier(&payload.tier) {
        return Err(AppError::BadRequest("Invalid tier".into()));
    }
    if payload.prepared_message.len() > MAX_PREPARED_MESSAGE_B64_CHARS
        || payload.signature.len() > MAX_SIGNATURE_B64_CHARS
    {
        return Err(AppError::BadRequest("Token is too large".into()));
    }

    let prepared_message = B64
        .decode(&payload.prepared_message)
        .map_err(|_| AppError::BadRequest("prepared_message is not valid base64".into()))?;
    let signature = B64
        .decode(&payload.signature)
        .map_err(|_| AppError::BadRequest("signature is not valid base64".into()))?;

    blind_tokens::verify(&payload.tier, &prepared_message, &signature)
        .map_err(|_| AppError::BadRequest("That token isn't valid".into()))?;

    let serial_hash = blind_tokens::serial_hash(&prepared_message);

    let inserted: Option<(String,)> = sqlx::query_as(
        r#"
        INSERT INTO blind_token_redemptions (serial_hash, tier, redeemed_by)
        VALUES ($1, $2, $3)
        ON CONFLICT (serial_hash) DO NOTHING
        RETURNING serial_hash
        "#,
    )
    .bind(&serial_hash)
    .bind(&payload.tier)
    .bind(user_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if inserted.is_none() {
        return Err(AppError::BadRequest("That token has already been redeemed".into()));
    }

    // Only ever upgrades -- redeeming a "patron" token on an "enterprise"
    // account shouldn't demote it.
    sqlx::query(
        r#"
        UPDATE users
        SET patron_tier = $1
        WHERE id = $2 AND $3 > (
            SELECT CASE patron_tier WHEN 'free' THEN 0 WHEN 'patron' THEN 1 WHEN 'guild' THEN 2 WHEN 'enterprise' THEN 3 ELSE 0 END
            FROM users WHERE id = $2
        )
        "#,
    )
    .bind(&payload.tier)
    .bind(user_id)
    .bind(crate::tiers::tier_rank(&payload.tier) as i32)
    .execute(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({ "tier": payload.tier })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use blind_rsa_signatures::DefaultRng;
    use uuid::Uuid;

    /// Same database-connection convention as every other route test module
    /// in this crate (see `routes::users::tests::test_db`).
    async fn test_db() -> Database {
        dotenvy::dotenv().ok();
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is required for tests");
        let db = Database::new(&database_url).await.expect("failed to connect to test database");
        blind_tokens::init_keys(&db).await.expect("failed to init blind-token keys for tests");
        db
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

    async fn create_test_user_with_tier(db: &Database, tier: &str) -> Uuid {
        let id = create_test_user(db).await;
        sqlx::query("UPDATE users SET patron_tier = $1 WHERE id = $2")
            .bind(tier)
            .bind(id)
            .execute(&db.pool)
            .await
            .expect("failed to set test user's tier");
        id
    }

    async fn create_test_site_owner(db: &Database) -> Uuid {
        let unique = Uuid::new_v4();
        sqlx::query_scalar(
            "INSERT INTO users (username, email, password_hash, display_name, site_role) VALUES ($1, $2, $3, $4, 'owner') RETURNING id",
        )
        .bind(format!("test_{unique}"))
        .bind(format!("test_{unique}@example.invalid"))
        .bind("not-a-real-hash")
        .bind(format!("Test Owner {unique}"))
        .fetch_one(&db.pool)
        .await
        .expect("failed to insert test site owner")
    }

    async fn cleanup_test_user(db: &Database, user_id: Uuid) {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1").bind(user_id).execute(&db.pool).await;
    }

    /// Stands in for apps/desktop/src/lib/blind-tokens.ts: blinds a fresh
    /// random serial against a tier's public key using the same
    /// blind-rsa-signatures crate the server uses (the real client uses
    /// @cloudflare/blindrsa-ts instead -- different implementation of the
    /// same RFC 9474 ciphersuite, so this only exercises the server's half
    /// of the protocol, not cross-implementation interop).
    fn client_blind(tier: &str) -> (blind_rsa_signatures::PublicKeySha384PSSRandomized, blind_rsa_signatures::BlindingResult, [u8; 32]) {
        let der = blind_tokens::public_key_der(tier).expect("tier should have a key");
        let pk = blind_rsa_signatures::PublicKeySha384PSSRandomized::from_der(&der).unwrap();
        let serial: [u8; 32] = rand::random();
        let blinding_result = pk.blind(&mut DefaultRng, serial).expect("blind should succeed");
        (pk, blinding_result, serial)
    }

    fn client_finalize(
        pk: &blind_rsa_signatures::PublicKeySha384PSSRandomized,
        blinding_result: &blind_rsa_signatures::BlindingResult,
        serial: &[u8; 32],
        blind_sig_bytes: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let blind_sig = blind_rsa_signatures::BlindSignature(blind_sig_bytes.to_vec());
        let sig = pk.finalize(&blind_sig, blinding_result, serial).expect("finalize should succeed");
        let randomizer = blinding_result.msg_randomizer.expect("randomized variant always has one").0;
        let mut prepared_message = randomizer.to_vec();
        prepared_message.extend_from_slice(serial);
        (prepared_message, sig.0)
    }

    async fn mint_test_receipt(db: &Database, tier: &str) -> String {
        let token = blind_tokens::new_receipt_token();
        sqlx::query("INSERT INTO blind_token_receipts (tier, token_hash) VALUES ($1, $2)")
            .bind(tier)
            .bind(blind_tokens::hash_receipt_token(&token))
            .execute(&db.pool)
            .await
            .expect("failed to insert test receipt");
        token
    }

    #[tokio::test]
    async fn non_site_owner_cannot_mint_a_receipt() {
        let db = test_db().await;
        let caller = create_test_user(&db).await;

        let result = mint_receipt(
            State(db.clone()),
            CurrentSession { user_id: caller, session_id: Uuid::new_v4() },
            Json(MintReceiptRequest { tier: "patron".into() }),
        )
        .await;

        match result {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected Forbidden, got {other:?}"),
        }

        cleanup_test_user(&db, caller).await;
    }

    #[tokio::test]
    async fn mint_receipt_rejects_an_invalid_tier() {
        let db = test_db().await;
        let owner = create_test_site_owner(&db).await;

        let result = mint_receipt(
            State(db.clone()),
            CurrentSession { user_id: owner, session_id: Uuid::new_v4() },
            Json(MintReceiptRequest { tier: "nonsense".into() }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected BadRequest, got {other:?}"),
        }

        cleanup_test_user(&db, owner).await;
    }

    #[tokio::test]
    async fn full_round_trip_blinds_signs_and_redeems_exactly_once() {
        let db = test_db().await;
        let owner = create_test_site_owner(&db).await;
        let buyer = create_test_user(&db).await;
        let tier = "patron";

        let receipt_token = mint_test_receipt(&db, tier).await;

        let (pk, blinding_result, serial) = client_blind(tier);

        let sign_response = blind_sign(
            State(db.clone()),
            Json(BlindSignRequest {
                tier: tier.into(),
                receipt_token: receipt_token.clone(),
                blinded_message: B64.encode(&blinding_result.blind_message),
            }),
        )
        .await
        .expect("blind_sign should succeed with a valid, unused receipt");

        let blind_sig_bytes = B64.decode(&sign_response.0.blind_signature).unwrap();
        let (prepared_message, signature) = client_finalize(&pk, &blinding_result, &serial, &blind_sig_bytes);

        // Spending the same receipt a second time must fail.
        let (_, blinding_result2, _) = client_blind(tier);
        let reuse_result = blind_sign(
            State(db.clone()),
            Json(BlindSignRequest {
                tier: tier.into(),
                receipt_token: receipt_token.clone(),
                blinded_message: B64.encode(&blinding_result2.blind_message),
            }),
        )
        .await;
        match reuse_result {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected a spent receipt to be rejected, got {other:?}"),
        }

        // Redemption lands the tier on the buyer's account, even though
        // nothing connects this call to the site owner who minted the
        // receipt or to whatever payment prompted it.
        let redeem_result = redeem(
            State(db.clone()),
            CurrentUser(buyer),
            Json(RedeemRequest {
                tier: tier.into(),
                prepared_message: B64.encode(&prepared_message),
                signature: B64.encode(&signature),
            }),
        )
        .await
        .expect("redeem should succeed with a valid, unspent token");
        assert_eq!(redeem_result.0["tier"], tier);

        let patron_tier: String =
            sqlx::query_scalar("SELECT patron_tier FROM users WHERE id = $1").bind(buyer).fetch_one(&db.pool).await.unwrap();
        assert_eq!(patron_tier, tier);

        // Redeeming the exact same token again must fail.
        let double_spend = redeem(
            State(db.clone()),
            CurrentUser(buyer),
            Json(RedeemRequest {
                tier: tier.into(),
                prepared_message: B64.encode(&prepared_message),
                signature: B64.encode(&signature),
            }),
        )
        .await;
        match double_spend {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected a double-spent token to be rejected, got {other:?}"),
        }

        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, buyer).await;
    }

    #[tokio::test]
    async fn redeem_rejects_a_tampered_signature() {
        let db = test_db().await;
        let owner = create_test_site_owner(&db).await;
        let buyer = create_test_user(&db).await;
        let tier = "guild";

        let receipt_token = mint_test_receipt(&db, tier).await;
        let (pk, blinding_result, serial) = client_blind(tier);
        let sign_response = blind_sign(
            State(db.clone()),
            Json(BlindSignRequest {
                tier: tier.into(),
                receipt_token,
                blinded_message: B64.encode(&blinding_result.blind_message),
            }),
        )
        .await
        .unwrap();
        let blind_sig_bytes = B64.decode(&sign_response.0.blind_signature).unwrap();
        let (prepared_message, mut signature) = client_finalize(&pk, &blinding_result, &serial, &blind_sig_bytes);
        signature[0] ^= 0xff; // tamper

        let result = redeem(
            State(db.clone()),
            CurrentUser(buyer),
            Json(RedeemRequest {
                tier: tier.into(),
                prepared_message: B64.encode(&prepared_message),
                signature: B64.encode(&signature),
            }),
        )
        .await;
        match result {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected a tampered signature to be rejected, got {other:?}"),
        }

        let patron_tier: String =
            sqlx::query_scalar("SELECT patron_tier FROM users WHERE id = $1").bind(buyer).fetch_one(&db.pool).await.unwrap();
        assert_eq!(patron_tier, "free", "a rejected token must not grant anything");

        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, buyer).await;
    }

    #[tokio::test]
    async fn redeeming_a_lower_tier_token_never_downgrades_an_existing_higher_tier() {
        let db = test_db().await;
        let owner = create_test_site_owner(&db).await;
        let buyer = create_test_user_with_tier(&db, "enterprise").await;
        let tier = "patron";

        let receipt_token = mint_test_receipt(&db, tier).await;
        let (pk, blinding_result, serial) = client_blind(tier);
        let sign_response = blind_sign(
            State(db.clone()),
            Json(BlindSignRequest {
                tier: tier.into(),
                receipt_token,
                blinded_message: B64.encode(&blinding_result.blind_message),
            }),
        )
        .await
        .unwrap();
        let blind_sig_bytes = B64.decode(&sign_response.0.blind_signature).unwrap();
        let (prepared_message, signature) = client_finalize(&pk, &blinding_result, &serial, &blind_sig_bytes);

        redeem(
            State(db.clone()),
            CurrentUser(buyer),
            Json(RedeemRequest {
                tier: tier.into(),
                prepared_message: B64.encode(&prepared_message),
                signature: B64.encode(&signature),
            }),
        )
        .await
        .expect("redeem itself should still succeed (the token is valid and unspent)");

        let patron_tier: String =
            sqlx::query_scalar("SELECT patron_tier FROM users WHERE id = $1").bind(buyer).fetch_one(&db.pool).await.unwrap();
        assert_eq!(patron_tier, "enterprise", "a lower-tier token must not downgrade an existing higher tier");

        cleanup_test_user(&db, owner).await;
        cleanup_test_user(&db, buyer).await;
    }
}

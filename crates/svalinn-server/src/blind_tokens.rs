//! Anonymous patron-tier grants via RFC 9474 blind RSA signatures.
//!
//! The three moves, spread across time so they can't be correlated:
//!
//! 1. Someone pays for a tier through whatever channel you like (today:
//!    cash/voucher handled off-platform, confirmed by the site owner).
//!    The site owner mints a one-time *receipt* for that tier
//!    (`routes::blind_tokens::mint_receipt`).
//! 2. Whoever holds the receipt runs the client-side blind-RSA flow: blind
//!    a random serial, spend the receipt to get it blind-signed
//!    (`blind_sign`), then unblind locally. The server sees only an opaque
//!    blinded value -- it cannot read the serial it just signed.
//! 3. Later -- on any account, any device, any time -- that finished
//!    (serial, signature) pair is redeemed for the tier (`redeem`). The
//!    server can verify the signature is genuine, but has no way to tell
//!    which receipt produced it: the blinding factor made step 2's signing
//!    operation and this verification cryptographically unlinkable.
//!
//! The server never needs its own blind()/finalize() -- those are client
//! operations (see apps/desktop/src/lib/blind-tokens.ts, built on
//! @cloudflare/blindrsa-ts, which implements the same RFC 9474 ciphersuite:
//! RSABSSA-SHA384-PSS-Randomized).

use std::collections::HashMap;
use std::sync::OnceLock;

use blind_rsa_signatures::{
    BlindSignature, DefaultRng, KeyPairSha384PSSRandomized as KeyPair,
    MessageRandomizer, PublicKeySha384PSSRandomized as PublicKey,
    SecretKeySha384PSSRandomized as SecretKey, Signature,
};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::db::Database;

/// Tiers that can be bought this way. Deliberately excludes "free" --
/// nobody redeems a token for the tier everyone already has.
pub const TIERS: [&str; 3] = ["patron", "guild", "enterprise"];

const RSA_MODULUS_BITS: usize = 2048;

struct SkuKeys {
    public_key: PublicKey,
    secret_key: SecretKey,
}

static KEYS: OnceLock<HashMap<&'static str, SkuKeys>> = OnceLock::new();

/// Loads each tier's blind-signing keypair, generating and persisting one
/// the first time a tier is seen. Call once at startup, after migrations
/// have run.
pub async fn init_keys(db: &Database) -> Result<(), String> {
    // Idempotent: main() calls this once at startup, but every test module
    // that exercises these routes directly (no main() in sight) also needs
    // the keys loaded, and many such tests run concurrently in the same
    // process.
    if KEYS.get().is_some() {
        return Ok(());
    }

    let mut map = HashMap::new();

    for tier in TIERS {
        let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT secret_key_der, public_key_der FROM blind_token_skus WHERE tier = $1",
        )
        .bind(tier)
        .fetch_optional(&db.pool)
        .await
        .map_err(|e| format!("Couldn't load blind-token keys for {tier}: {e}"))?;

        let (secret_key, public_key) = match row {
            Some((sk_der, pk_der)) => {
                let secret_key = SecretKey::from_der(&sk_der)
                    .map_err(|e| format!("Stored blind-token secret key for {tier} is invalid: {e}"))?;
                let public_key = PublicKey::from_der(&pk_der)
                    .map_err(|e| format!("Stored blind-token public key for {tier} is invalid: {e}"))?;
                (secret_key, public_key)
            }
            None => {
                // First time this tier has ever been seen -- mint its
                // keypair and persist it so every future restart reuses the
                // same one (rotating it would strand any outstanding,
                // not-yet-redeemed token).
                let kp = KeyPair::generate(&mut DefaultRng, RSA_MODULUS_BITS)
                    .map_err(|e| format!("Couldn't generate blind-token keypair for {tier}: {e}"))?;
                let sk_der = kp.sk.to_der().map_err(|e| e.to_string())?;
                let pk_der = kp.pk.to_der().map_err(|e| e.to_string())?;

                sqlx::query(
                    r#"
                    INSERT INTO blind_token_skus (tier, secret_key_der, public_key_der)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (tier) DO NOTHING
                    "#,
                )
                .bind(tier)
                .bind(&sk_der)
                .bind(&pk_der)
                .execute(&db.pool)
                .await
                .map_err(|e| format!("Couldn't save blind-token keypair for {tier}: {e}"))?;

                (kp.sk, kp.pk)
            }
        };

        map.insert(tier, SkuKeys { public_key, secret_key });
    }

    // If another concurrent caller won the race and set this first, that's
    // fine -- just use what's there instead of erroring.
    let _ = KEYS.set(map);
    Ok(())
}

fn keys() -> &'static HashMap<&'static str, SkuKeys> {
    KEYS.get().expect("blind_tokens::init_keys must be called at startup")
}

pub fn is_valid_tier(tier: &str) -> bool {
    TIERS.contains(&tier)
}

/// The DER-encoded (SPKI) public key for a tier, for clients to import and
/// blind against. `None` for an unrecognized tier.
pub fn public_key_der(tier: &str) -> Option<Vec<u8>> {
    keys().get(tier).and_then(|k| k.public_key.to_der().ok())
}

/// Signs an already-blinded message. The server cannot recover the
/// original message from `blind_msg` -- that's the entire point.
pub fn blind_sign(tier: &str, blind_msg: &[u8]) -> Result<Vec<u8>, String> {
    let sk = &keys().get(tier).ok_or_else(|| "unknown tier".to_string())?.secret_key;
    let sig: BlindSignature = sk.blind_sign(blind_msg).map_err(|e| e.to_string())?;
    Ok(sig.0)
}

/// Verifies a finished (unblinded) token against its tier's public key.
/// `prepared_message` is the client's RSABSSA "prepared message": for the
/// Randomized variant that's a 32-byte message randomizer followed by the
/// original random serial.
pub fn verify(tier: &str, prepared_message: &[u8], signature: &[u8]) -> Result<(), String> {
    const RANDOMIZER_LEN: usize = 32;
    if prepared_message.len() <= RANDOMIZER_LEN {
        return Err("prepared message is too short".into());
    }
    let (randomizer_bytes, msg) = prepared_message.split_at(RANDOMIZER_LEN);
    let mut randomizer = [0u8; RANDOMIZER_LEN];
    randomizer.copy_from_slice(randomizer_bytes);

    let pk = &keys().get(tier).ok_or_else(|| "unknown tier".to_string())?.public_key;
    pk.verify(&Signature(signature.to_vec()), Some(MessageRandomizer(randomizer)), msg)
        .map_err(|e| e.to_string())
}

/// SHA-256 of the original serial (the part of the prepared message after
/// the randomizer), used only to block redeeming the same token twice.
/// Hex-encoded so it drops straight into a TEXT column, same convention as
/// `routes::auth::hash_token`.
pub fn serial_hash(prepared_message: &[u8]) -> String {
    let serial = &prepared_message[32.min(prepared_message.len())..];
    to_hex(&Sha256::digest(serial))
}

/// 256 random bits, hex encoded -- a one-time receipt token.
pub fn new_receipt_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    to_hex(&bytes)
}

/// Receipts are stored as SHA-256 hashes, same reasoning as refresh tokens:
/// a database leak shouldn't hand out spendable receipts.
pub fn hash_receipt_token(token: &str) -> String {
    to_hex(&Sha256::digest(token.as_bytes()))
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

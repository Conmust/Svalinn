//! Keeps real email addresses out of plaintext storage while still letting
//! the server do the things it actually needs an email for: log someone in,
//! enforce "one account per email", and recognize a banned email trying to
//! come back under a new account.
//!
//! Two independent secrets, both read once at startup (see `init_keys`,
//! mirroring `extractors::auth::init_jwt_secret`) and never logged:
//!
//! - `EMAIL_ENCRYPTION_KEY`: a 32-byte AES-256-GCM key (base64), used by
//!   [`encrypt`]/[`decrypt`] to recover the real address for the one place
//!   that still needs it (sending a verification or password-reset email).
//!   Encryption is randomized (a fresh nonce every call), so the same email
//!   encrypts differently each time -- which is exactly why it alone can't
//!   be used to look anyone up.
//! - `EMAIL_BLIND_INDEX_PEPPER`: a secret used to key [`blind_index`], a
//!   deterministic HMAC-SHA256 of the normalized address. Same input always
//!   produces the same output, so it works as an opaque, hash-only stand-in
//!   for the email in every `WHERE` clause (uniqueness, login lookup,
//!   matching against `banned_emails`) -- without the column, or anything
//!   that reads it, ever seeing the address itself. A stolen database dump
//!   reveals nothing about anyone's email from this column alone; the
//!   pepper lives only in the server's environment, not in the database.
//!
//! Losing the encryption key makes every stored email permanently
//! unrecoverable (nothing to send a password-reset link to); losing the
//! pepper doesn't lose data, but changes every future blind index, so old
//! and new rows would stop matching each other -- back up both, but treat
//! the pepper as the one that must never change once chosen.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

const NONCE_LEN: usize = 12;
const MIN_PEPPER_LENGTH: usize = 16;

static ENCRYPTION_KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
static BLIND_INDEX_PEPPER: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Reads `EMAIL_ENCRYPTION_KEY` and `EMAIL_BLIND_INDEX_PEPPER` from the
/// environment and stores them. Call once at startup, right alongside
/// `init_jwt_secret`. Returns an optional warning (dev-only shortcuts that
/// are fine locally but shouldn't ship), or an error if the server must not
/// start at all.
pub fn init_keys(app_env: &str) -> Result<Option<String>, String> {
    let key_b64 = std::env::var("EMAIL_ENCRYPTION_KEY").unwrap_or_default();
    let pepper = std::env::var("EMAIL_BLIND_INDEX_PEPPER").unwrap_or_default();
    let mut warnings = Vec::new();

    if key_b64.trim().is_empty() {
        return Err("EMAIL_ENCRYPTION_KEY is not set. Add a base64-encoded 32-byte key to your .env file (e.g. `openssl rand -base64 32`).".into());
    }
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(key_b64.trim())
        .map_err(|e| format!("EMAIL_ENCRYPTION_KEY is not valid base64: {e}"))?;
    let key: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
        format!(
            "EMAIL_ENCRYPTION_KEY must decode to exactly 32 bytes (got {}). Generate one with `openssl rand -base64 32`.",
            key_bytes.len()
        )
    })?;

    if pepper.trim().is_empty() {
        return Err("EMAIL_BLIND_INDEX_PEPPER is not set. Add a long random value to your .env file.".into());
    }
    if pepper.trim().chars().count() < MIN_PEPPER_LENGTH {
        let msg = format!("EMAIL_BLIND_INDEX_PEPPER is shorter than {MIN_PEPPER_LENGTH} characters.");
        if app_env == "development" {
            warnings.push(format!("{msg} That's fine for local development, but use a long random value anywhere else."));
        } else {
            return Err(format!("{msg} Use a long random value (APP_ENV is not \"development\")."));
        }
    }

    let _ = ENCRYPTION_KEY.set(key);
    let _ = BLIND_INDEX_PEPPER.set(pepper.trim().to_string());
    Ok(warnings.into_iter().next())
}

fn encryption_key() -> &'static [u8; 32] {
    ENCRYPTION_KEY.get().expect("init_keys must be called before any email_privacy function")
}

fn pepper() -> &'static str {
    BLIND_INDEX_PEPPER.get().expect("init_keys must be called before any email_privacy function")
}

/// Trims and lowercases so the same real address -- however a client happens
/// to capitalize it -- always produces the same ciphertext input and the
/// same blind index.
fn normalize(email: &str) -> String {
    email.trim().to_lowercase()
}

/// A deliberately loose shape check (has an `@`, a non-empty local part, a
/// domain with a dot that doesn't start/end with one, no whitespace, a sane
/// length) -- not a full RFC 5322 parser. The verification-link flow is
/// what actually proves the address is reachable; this just catches typos
/// and garbage before bothering to send anything.
pub fn is_plausible_format(email: &str) -> bool {
    let email = email.trim();
    email.len() <= 255
        && !email.contains(char::is_whitespace)
        && email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.'))
}

/// Encrypts an email for storage. Randomized -- never use the output to
/// compare two emails for equality; use `blind_index` for that instead.
pub fn encrypt(email: &str) -> String {
    let cipher = Aes256Gcm::new(encryption_key().into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypting normalized (not raw) input means decrypt() always returns
    // the same canonical form that was hashed -- display code doesn't need
    // to separately re-normalize before comparing it to anything.
    let ciphertext = cipher
        .encrypt(nonce, normalize(email).as_bytes())
        .expect("AES-GCM encryption with a valid 32-byte key cannot fail");

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    base64::engine::general_purpose::STANDARD.encode(out)
}

#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error("stored value is not valid base64")]
    Encoding,
    #[error("stored value is too short to contain a nonce")]
    Truncated,
    #[error("decryption failed (wrong key, or data was tampered with)")]
    Cipher,
    #[error("decrypted bytes are not valid UTF-8")]
    NotUtf8,
}

/// Recovers the real email from `encrypt`'s output. The only legitimate
/// uses are sending mail to it (verification, password reset) and one-time
/// migration backfills -- never a lookup/comparison path.
pub fn decrypt(stored: &str) -> Result<String, DecryptError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(stored)
        .map_err(|_| DecryptError::Encoding)?;
    if raw.len() < NONCE_LEN {
        return Err(DecryptError::Truncated);
    }
    let (nonce_bytes, ciphertext) = raw.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(encryption_key().into());
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| DecryptError::Cipher)?;
    String::from_utf8(plaintext).map_err(|_| DecryptError::NotUtf8)
}

/// A deterministic, keyed stand-in for an email, safe to store and index.
/// Two calls with the same real address (any capitalization/whitespace)
/// always produce the same string; recovering the address from it requires
/// the pepper, which never leaves the server's environment.
pub fn blind_index(email: &str) -> String {
    type HmacSha256 = Hmac<Sha256>;
    // Fully qualified: `aes_gcm::aead::KeyInit` (imported above for AES) and
    // `hmac::Mac` both define `new_from_slice`, so plain method-call syntax
    // is ambiguous here.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(pepper().as_bytes()).expect("HMAC accepts a key of any length");
    mac.update(normalize(email).as_bytes());
    let bytes = mac.finalize().into_bytes();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test_keys() {
        // Fixed, obviously-fake values -- fine for tests, OnceLock makes a
        // second init() in the same test binary a harmless no-op.
        let _ = ENCRYPTION_KEY.set([7u8; 32]);
        let _ = BLIND_INDEX_PEPPER.set("test-pepper-not-for-real-use".to_string());
    }

    #[test]
    fn encrypt_decrypt_roundtrips() {
        init_test_keys();
        let email = "Alice@Example.com";
        let ciphertext = encrypt(email);
        assert_eq!(decrypt(&ciphertext).unwrap(), "alice@example.com");
    }

    #[test]
    fn encrypt_is_randomized() {
        init_test_keys();
        assert_ne!(encrypt("alice@example.com"), encrypt("alice@example.com"));
    }

    #[test]
    fn blind_index_is_deterministic_and_case_insensitive() {
        init_test_keys();
        assert_eq!(blind_index("Alice@Example.com"), blind_index(" alice@example.com "));
    }

    #[test]
    fn blind_index_differs_for_different_emails() {
        init_test_keys();
        assert_ne!(blind_index("alice@example.com"), blind_index("bob@example.com"));
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        init_test_keys();
        let mut ciphertext = base64::engine::general_purpose::STANDARD.decode(encrypt("alice@example.com")).unwrap();
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;
        let tampered = base64::engine::general_purpose::STANDARD.encode(ciphertext);
        assert!(matches!(decrypt(&tampered), Err(DecryptError::Cipher)));
    }
}

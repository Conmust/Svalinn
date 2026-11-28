//! TOTP (RFC 6238, on top of RFC 4226's HOTP) -- the standard "6-digit code
//! that changes every 30 seconds" used by authenticator apps (Google
//! Authenticator, Authy, 1Password, etc.). No crate pulled in for this: the
//! algorithm is small, and the project already depends on `hmac` and
//! `sha1` for other things, so this is the whole implementation.
//!
//! A secret here is always raw bytes. Storage encrypts/decrypts it with
//! `email_privacy`'s AES-256-GCM key (see that module's doc comment) --
//! there's no reason to manage a second encryption key for one more small
//! secret with the exact same requirement: recoverable by the server to
//! check codes, never stored in plaintext.

use hmac::{Hmac, Mac};
use sha1::Sha1;

/// Standard TOTP step size. Fixed, not configurable -- every authenticator
/// app assumes 30 seconds, and there's no reason for Svalinn to disagree.
const STEP_SECONDS: u64 = 30;
/// How many steps of clock drift either side of "now" to still accept.
/// ±1 step (so up to ~59s of total drift depending on exactly when within
/// a step the code was generated) covers normal phone-clock skew without
/// opening much of a guessing window -- each extra step roughly triples the
/// number of codes an attacker could have standing, so this stays small.
const WINDOW_STEPS: i64 = 1;

/// 160 bits, the size RFC 4226 recommends for HOTP/TOTP secrets.
const SECRET_LEN: usize = 20;

/// A fresh random secret, raw bytes (not yet base32'd or encrypted --
/// callers do both separately, since they're needed at different times:
/// base32 for display during setup, encryption for storage).
pub fn generate_secret() -> Vec<u8> {
    let mut bytes = vec![0u8; SECRET_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    bytes
}

/// RFC 4648 base32, no padding -- the form every authenticator app expects
/// when a secret is typed in or embedded in an `otpauth://` URI.
pub fn to_base32(secret: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, secret)
}

/// The `otpauth://` URI a QR code encodes. `account_name` and `issuer` are
/// shown in the authenticator app's list (issuer as the entry's "site",
/// account name as the entry's label) -- URL-encoded since either could in
/// principle contain characters that need escaping (a username can include
/// a handful of symbols; see routes::auth's username rules).
pub fn otpauth_uri(secret: &[u8], account_name: &str, issuer: &str) -> String {
    let encode = |s: &str| urlencoding_light(s);
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        encode(issuer),
        encode(account_name),
        to_base32(secret),
        encode(issuer),
    )
}

/// Percent-encodes just enough for a URI path segment / query value -- no
/// dependency pulled in for this; TOTP labels are short, plain strings
/// (issuer is a fixed literal, account name is a username or email) so a
/// small, conservative allow-list is all that's needed.
fn urlencoding_light(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts a key of any length");
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let truncated = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);
    truncated % 1_000_000
}

fn step_for(unix_time: u64) -> u64 {
    unix_time / STEP_SECONDS
}

/// Formats a step's code the way an authenticator app displays it: 6
/// digits, zero-padded.
fn format_code(code: u32) -> String {
    format!("{code:06}")
}

/// Checks `code` against the steps from `unix_time`, within
/// [`WINDOW_STEPS`] either side, skipping `last_used_step` if given (replay
/// protection -- a step already accepted once is never accepted again).
/// Returns the matching step number on success, so the caller can persist
/// it as the new `last_used_step`.
///
/// Comparing six-digit codes directly (not in constant time) is standard
/// practice for TOTP: the real defense against guessing is rate limiting
/// attempts, not timing-safe comparison of a value with only a million
/// possibilities.
pub fn verify(secret: &[u8], code: &str, unix_time: u64, last_used_step: Option<i64>) -> Option<i64> {
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now_step = step_for(unix_time) as i64;
    for delta in -WINDOW_STEPS..=WINDOW_STEPS {
        let step = now_step + delta;
        if step < 0 || last_used_step == Some(step) {
            continue;
        }
        if format_code(hotp(secret, step as u64)) == code {
            return Some(step);
        }
    }
    None
}

/// The code valid right now for `secret`. Test-only: production code always
/// goes through `verify` (which also handles drift and replay), never
/// generates a code of its own -- this exists so tests elsewhere in the
/// crate (routes::users, routes::auth) can drive a real `verify()` call
/// from a secret they only have in encrypted/base32 form, without
/// reimplementing HOTP themselves.
#[cfg(test)]
pub(crate) fn current_code(secret: &[u8], unix_time: u64) -> String {
    format_code(hotp(secret, step_for(unix_time)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_rfc_6238_sha1_test_vector() {
        // RFC 6238 Appendix B's SHA-1 test vectors use the 20-byte ASCII
        // secret "12345678901234567890" and assert the code at a handful of
        // fixed Unix times -- this is the canonical cross-implementation
        // check that the HOTP/TOTP math here is actually right, not just
        // internally self-consistent.
        let secret = b"12345678901234567890";
        assert_eq!(format_code(hotp(secret, step_for(59))), "287082");
        assert_eq!(format_code(hotp(secret, step_for(1111111109))), "081804");
        assert_eq!(format_code(hotp(secret, step_for(1111111111))), "050471");
        assert_eq!(format_code(hotp(secret, step_for(1234567890))), "005924");
        assert_eq!(format_code(hotp(secret, step_for(2000000000))), "279037");
        assert_eq!(format_code(hotp(secret, step_for(20000000000))), "353130");
    }

    #[test]
    fn verify_accepts_the_current_code_and_rejects_a_wrong_one() {
        let secret = generate_secret();
        let now = 1_700_000_000u64;
        let code = format_code(hotp(&secret, step_for(now)));
        assert_eq!(verify(&secret, &code, now, None), Some(step_for(now) as i64));
        assert_eq!(verify(&secret, "000000", now, None), None);
    }

    #[test]
    fn verify_tolerates_small_clock_drift_but_not_large() {
        let secret = generate_secret();
        let now = 1_700_000_000u64;
        let one_step_ahead = format_code(hotp(&secret, step_for(now) + 1));
        assert!(verify(&secret, &one_step_ahead, now, None).is_some());

        let five_steps_ahead = format_code(hotp(&secret, step_for(now) + 5));
        assert_eq!(verify(&secret, &five_steps_ahead, now, None), None);
    }

    #[test]
    fn verify_refuses_to_accept_the_same_step_twice() {
        let secret = generate_secret();
        let now = 1_700_000_000u64;
        let step = step_for(now) as i64;
        let code = format_code(hotp(&secret, step as u64));
        assert_eq!(verify(&secret, &code, now, Some(step)), None);
        // A different, still-valid step in the window is unaffected.
        let next = format_code(hotp(&secret, (step + 1) as u64));
        assert_eq!(verify(&secret, &next, now, Some(step)), Some(step + 1));
    }

    #[test]
    fn otpauth_uri_escapes_the_label_and_carries_the_base32_secret() {
        let secret = generate_secret();
        let uri = otpauth_uri(&secret, "a b@example.test", "Svalinn");
        assert!(uri.starts_with("otpauth://totp/Svalinn:a%20b%40example.test?"));
        assert!(uri.contains(&format!("secret={}", to_base32(&secret))));
        assert!(uri.contains("issuer=Svalinn"));
    }
}

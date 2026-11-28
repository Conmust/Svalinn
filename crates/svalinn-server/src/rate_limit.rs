//! In-memory rate limiting for login, registration and invite codes.
//!
//! Each key (for example "login-ip:203.0.113.5") keeps the times of its recent
//! attempts; once a key has `limit` attempts within `window`, further attempts
//! are refused until the oldest one ages out. Counts live in this process, so
//! they reset on restart and aren't shared between several server instances.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;

use crate::errors::AppError;

/// A rule: at most `limit` attempts per `window`.
#[derive(Clone, Copy)]
pub struct Rule {
    pub name: &'static str,
    pub limit: usize,
    pub window: Duration,
}

/// Any login attempt from one IP address.
pub const LOGIN_PER_IP: Rule = Rule { name: "login-ip", limit: 20, window: Duration::from_secs(5 * 60) };
/// Failed logins for one account from one IP address. Reset by a successful
/// login. This is the real brute-force throttle: it's what actually stops
/// someone guessing passwords against one account, and it's tight because
/// it only ever penalizes the IP doing the guessing.
pub const LOGIN_FAILURES_PER_ACCOUNT_IP: Rule =
    Rule { name: "login-account-ip", limit: 5, window: Duration::from_secs(15 * 60) };
/// Failed logins for one account, from anywhere, combined. Reset by a
/// successful login. Deliberately looser than the per-(account, IP) rule
/// above: this one is keyed on the account alone, with no IP in the key, so
/// an attacker who knows nothing but a victim's email can trip it from a
/// single IP with a handful of wrong passwords -- which would lock the
/// legitimate owner out of their own account for the window's duration,
/// with no password or access of any kind required to cause that. Its only
/// job is to catch a *distributed* brute force (many IPs against the same
/// account) that the per-IP rule above can't see; it must never be tight
/// enough for one attacker, from one IP, to deny the real owner a login.
pub const LOGIN_FAILURES_PER_ACCOUNT: Rule = Rule { name: "login-account", limit: 30, window: Duration::from_secs(15 * 60) };
/// New accounts from one IP address.
pub const REGISTER_PER_IP: Rule = Rule { name: "register-ip", limit: 5, window: Duration::from_secs(60 * 60) };
/// Invite lookups and joins by one user (stops guessing codes).
pub const INVITES_PER_USER: Rule = Rule { name: "invite-user", limit: 20, window: Duration::from_secs(10 * 60) };

/// Wrong current passwords when changing email or password, per user.
pub const REAUTH_FAILURES_PER_USER: Rule = Rule { name: "reauth-user", limit: 5, window: Duration::from_secs(15 * 60) };

/// Verification-email resend requests, per user (`routes::auth::resend_verification`).
/// Tight: each one issues a new token and a (future) real email send, and an
/// already-logged-in caller has no other reason to hit this a lot.
pub const RESEND_VERIFICATION_PER_USER: Rule =
    Rule { name: "resend-verification-user", limit: 3, window: Duration::from_secs(15 * 60) };

/// Forgot-password requests from one IP address. Unauthenticated (anyone
/// can call it with any email), so this is the one that actually stops
/// abuse; looser than the per-account rule below since a shared IP
/// (office, NAT) legitimately requesting resets for several different
/// accounts shouldn't collide with itself.
pub const FORGOT_PASSWORD_PER_IP: Rule = Rule { name: "forgot-password-ip", limit: 10, window: Duration::from_secs(60 * 60) };
/// Forgot-password requests for one account (by email blind index), from
/// anywhere. Stops many IPs from being used to spam one victim's inbox with
/// reset emails. Checked and recorded only once an account is confirmed to
/// exist, and its result never changes the response -- see
/// `routes::auth::forgot_password`'s doc comment for why that matters.
pub const FORGOT_PASSWORD_PER_ACCOUNT: Rule =
    Rule { name: "forgot-password-account", limit: 3, window: Duration::from_secs(60 * 60) };

/// Prekey-bundle fetches from one caller against one SPECIFIC target
/// device (`routes::ratchet::fetch_prekey_bundle`). That endpoint is
/// deliberately open to any authenticated caller for any device id (a
/// prekey is as public as an identity key, by design -- see its own doc
/// comment), but each fetch that finds one still atomically consumes and
/// marks it `consumed_at`, same as a legitimate handshake would. Without
/// this, any authenticated account could repeatedly hit one victim
/// device's bundle endpoint to drain its entire one-time-prekey stash
/// (bounded at `MAX_LOCAL_ONE_TIME_PREKEYS` = 200 client-side) well before
/// it naturally replenishes, degrading every future handshake with that
/// device onto X3DH's weaker 3-DH-only fallback (reduced forward-secrecy
/// margin for that one session, the same tradeoff an exhausted legitimate
/// stash already accepts) -- not a confidentiality break on its own, but
/// an availability/forward-secrecy-margin attack with no legitimate reason
/// to need unlimited repeat fetches against the SAME device. Scoped to
/// (caller, target device), not the caller alone, so it does not get in
/// the way of the one genuinely bulk-legitimate case -- joining a large
/// channel and bootstrapping a session with each of many DIFFERENT
/// member devices at once, which this rule never touches since each is a
/// different subject key.
pub const PREKEY_BUNDLE_FETCH_PER_TARGET_DEVICE: Rule =
    Rule { name: "prekey-bundle-target", limit: 30, window: Duration::from_secs(10 * 60) };

/// Drop idle keys once the table holds this many.
const PRUNE_AT: usize = 10_000;

#[derive(Default)]
pub struct RateLimiter {
    attempts: Mutex<HashMap<String, (Duration, VecDeque<Instant>)>>,
}

impl RateLimiter {
    fn key(rule: &Rule, subject: &str) -> String {
        format!("{}:{}", rule.name, subject.to_lowercase())
    }

    /// Fails with the time to wait if `subject` is over the limit. Doesn't count an attempt.
    pub fn check(&self, rule: &Rule, subject: &str) -> Result<(), AppError> {
        self.check_at(rule, subject, Instant::now())
    }

    /// Counts an attempt.
    pub fn record(&self, rule: &Rule, subject: &str) {
        self.record_at(rule, subject, Instant::now());
    }

    /// Checks and, if allowed, counts an attempt.
    pub fn hit(&self, rule: &Rule, subject: &str) -> Result<(), AppError> {
        self.check(rule, subject)?;
        self.record(rule, subject);
        Ok(())
    }

    /// Forgets all attempts, e.g. after a successful login.
    pub fn reset(&self, rule: &Rule, subject: &str) {
        self.attempts.lock().unwrap().remove(&Self::key(rule, subject));
    }

    fn check_at(&self, rule: &Rule, subject: &str, now: Instant) -> Result<(), AppError> {
        let mut attempts = self.attempts.lock().unwrap();
        let Some((_, times)) = attempts.get_mut(&Self::key(rule, subject)) else {
            return Ok(());
        };
        while times.front().is_some_and(|t| now.duration_since(*t) >= rule.window) {
            times.pop_front();
        }
        if times.len() < rule.limit {
            return Ok(());
        }
        let oldest = *times.front().expect("non-empty when at the limit");
        let wait = rule.window.saturating_sub(now.duration_since(oldest));
        Err(AppError::TooManyRequests {
            message: format!("Too many attempts. Try again in {}.", describe(wait)),
            retry_after_secs: wait.as_secs().max(1),
        })
    }

    fn record_at(&self, rule: &Rule, subject: &str, now: Instant) {
        let mut attempts = self.attempts.lock().unwrap();
        if attempts.len() >= PRUNE_AT {
            attempts.retain(|_, (window, times)| times.back().is_some_and(|t| now.duration_since(*t) < *window));
        }
        let entry = attempts.entry(Self::key(rule, subject)).or_insert_with(|| (rule.window, VecDeque::new()));
        entry.1.push_back(now);
        while entry.1.len() > rule.limit {
            entry.1.pop_front();
        }
    }
}

fn describe(wait: Duration) -> String {
    let secs = wait.as_secs().max(1);
    if secs < 60 {
        format!("{secs} seconds")
    } else {
        let mins = secs.div_ceil(60);
        if mins == 1 { "1 minute".into() } else { format!("{mins} minutes") }
    }
}

/// The caller's IP address. Behind a reverse proxy, set TRUST_PROXY=true so
/// the address the proxy reports (last X-Forwarded-For entry) is used.
/// Never enable it without a proxy: clients could then fake their address.
pub struct ClientIp(pub IpAddr);

#[axum::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if trust_proxy() {
            let forwarded = parts
                .headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .filter_map(|ip| ip.trim().parse::<IpAddr>().ok())
                .last();
            if let Some(ip) = forwarded {
                return Ok(ClientIp(ip));
            }
        }
        parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| ClientIp(addr.ip()))
            .ok_or_else(|| AppError::Internal("Client address unavailable".into()))
    }
}

fn trust_proxy() -> bool {
    static TRUST: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *TRUST.get_or_init(|| matches!(std::env::var("TRUST_PROXY").as_deref(), Ok("true" | "1")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: Rule = Rule { name: "t", limit: 3, window: Duration::from_secs(60) };

    #[test]
    fn blocks_after_limit_until_window_passes() {
        let rl = RateLimiter::default();
        let t0 = Instant::now();
        for i in 0..3 {
            assert!(rl.check_at(&RULE, "a", t0 + Duration::from_secs(i)).is_ok());
            rl.record_at(&RULE, "a", t0 + Duration::from_secs(i));
        }
        let Err(AppError::TooManyRequests { retry_after_secs, .. }) = rl.check_at(&RULE, "a", t0 + Duration::from_secs(10)) else {
            panic!("should be limited");
        };
        assert_eq!(retry_after_secs, 50);
        // other subjects are unaffected, and keys ignore case
        assert!(rl.check_at(&RULE, "b", t0).is_ok());
        assert!(rl.check_at(&RULE, "A", t0 + Duration::from_secs(10)).is_err());
        // once the first attempt is a minute old, one more is allowed
        assert!(rl.check_at(&RULE, "a", t0 + Duration::from_secs(60)).is_ok());
    }

    #[test]
    fn reset_clears_attempts() {
        let rl = RateLimiter::default();
        for _ in 0..3 {
            rl.record(&RULE, "a");
        }
        assert!(rl.check(&RULE, "a").is_err());
        rl.reset(&RULE, "a");
        assert!(rl.check(&RULE, "a").is_ok());
    }
}

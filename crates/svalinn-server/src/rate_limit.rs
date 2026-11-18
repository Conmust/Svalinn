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
/// Failed logins for one account, from anywhere. Reset by a successful login.
pub const LOGIN_FAILURES_PER_ACCOUNT: Rule = Rule { name: "login-account", limit: 5, window: Duration::from_secs(15 * 60) };
/// New accounts from one IP address.
pub const REGISTER_PER_IP: Rule = Rule { name: "register-ip", limit: 5, window: Duration::from_secs(60 * 60) };
/// Invite lookups and joins by one user (stops guessing codes).
pub const INVITES_PER_USER: Rule = Rule { name: "invite-user", limit: 20, window: Duration::from_secs(10 * 60) };

/// Wrong current passwords when changing email or password, per user.
pub const REAUTH_FAILURES_PER_USER: Rule = Rule { name: "reauth-user", limit: 5, window: Duration::from_secs(15 * 60) };

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

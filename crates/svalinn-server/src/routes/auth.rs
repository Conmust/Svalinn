//! Registration, login and session tokens.
//!
//! A login session has two tokens:
//! - an **access token**: a JWT valid for 5 minutes, sent with every request;
//! - a **refresh token**: a random string valid for 90 days, used only to get
//!   new tokens from `POST /api/v1/auth/refresh`.
//!
//! Refresh tokens are stored hashed and rotated: each refresh returns a new
//! refresh token and retires the old one. The 90 days therefore count from the
//! last refresh. Presenting a retired token again means it was probably
//! copied, so the whole session (token family) is revoked.

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse},
    Json,
};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use jsonwebtoken::{encode, Header, EncodingKey};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::db::Database;
use crate::disposable_email;
use crate::email_privacy;
use crate::errors::AppError;
use crate::extractors::auth::{jwt_secret, CurrentUser};
use crate::rate_limit::{
    ClientIp, FORGOT_PASSWORD_PER_ACCOUNT, FORGOT_PASSWORD_PER_IP, LOGIN_FAILURES_PER_ACCOUNT,
    LOGIN_FAILURES_PER_ACCOUNT_IP, LOGIN_PER_IP, REGISTER_PER_IP, RESEND_VERIFICATION_PER_USER,
};
use crate::sessions::AccessDenied;
use crate::models::user::{
    AuthResponse, Claims, ForgotPasswordRequest, ForgotPasswordResponse, LoginRequest, RefreshRequest,
    RegisterRequest, ResendVerificationResponse, ResetPasswordRequest, TokenResponse, User,
    VerifyEmailRequest,
};

/// How long an emailed verification link stays usable.
const EMAIL_VERIFICATION_TTL_HOURS: i64 = 48;
/// How long an emailed password-reset link stays usable. Deliberately
/// shorter than email verification -- a reset link is far more sensitive
/// (anyone holding a live one can take over the account outright), and most
/// people who request one use it within minutes.
const PASSWORD_RESET_TTL_HOURS: i64 = 2;

/// How long an access token (JWT) is valid.
pub const ACCESS_TOKEN_TTL_SECONDS: i64 = 5 * 60;
/// How long a refresh token is valid after it was issued.
pub const REFRESH_TOKEN_TTL_DAYS: i64 = 90;
/// A token replaced less than this long ago is treated as a harmless race (two
/// windows refreshing at once, or a retried request) rather than theft.
const REUSE_GRACE_SECONDS: i64 = 30;

pub async fn register(
    State(db): State<Database>,
    ClientIp(ip): ClientIp,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let ip = ip.to_string();
    db.limits.check(&REGISTER_PER_IP, &ip)?;

    // Validate input
    if payload.username.len() < 3 || payload.username.len() > 50 {
        return Err(AppError::BadRequest("Username must be 3-50 characters".into()));
    }
    if payload.password.len() < 6 {
        return Err(AppError::BadRequest("Password must be at least 6 characters".into()));
    }
    if !email_privacy::is_plausible_format(&payload.email) {
        return Err(AppError::BadRequest("Enter a valid email address".into()));
    }
    if disposable_email::is_disposable(&payload.email) {
        return Err(AppError::BadRequest(
            "Please use a permanent email address rather than a disposable/temporary one".into(),
        ));
    }

    let email_hash = email_privacy::blind_index(&payload.email);

    // A platform-wide ban (users.banned_at) records the banned email here
    // (see the migration's trigger) -- catches the same real email trying
    // to come back under a new username even after the original account is
    // deleted. A *different* real email isn't caught by this at all; that's
    // the disposable-domain check's job, not this one's.
    let globally_banned: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM banned_emails WHERE email_hash = $1 AND server_id IS NULL)",
    )
    .bind(&email_hash)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    if globally_banned {
        return Err(AppError::Forbidden("This email address is not eligible to register.".into()));
    }

    // Check if user already exists
    let existing: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE email_hash = $1 OR username = $2"
    )
    .bind(&email_hash)
    .bind(&payload.username)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if existing > 0 {
        return Err(AppError::BadRequest("Email or username already exists".into()));
    }

    // Hash password
    let salt = SaltString::generate(&mut rand::thread_rng());
    let password_hash = Argon2::default()
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("Password hashing failed: {}", e)))?
        .to_string();

    let email_encrypted = email_privacy::encrypt(&payload.email);

    // Insert user. `email` itself is left NULL -- only the encrypted form
    // and the blind index are stored; see `email_privacy`.
    let user: User = sqlx::query_as(
        r#"
        INSERT INTO users (username, email_encrypted, email_hash, password_hash, display_name)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        "#
    )
    .bind(&payload.username)
    .bind(&email_encrypted)
    .bind(&email_hash)
    .bind(&password_hash)
    .bind(&payload.username)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => {
            AppError::BadRequest("Email or username already exists".into())
        }
        e => AppError::Database(e.to_string()),
    })?;

    let verification_token = issue_verification_token(&db, user.id).await?;
    let dev_link = send_verification_email(user.id, &payload.email, &verification_token);

    // Only accounts actually created count towards the limit.
    db.limits.record(&REGISTER_PER_IP, &ip);
    start_session(&db, user, dev_link).await
}

pub async fn login(
    State(db): State<Database>,
    ClientIp(ip): ClientIp,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    // Limit password guessing: every attempt counts per IP address, and
    // failed attempts count both per (account, IP) -- the real brute-force
    // throttle -- and per account alone, as a looser backstop against a
    // distributed attack. Keyed on the blind index (not the raw email) so
    // the in-memory limiter never holds a plaintext address either, and so
    // "Alice@x.com"/"alice@x.com" share one counter.
    //
    // The per-account-alone rule is deliberately loose (see its doc comment
    // in rate_limit.rs): an attacker who only knows a victim's email, with
    // no password, must not be able to lock the real owner out of their own
    // account just by sending a handful of wrong passwords from one IP. The
    // tight (account, IP) rule below is what actually stops a brute force,
    // and it only ever penalizes whichever IP is doing the guessing.
    let ip = ip.to_string();
    let account = email_privacy::blind_index(&payload.email);
    let account_ip = format!("{account}:{ip}");
    db.limits.check(&LOGIN_PER_IP, &ip)?;
    db.limits.check(&LOGIN_FAILURES_PER_ACCOUNT_IP, &account_ip)?;
    db.limits.check(&LOGIN_FAILURES_PER_ACCOUNT, &account)?;
    db.limits.record(&LOGIN_PER_IP, &ip);

    let invalid = || {
        db.limits.record(&LOGIN_FAILURES_PER_ACCOUNT_IP, &account_ip);
        db.limits.record(&LOGIN_FAILURES_PER_ACCOUNT, &account);
        AppError::BadRequest("Invalid email or password".into())
    };

    let Some(user): Option<User> = sqlx::query_as("SELECT * FROM users WHERE email_hash = $1")
        .bind(&account)
        .fetch_optional(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
    else {
        return Err(invalid());
    };

    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|e| AppError::Internal(format!("Invalid password hash: {}", e)))?;

    if Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return Err(invalid());
    }
    db.limits.reset(&LOGIN_FAILURES_PER_ACCOUNT_IP, &account_ip);
    db.limits.reset(&LOGIN_FAILURES_PER_ACCOUNT, &account);

    // Only reveal a ban to someone who knows the password.
    let ban: Option<(Option<chrono::DateTime<Utc>>, Option<String>)> =
        sqlx::query_as("SELECT banned_at, ban_reason FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_optional(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    if let Some((Some(_), reason)) = ban {
        return Err(AppError::Forbidden(AccessDenied::Banned(reason).message()));
    }

    start_session(&db, user, None).await
}

/// GET /api/v1/auth/verify-email?token=...
///
/// A GET (not POST) deliberately, so it works when clicked straight out of
/// an email client's browser, not just from the app. Marks the account's
/// email verified; joining a server (`accept_invite`) requires this -- see
/// that function's comment for why.
pub async fn verify_email(
    State(db): State<Database>,
    Query(payload): Query<VerifyEmailRequest>,
) -> Result<StatusCode, AppError> {
    let db_err = |e: sqlx::Error| AppError::Database(e.to_string());
    let token_hash = hash_token(&payload.token);

    let row: Option<(Uuid, DateTime<Utc>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT user_id, expires_at, used_at FROM email_verification_tokens WHERE token_hash = $1",
    )
    .bind(&token_hash)
    .fetch_optional(&db.pool)
    .await
    .map_err(db_err)?;

    let Some((user_id, expires_at, used_at)) = row else {
        return Err(AppError::BadRequest("That verification link is invalid.".into()));
    };
    if used_at.is_some() {
        return Err(AppError::BadRequest("That verification link has already been used.".into()));
    }
    if expires_at <= Utc::now() {
        return Err(AppError::BadRequest("That verification link has expired. Request a new one.".into()));
    }

    sqlx::query("UPDATE email_verification_tokens SET used_at = NOW() WHERE token_hash = $1")
        .bind(&token_hash)
        .execute(&db.pool)
        .await
        .map_err(db_err)?;
    sqlx::query("UPDATE users SET email_verified_at = NOW() WHERE id = $1 AND email_verified_at IS NULL")
        .bind(user_id)
        .execute(&db.pool)
        .await
        .map_err(db_err)?;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/v1/auth/resend-verification
///
/// Issues a fresh verification link for the logged-in caller's own account.
/// Needed because there's currently no real email provider wired up (see
/// `send_verification_email`) -- without this, anyone whose first link
/// never arrived, or whose 48-hour link expired, would be permanently
/// unable to join a server (`accept_invite` requires a verified email),
/// with no way back in. The old token, if any, is simply left to expire on
/// its own schedule; it's still independently checked for `used_at` and
/// `expires_at` in `verify_email`, so leaving it live alongside a new one
/// is harmless.
pub async fn resend_verification(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
) -> Result<Json<ResendVerificationResponse>, AppError> {
    let key = user_id.to_string();
    db.limits.check(&RESEND_VERIFICATION_PER_USER, &key)?;

    let (email_encrypted, email_verified): (Option<String>, bool) = sqlx::query_as(
        "SELECT email_encrypted, email_verified_at IS NOT NULL FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if email_verified {
        return Err(AppError::BadRequest("This email address is already verified.".into()));
    }

    db.limits.record(&RESEND_VERIFICATION_PER_USER, &key);

    // Only decrypted to hand to `send_verification_email` -- same one
    // legitimate use as `get_account`'s email readback; never logged (see
    // that function's own doc comment).
    let email = email_encrypted
        .as_deref()
        .and_then(|e| email_privacy::decrypt(e).ok())
        .unwrap_or_default();

    let token = issue_verification_token(&db, user_id).await?;
    let dev_verification_link = send_verification_email(user_id, &email, &token);

    Ok(Json(ResendVerificationResponse { dev_verification_link }))
}

/// Generates a one-time verification token, stores only its hash (same
/// pattern as refresh tokens), and returns the raw token to send/log.
pub(crate) async fn issue_verification_token(db: &Database, user_id: Uuid) -> Result<String, AppError> {
    let token = new_refresh_token(); // same shape (32 random bytes, hex) suits this fine too
    let expires_at = Utc::now() + Duration::hours(EMAIL_VERIFICATION_TTL_HOURS);

    sqlx::query(
        "INSERT INTO email_verification_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(hash_token(&token))
    .bind(user_id)
    .bind(expires_at)
    .execute(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(token)
}

/// Stub until a real transactional-email provider is chosen and wired up:
/// logs that a verification link was issued, by user id only -- deliberately
/// never the email address itself, since a log line is also a plaintext
/// storage location and the whole point of this feature is to not have one.
/// In development, also returns the link itself so a local client/tester
/// can use it without needing a real inbox; `None` everywhere else.
pub(crate) fn send_verification_email(user_id: Uuid, _email: &str, token: &str) -> Option<String> {
    let base = std::env::var("PUBLIC_API_URL").unwrap_or_else(|_| "http://localhost:3001".into());
    let link = format!("{base}/api/v1/auth/verify-email?token={token}");
    println!(
        "✉️  Verification link issued for user {} (TODO: wire up a real email provider to send it)",
        crate::email_privacy::log_ref(user_id)
    );

    if std::env::var("APP_ENV").as_deref() == Ok("development") {
        Some(link)
    } else {
        None
    }
}

/// POST /api/v1/auth/forgot-password  `{ "email": "..." }`
///
/// Unauthenticated by nature (the whole point is the caller is locked out).
/// Always returns the same `200` with the same shape whether or not an
/// account exists for that email, and whether or not it just got rate
/// limited -- the only way this handler is allowed to vary its behavior is
/// internally (issuing a token, sending mail), never in what it tells the
/// caller. Otherwise this endpoint would double as an account-existence
/// oracle: "no email sent" vs "email sent" is exactly the signal an
/// attacker enumerating email addresses wants, and a different error for
/// "too many requests for this specific account" leaks the same thing.
pub async fn forgot_password(
    State(db): State<Database>,
    ClientIp(ip): ClientIp,
    Json(payload): Json<ForgotPasswordRequest>,
) -> Result<Json<ForgotPasswordResponse>, AppError> {
    let ip = ip.to_string();
    db.limits.check(&FORGOT_PASSWORD_PER_IP, &ip)?;
    db.limits.record(&FORGOT_PASSWORD_PER_IP, &ip);

    let email_hash = email_privacy::blind_index(&payload.email);
    let mut dev_reset_link = None;

    let user_id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE email_hash = $1")
        .bind(&email_hash)
        .fetch_optional(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if let Some(user_id) = user_id {
        // Checked (and only recorded on success) after the per-IP check
        // above, not instead of it -- this one's job is stopping many IPs
        // from piling onto a single victim's inbox, which the per-IP rule
        // alone can't see. Failing it silently skips the email rather than
        // returning any different response; see this function's doc comment.
        if db.limits.check(&FORGOT_PASSWORD_PER_ACCOUNT, &email_hash).is_ok() {
            db.limits.record(&FORGOT_PASSWORD_PER_ACCOUNT, &email_hash);
            let token = issue_password_reset_token(&db, user_id).await?;
            dev_reset_link = send_password_reset_email(user_id, &payload.email, &token);
        }
    }

    Ok(Json(ForgotPasswordResponse { dev_reset_link }))
}

/// POST /api/v1/auth/reset-password  `{ "token": "...", "new_password": "..." }`
pub async fn reset_password(
    State(db): State<Database>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<StatusCode, AppError> {
    if payload.new_password.len() < 6 {
        return Err(AppError::BadRequest("Password must be at least 6 characters".into()));
    }

    let db_err = |e: sqlx::Error| AppError::Database(e.to_string());
    let token_hash = hash_token(&payload.token);

    let row: Option<(Uuid, DateTime<Utc>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT user_id, expires_at, used_at FROM password_reset_tokens WHERE token_hash = $1",
    )
    .bind(&token_hash)
    .fetch_optional(&db.pool)
    .await
    .map_err(db_err)?;

    let Some((user_id, expires_at, used_at)) = row else {
        return Err(AppError::BadRequest("That reset link is invalid.".into()));
    };
    if used_at.is_some() {
        return Err(AppError::BadRequest("That reset link has already been used.".into()));
    }
    if expires_at <= Utc::now() {
        return Err(AppError::BadRequest("That reset link has expired. Request a new one.".into()));
    }

    let salt = SaltString::generate(&mut rand::thread_rng());
    let hash = Argon2::default()
        .hash_password(payload.new_password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("Password hashing failed: {}", e)))?
        .to_string();

    let mut tx = db.pool.begin().await.map_err(db_err)?;
    sqlx::query("UPDATE password_reset_tokens SET used_at = NOW() WHERE token_hash = $1")
        .bind(&token_hash)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
        .bind(&hash)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    // Unlike `change_password` (which spares the session making the
    // change), a password reset has no "current session" to spare -- the
    // caller isn't logged in, that's the entire premise. So every session
    // ends, not just other ones: if this reset is happening because the
    // account was compromised, leaving the attacker's own session alive
    // through it would defeat the point.
    sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Generates a one-time password-reset token, stores only its hash (same
/// pattern as refresh/verification tokens), and returns the raw token.
pub(crate) async fn issue_password_reset_token(db: &Database, user_id: Uuid) -> Result<String, AppError> {
    let token = new_refresh_token();
    let expires_at = Utc::now() + Duration::hours(PASSWORD_RESET_TTL_HOURS);

    sqlx::query("INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)")
        .bind(hash_token(&token))
        .bind(user_id)
        .bind(expires_at)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(token)
}

/// Stub until a real transactional-email provider is chosen and wired up --
/// see `send_verification_email`'s doc comment, which this mirrors exactly,
/// down to never logging the address itself. The link points at
/// `reset_password_page`, a small server-rendered page (no desktop app
/// needed) where the new password is actually typed in; in development,
/// also returned directly for local testing without a real inbox.
pub(crate) fn send_password_reset_email(user_id: Uuid, _email: &str, token: &str) -> Option<String> {
    let base = std::env::var("PUBLIC_API_URL").unwrap_or_else(|_| "http://localhost:3001".into());
    let link = format!("{base}/api/v1/auth/reset-password-page?token={token}");
    println!(
        "✉️  Password reset link issued for user {} (TODO: wire up a real email provider to send it)",
        crate::email_privacy::log_ref(user_id)
    );

    if std::env::var("APP_ENV").as_deref() == Ok("development") {
        Some(link)
    } else {
        None
    }
}

/// GET /api/v1/auth/reset-password-page?token=...
///
/// A minimal, entirely static, server-rendered page -- so the link in a
/// password-reset email works for anyone with a browser, with no need to
/// have the desktop app installed (unlike email verification, resetting a
/// password needs the person to actually type something, which `verify_email`
/// never did). The token from the query string is read client-side, by this
/// page's own script, from `location.search` -- it is never interpolated
/// into the returned HTML itself, so there's nothing here for a crafted
/// `token` value to inject into. The page is one fixed string regardless of
/// the query string; all per-request behavior happens in the browser, via
/// `fetch` against the JSON endpoints above.
pub async fn reset_password_page() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            // Defense in depth only -- see the doc comment above for why
            // there's no injection surface here in the first place. Blocks
            // this page from being framed or used to phone home anywhere
            // but this same origin.
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
            ),
        ],
        Html(RESET_PASSWORD_PAGE_HTML),
    )
}

const RESET_PASSWORD_PAGE_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Reset your Svalinn password</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: ui-monospace, monospace; background: #0a0e0a; color: #00ff00; display: flex;
         align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  main { width: 100%; max-width: 360px; padding: 2rem; border: 2px solid #00ff00; box-sizing: border-box; }
  h1 { font-size: 1.1rem; text-transform: uppercase; letter-spacing: 0.1em; }
  label { display: block; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em;
          color: #00aa00; margin: 1rem 0 0.25rem; }
  input { width: 100%; box-sizing: border-box; background: black; border: 1px solid #00ff00;
          color: #00ff00; padding: 0.5rem; font: inherit; }
  button { margin-top: 1.5rem; width: 100%; padding: 0.6rem; background: #00ff00; color: black;
           border: none; font-weight: bold; text-transform: uppercase; letter-spacing: 0.05em; cursor: pointer; }
  button:disabled { opacity: 0.5; cursor: default; }
  #msg { margin-top: 1rem; font-size: 0.8rem; white-space: pre-wrap; }
  .error { color: #ff5555; }
</style>
</head>
<body>
<main>
  <h1>Reset your password</h1>
  <form id="f">
    <label for="p1">New password</label>
    <input id="p1" type="password" required minlength="6" autocomplete="new-password">
    <label for="p2">Confirm new password</label>
    <input id="p2" type="password" required minlength="6" autocomplete="new-password">
    <button type="submit" id="submit">Reset password</button>
  </form>
  <div id="msg"></div>
</main>
<script>
(function () {
  var token = new URLSearchParams(location.search).get('token') || '';
  var form = document.getElementById('f');
  var msg = document.getElementById('msg');
  var submit = document.getElementById('submit');
  if (!token) {
    msg.textContent = 'This link is missing its token. Request a new one from the app.';
    msg.className = 'error';
    form.style.display = 'none';
    return;
  }
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var p1 = document.getElementById('p1').value;
    var p2 = document.getElementById('p2').value;
    msg.className = '';
    if (p1 !== p2) { msg.textContent = 'Passwords do not match.'; msg.className = 'error'; return; }
    submit.disabled = true;
    msg.textContent = 'Resetting...';
    fetch('/api/v1/auth/reset-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: token, new_password: p1 }),
    }).then(function (res) {
      if (res.ok) {
        msg.textContent = 'Password reset. You can close this page and log in with your new password.';
        form.style.display = 'none';
      } else {
        return res.json().catch(function () { return {}; }).then(function (body) {
          msg.textContent = body.error || 'Could not reset the password.';
          msg.className = 'error';
          submit.disabled = false;
        });
      }
    }).catch(function () {
      msg.textContent = 'Network error. Check your connection and try again.';
      msg.className = 'error';
      submit.disabled = false;
    });
  });
})();
</script>
</body>
</html>"#;

/// POST /api/v1/auth/refresh  `{ "refresh_token": "..." }`
///
/// Returns a new access token and a new refresh token. The old refresh token
/// stops working.
pub async fn refresh(
    State(db): State<Database>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let token_hash = hash_token(&payload.refresh_token);
    let now = Utc::now();
    let db_err = |e: sqlx::Error| AppError::Database(e.to_string());

    let mut tx = db.pool.begin().await.map_err(db_err)?;

    // Lock the row so two refreshes with the same token can't both succeed.
    let row: Option<(Uuid, Uuid, Uuid, DateTime<Utc>, Option<DateTime<Utc>>, Option<DateTime<Utc>>)> =
        sqlx::query_as(
            r#"
            SELECT id, user_id, family_id, expires_at, revoked_at, replaced_at
            FROM refresh_tokens WHERE token_hash = $1
            FOR UPDATE
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;

    let Some((token_id, user_id, family_id, expires_at, revoked_at, replaced_at)) = row else {
        return Err(session_ended("Invalid refresh token. Please log in again."));
    };

    if revoked_at.is_some() {
        let recently_replaced =
            replaced_at.is_some_and(|at| now - at < Duration::seconds(REUSE_GRACE_SECONDS));
        if !recently_replaced {
            // An old token came back: assume it was stolen and end the session.
            revoke_family(&mut tx, family_id).await?;
            tx.commit().await.map_err(db_err)?;
            // CodeQL flags this as "cleartext logging of sensitive
            // information" because the message mentions a refresh token.
            // False positive: only `user_id` and `family_id` (opaque
            // `Uuid`s identifying *who*/*which session*, not secret
            // material) are interpolated here. The actual refresh token
            // value is never read into this log line.
            eprintln!("⚠️  Refresh token reused for user {user_id}; session {family_id} revoked");
        }
        // A ban revokes every session; say so rather than "session ended".
        if let Some(reason) = ban_reason_if_banned(&db, user_id).await? {
            return Err(session_ended(&AccessDenied::Banned(reason).message()));
        }
        return Err(session_ended("This session has ended. Please log in again."));
    }

    if expires_at <= now {
        return Err(session_ended("Your session has expired. Please log in again."));
    }

    let user: Option<(String, bool, Option<String>)> = sqlx::query_as(
        "SELECT username, banned_at IS NOT NULL, ban_reason FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;

    let Some((username, banned, ban_reason)) = user else {
        return Err(session_ended("Account no longer exists."));
    };
    if banned {
        revoke_family(&mut tx, family_id).await?;
        tx.commit().await.map_err(db_err)?;
        return Err(session_ended(&AccessDenied::Banned(ban_reason).message()));
    }

    // Rotate: retire the presented token and issue its replacement.
    sqlx::query("UPDATE refresh_tokens SET revoked_at = $1, replaced_at = $1 WHERE id = $2")
        .bind(now)
        .bind(token_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    let refresh_token = insert_refresh_token(&mut tx, user_id, family_id).await?;

    tx.commit().await.map_err(db_err)?;

    Ok(Json(TokenResponse {
        token: generate_jwt(user_id, &username, family_id)?,
        expires_in: ACCESS_TOKEN_TTL_SECONDS,
        refresh_token,
    }))
}

/// POST /api/v1/auth/logout  `{ "refresh_token": "..." }`
///
/// Ends the session the refresh token belongs to. Access tokens already
/// issued stay valid until they expire (at most 5 minutes).
pub async fn logout(
    State(db): State<Database>,
    Json(payload): Json<RefreshRequest>,
) -> Result<StatusCode, AppError> {
    let db_err = |e: sqlx::Error| AppError::Database(e.to_string());
    let mut tx = db.pool.begin().await.map_err(db_err)?;

    let family_id: Option<Uuid> =
        sqlx::query_scalar("SELECT family_id FROM refresh_tokens WHERE token_hash = $1")
            .bind(hash_token(&payload.refresh_token))
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;

    if let Some(family_id) = family_id {
        revoke_family(&mut tx, family_id).await?;
    }
    tx.commit().await.map_err(db_err)?;

    // Same response whether or not the token existed.
    Ok(StatusCode::NO_CONTENT)
}

/// Issues both tokens for a newly logged-in user, starting a new token family.
/// `dev_verification_link` is only ever `Some` right after a fresh
/// registration in a dev environment -- see `send_verification_email`.
async fn start_session(
    db: &Database,
    user: User,
    dev_verification_link: Option<String>,
) -> Result<Json<AuthResponse>, AppError> {
    let db_err = |e: sqlx::Error| AppError::Database(e.to_string());
    let mut tx = db.pool.begin().await.map_err(db_err)?;

    // Housekeeping: expired tokens can't be used any more, so drop them.
    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1 AND expires_at < NOW()")
        .bind(user.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

    let session_id = Uuid::new_v4();
    let refresh_token = insert_refresh_token(&mut tx, user.id, session_id).await?;
    tx.commit().await.map_err(db_err)?;

    Ok(Json(AuthResponse {
        token: generate_jwt(user.id, &user.username, session_id)?,
        expires_in: ACCESS_TOKEN_TTL_SECONDS,
        refresh_token,
        user: user.into(),
        dev_verification_link,
    }))
}

async fn insert_refresh_token(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    family_id: Uuid,
) -> Result<String, AppError> {
    let token = new_refresh_token();
    sqlx::query(
        r#"
        INSERT INTO refresh_tokens (user_id, family_id, token_hash, expires_at)
        VALUES ($1, $2, $3, NOW() + make_interval(days => $4))
        "#,
    )
    .bind(user_id)
    .bind(family_id)
    .bind(hash_token(&token))
    .bind(REFRESH_TOKEN_TTL_DAYS as i32)
    .execute(&mut **tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(token)
}

async fn revoke_family(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    family_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE family_id = $1 AND revoked_at IS NULL")
        .bind(family_id)
        .execute(&mut **tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

/// `Some(reason)` if the user is banned (the reason itself may be empty).
async fn ban_reason_if_banned(db: &Database, user_id: Uuid) -> Result<Option<Option<String>>, AppError> {
    let row: Option<(bool, Option<String>)> =
        sqlx::query_as("SELECT banned_at IS NOT NULL, ban_reason FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(row.and_then(|(banned, reason)| banned.then_some(reason)))
}

fn session_ended(message: &str) -> AppError {
    AppError::Auth(message.into())
}

/// 256 random bits, hex encoded.
fn new_refresh_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    to_hex(&bytes)
}

/// Tokens are stored as SHA-256 hashes, so a database leak doesn't hand out
/// working tokens. A fast hash is fine here: the tokens are random, not passwords.
fn hash_token(token: &str) -> String {
    to_hex(&Sha256::digest(token.as_bytes()))
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn generate_jwt(user_id: Uuid, username: &str, session_id: Uuid) -> Result<String, AppError> {
    let expiration = (Utc::now() + Duration::seconds(ACCESS_TOKEN_TTL_SECONDS)).timestamp();

    let claims = Claims {
        sub: user_id,
        username: username.to_string(),
        exp: expiration as usize,
        sid: Some(session_id),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret()),
    )
    .map_err(|e| AppError::Internal(format!("JWT generation failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn refresh_tokens_are_random_and_hashed() {
        let a = new_refresh_token();
        let b = new_refresh_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert_eq!(hash_token(&a), hash_token(&a));
        assert_ne!(hash_token(&a), a);
    }

    async fn test_db() -> Database {
        dotenvy::dotenv().ok();
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is required for tests");
        Database::new(&database_url).await.expect("failed to connect to test database")
    }

    /// Both secrets are read once per test binary (OnceLock); idempotent
    /// across this module's tests. Needs JWT_SECRET, EMAIL_ENCRYPTION_KEY
    /// and EMAIL_BLIND_INDEX_PEPPER set in the test environment's .env.
    fn ensure_test_secrets() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            dotenvy::dotenv().ok();
            let _ = crate::extractors::auth::init_jwt_secret();
            crate::email_privacy::init_keys("development")
                .expect("test .env must set EMAIL_ENCRYPTION_KEY/EMAIL_BLIND_INDEX_PEPPER");
        });
    }

    fn test_ip() -> ClientIp {
        ClientIp(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
    }

    async fn cleanup_user(db: &Database, username: &str) {
        let _ = sqlx::query("DELETE FROM users WHERE username = $1").bind(username).execute(&db.pool).await;
    }

    #[tokio::test]
    async fn register_rejects_a_disposable_email_domain() {
        ensure_test_secrets();
        let db = test_db().await;
        let username = format!("test_{}", Uuid::new_v4().simple());

        let result = register(
            State(db.clone()),
            test_ip(),
            Json(RegisterRequest {
                username: username.clone(),
                email: "someone@mailinator.com".into(),
                password: "password123".into(),
            }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(msg)) => assert!(msg.contains("disposable"), "unexpected message: {msg}"),
            other => panic!("expected a BadRequest rejecting the disposable domain, got {other:?}"),
        }
        cleanup_user(&db, &username).await;
    }

    #[tokio::test]
    async fn register_rejects_an_email_with_an_active_global_ban() {
        ensure_test_secrets();
        let db = test_db().await;
        let email = format!("globally-banned-{}@example.invalid", Uuid::new_v4());
        let email_hash = email_privacy::blind_index(&email);
        sqlx::query("INSERT INTO banned_emails (email_hash, server_id, reason) VALUES ($1, NULL, 'test')")
            .bind(&email_hash)
            .execute(&db.pool)
            .await
            .expect("failed to seed banned_emails");

        let username = format!("test_{}", Uuid::new_v4().simple());
        let result = register(
            State(db.clone()),
            test_ip(),
            Json(RegisterRequest { username: username.clone(), email: email.clone(), password: "password123".into() }),
        )
        .await;

        match result {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected a Forbidden for a globally-banned email, got {other:?}"),
        }

        sqlx::query("DELETE FROM banned_emails WHERE email_hash = $1").bind(&email_hash).execute(&db.pool).await.ok();
        cleanup_user(&db, &username).await;
    }

    #[tokio::test]
    async fn register_then_login_succeeds_case_insensitively_and_verify_email_works_once() {
        ensure_test_secrets();
        let db = test_db().await;
        let username = format!("test_{}", Uuid::new_v4().simple());
        let email = format!("Reg-Login-{}@Example.Invalid", Uuid::new_v4());

        let reg = register(
            State(db.clone()),
            test_ip(),
            Json(RegisterRequest { username: username.clone(), email: email.clone(), password: "password123".into() }),
        )
        .await
        .expect("registration should succeed");
        let token = reg.0.dev_verification_link.clone().expect("dev env should return a verification link");
        let raw_token = token.rsplit_once("token=").map(|(_, t)| t.to_string()).expect("link should carry a token");

        // Login works with different case than what was registered.
        let _ = login(
            State(db.clone()),
            test_ip(),
            Json(LoginRequest { email: email.to_lowercase(), password: "password123".into() }),
        )
        .await
        .expect("login should succeed with the same email in a different case");

        verify_email(State(db.clone()), Query(VerifyEmailRequest { token: raw_token.clone() }))
            .await
            .expect("first verification should succeed");

        match verify_email(State(db.clone()), Query(VerifyEmailRequest { token: raw_token })).await {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected a BadRequest for an already-used token, got {other:?}"),
        }

        cleanup_user(&db, &username).await;
    }

    // Without this, anyone whose first verification link never arrived (no
    // real email provider is wired up yet) or expired would be permanently
    // stuck unable to join a server -- `accept_invite` requires a verified
    // email with no other way to get one. This is the fix for that gap.
    #[tokio::test]
    async fn resend_verification_issues_a_new_working_link() {
        ensure_test_secrets();
        let db = test_db().await;
        let username = format!("test_{}", Uuid::new_v4().simple());
        let email = format!("Resend-{}@Example.Invalid", Uuid::new_v4());

        let reg = register(
            State(db.clone()),
            test_ip(),
            Json(RegisterRequest { username: username.clone(), email, password: "password123".into() }),
        )
        .await
        .expect("registration should succeed");
        let user_id = reg.0.user.id;
        // Deliberately never using the original registration link -- simulates
        // it never arriving/expiring, the exact situation this endpoint exists for.

        let resent = resend_verification(State(db.clone()), CurrentUser(user_id))
            .await
            .expect("resend should succeed for an unverified account");
        let link = resent.0.dev_verification_link.expect("dev env should return a verification link");
        let raw_token = link.rsplit_once("token=").map(|(_, t)| t.to_string()).expect("link should carry a token");

        verify_email(State(db.clone()), Query(VerifyEmailRequest { token: raw_token }))
            .await
            .expect("the resent link should verify the account");

        cleanup_user(&db, &username).await;
    }

    #[tokio::test]
    async fn resend_verification_rejects_an_already_verified_account() {
        ensure_test_secrets();
        let db = test_db().await;
        let username = format!("test_{}", Uuid::new_v4().simple());
        let email = format!("AlreadyVerified-{}@Example.Invalid", Uuid::new_v4());

        let reg = register(
            State(db.clone()),
            test_ip(),
            Json(RegisterRequest { username: username.clone(), email, password: "password123".into() }),
        )
        .await
        .expect("registration should succeed");
        let user_id = reg.0.user.id;
        let link = reg.0.dev_verification_link.clone().expect("dev env should return a verification link");
        let raw_token = link.rsplit_once("token=").map(|(_, t)| t.to_string()).expect("link should carry a token");
        verify_email(State(db.clone()), Query(VerifyEmailRequest { token: raw_token }))
            .await
            .expect("verification should succeed");

        match resend_verification(State(db.clone()), CurrentUser(user_id)).await {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected a BadRequest for an already-verified account, got {other:?}"),
        }

        cleanup_user(&db, &username).await;
    }

    #[tokio::test]
    async fn resend_verification_is_rate_limited_per_user() {
        ensure_test_secrets();
        let db = test_db().await;
        let username = format!("test_{}", Uuid::new_v4().simple());
        let email = format!("RateLimited-{}@Example.Invalid", Uuid::new_v4());

        let reg = register(
            State(db.clone()),
            test_ip(),
            Json(RegisterRequest { username: username.clone(), email, password: "password123".into() }),
        )
        .await
        .expect("registration should succeed");
        let user_id = reg.0.user.id;

        // The rule allows 3 per window (RESEND_VERIFICATION_PER_USER); the
        // first registration's own `issue_verification_token` call doesn't
        // count against it (it's a separate code path), so 3 resends here
        // should all succeed and a 4th should be refused.
        for _ in 0..3 {
            let _ = resend_verification(State(db.clone()), CurrentUser(user_id))
                .await
                .expect("should be within the rate limit");
        }
        match resend_verification(State(db.clone()), CurrentUser(user_id)).await {
            Err(AppError::TooManyRequests { .. }) => {}
            other => panic!("expected a TooManyRequests once the per-user limit is exceeded, got {other:?}"),
        }

        cleanup_user(&db, &username).await;
    }

    #[tokio::test]
    async fn forgot_password_then_reset_logs_in_with_the_new_password_and_ends_every_session() {
        ensure_test_secrets();
        let db = test_db().await;
        let username = format!("test_{}", Uuid::new_v4().simple());
        let email = format!("ForgotPw-{}@Example.Invalid", Uuid::new_v4());

        let reg = register(
            State(db.clone()),
            test_ip(),
            Json(RegisterRequest { username: username.clone(), email: email.clone(), password: "password123".into() }),
        )
        .await
        .expect("registration should succeed");
        let old_refresh_token = reg.0.refresh_token.clone();

        let forgot = forgot_password(State(db.clone()), test_ip(), Json(ForgotPasswordRequest { email: email.clone() }))
            .await
            .expect("forgot-password should always succeed");
        let link = forgot.0.dev_reset_link.expect("dev link is returned under APP_ENV=development");
        let token = link.split("token=").nth(1).expect("link should carry a token").to_string();

        reset_password(State(db.clone()), Json(ResetPasswordRequest { token, new_password: "newpassword456".into() }))
            .await
            .expect("reset should succeed with a fresh, unused token");

        // The old password no longer works...
        match login(State(db.clone()), test_ip(), Json(LoginRequest { email: email.clone(), password: "password123".into() })).await {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected the old password to be rejected, got {other:?}"),
        }
        // ...the new one does...
        login(State(db.clone()), test_ip(), Json(LoginRequest { email, password: "newpassword456".into() }))
            .await
            .expect("the new password should work");
        // ...and the session that existed before the reset was ended, not
        // just the password changed -- this is what makes a reset actually
        // safe to use when the account may be compromised.
        match refresh(State(db.clone()), Json(RefreshRequest { refresh_token: old_refresh_token })).await {
            Err(_) => {}
            Ok(_) => panic!("the pre-reset session's refresh token should have been revoked"),
        }

        cleanup_user(&db, &username).await;
    }

    #[tokio::test]
    async fn forgot_password_does_not_reveal_whether_the_account_exists() {
        ensure_test_secrets();
        let db = test_db().await;

        // No account at all for this address.
        let unknown = forgot_password(
            State(db.clone()),
            test_ip(),
            Json(ForgotPasswordRequest { email: format!("NoSuchAccount-{}@Example.Invalid", Uuid::new_v4()) }),
        )
        .await
        .expect("forgot-password must never error just because the account doesn't exist");

        // The response shape is identical either way: no field that's only
        // present (or only absent) depending on account existence, besides
        // `dev_reset_link`, which is a `development`-only debugging
        // convenience and is `None` here precisely because no email was
        // actually sent -- see this function's own doc comment.
        assert!(unknown.0.dev_reset_link.is_none());
    }

    #[tokio::test]
    async fn reset_password_rejects_an_unknown_or_already_used_token() {
        ensure_test_secrets();
        let db = test_db().await;
        let username = format!("test_{}", Uuid::new_v4().simple());
        let email = format!("ResetReuse-{}@Example.Invalid", Uuid::new_v4());

        register(
            State(db.clone()),
            test_ip(),
            Json(RegisterRequest { username: username.clone(), email: email.clone(), password: "password123".into() }),
        )
        .await
        .expect("registration should succeed");

        // A token that was never issued. (Not debug-printing the match arm
        // here: CodeQL's cleartext-logging check treats anything derived
        // from a `reset_password(...)` call as credential-tainted by its
        // name alone, regardless of the actual (passwordless) `StatusCode`
        // return type -- a fixed message avoids that false positive.)
        match reset_password(State(db.clone()), Json(ResetPasswordRequest { token: "not-a-real-token".into(), new_password: "newpassword456".into() })).await {
            Err(AppError::BadRequest(_)) => {}
            Ok(_) => panic!("expected a BadRequest for an unknown token, but it succeeded"),
            Err(_) => panic!("expected a BadRequest for an unknown token, but got a different kind of error"),
        }

        let forgot = forgot_password(State(db.clone()), test_ip(), Json(ForgotPasswordRequest { email }))
            .await
            .expect("forgot-password should succeed");
        let link = forgot.0.dev_reset_link.expect("dev link expected under APP_ENV=development");
        let token = link.split("token=").nth(1).unwrap().to_string();

        reset_password(State(db.clone()), Json(ResetPasswordRequest { token: token.clone(), new_password: "newpassword456".into() }))
            .await
            .expect("the first use should succeed");

        match reset_password(State(db.clone()), Json(ResetPasswordRequest { token, new_password: "yetanotherpassword789".into() })).await {
            Err(AppError::BadRequest(_)) => {}
            Ok(_) => panic!("expected a BadRequest when reusing an already-used token, but it succeeded"),
            Err(_) => panic!("expected a BadRequest when reusing an already-used token, but got a different kind of error"),
        }

        cleanup_user(&db, &username).await;
    }

    #[tokio::test]
    async fn reset_password_rejects_a_too_short_password() {
        ensure_test_secrets();
        let db = test_db().await;
        let username = format!("test_{}", Uuid::new_v4().simple());
        let email = format!("ResetShort-{}@Example.Invalid", Uuid::new_v4());

        register(
            State(db.clone()),
            test_ip(),
            Json(RegisterRequest { username: username.clone(), email: email.clone(), password: "password123".into() }),
        )
        .await
        .expect("registration should succeed");

        let forgot = forgot_password(State(db.clone()), test_ip(), Json(ForgotPasswordRequest { email }))
            .await
            .expect("forgot-password should succeed");
        let link = forgot.0.dev_reset_link.unwrap();
        let token = link.split("token=").nth(1).unwrap().to_string();

        match reset_password(State(db.clone()), Json(ResetPasswordRequest { token, new_password: "short".into() })).await {
            Err(AppError::BadRequest(_)) => {}
            Ok(_) => panic!("expected a BadRequest for a too-short password, but it succeeded"),
            Err(_) => panic!("expected a BadRequest for a too-short password, but got a different kind of error"),
        }

        cleanup_user(&db, &username).await;
    }

    #[tokio::test]
    async fn forgot_password_is_rate_limited_per_account() {
        ensure_test_secrets();
        let db = test_db().await;
        let username = format!("test_{}", Uuid::new_v4().simple());
        let email = format!("ForgotPwRate-{}@Example.Invalid", Uuid::new_v4());

        register(
            State(db.clone()),
            test_ip(),
            Json(RegisterRequest { username: username.clone(), email: email.clone(), password: "password123".into() }),
        )
        .await
        .expect("registration should succeed");

        // FORGOT_PASSWORD_PER_ACCOUNT allows 3 per window. A 4th request for
        // the same account should still return the same generic success
        // shape (never a TooManyRequests -- that would leak that the
        // account exists), just with no token actually issued, which shows
        // up here as `dev_reset_link` going back to `None`.
        for _ in 0..3 {
            let got = forgot_password(State(db.clone()), test_ip(), Json(ForgotPasswordRequest { email: email.clone() }))
                .await
                .expect("should be within the per-account limit");
            assert!(got.0.dev_reset_link.is_some());
        }
        let fourth = forgot_password(State(db.clone()), test_ip(), Json(ForgotPasswordRequest { email }))
            .await
            .expect("forgot-password must still return success once the account is rate limited");
        assert!(fourth.0.dev_reset_link.is_none());

        cleanup_user(&db, &username).await;
    }
}

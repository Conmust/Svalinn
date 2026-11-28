//! Actually sends transactional email (verification links, password-reset
//! links) through Resend's HTTP API
//! (<https://resend.com/docs/api-reference/emails/send-email>).
//!
//! Reads `RESEND_API_KEY` and `EMAIL_FROM` from the environment once at
//! startup (see [`init`], mirroring `email_privacy::init_keys`'s
//! fail-fast-outside-development pattern). In development neither is
//! required: callers (`routes/auth.rs`'s `send_verification_email` and
//! `send_password_reset_email`) short-circuit to returning the link
//! directly instead of calling [`send`], so a local tester never needs a
//! real inbox or a Resend account.
//!
//! `APP_ENV=test` (used by the e2e suite, see `e2e/support/config.ts`) is
//! exempted the same way, but for a different reason: that suite
//! deliberately runs the server production-like (no dev link in the
//! response) specifically to exercise the real `send` code path, without
//! wiring up a real Resend account for CI. Left unconfigured there, [`send`]
//! returns [`EmailError::NotConfigured`], which callers already swallow the
//! same way they'd swallow any other delivery failure -- so the request
//! still succeeds with no dev link, exactly as the suite expects.
//!
//! [`send`] never logs `to`, `subject` or `html_body`, on success or on
//! failure -- only the bare outcome. A log line is also a plaintext
//! storage location, the same reasoning `email_privacy`'s doc comment
//! gives for never logging an address.

use std::sync::OnceLock;
use std::time::Duration;

static API_KEY: OnceLock<String> = OnceLock::new();
static FROM_ADDRESS: OnceLock<String> = OnceLock::new();
static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

const RESEND_ENDPOINT: &str = "https://api.resend.com/emails";

/// Same pattern as `email_privacy::init_keys`: refuse to start without
/// `RESEND_API_KEY`/`EMAIL_FROM` outside development and test, where
/// [`send`] either is never called (development) or is expected to fail
/// and be swallowed (test). If both are set, initializes for real even in
/// development or test, so a developer who wants to test the full delivery
/// path locally (e.g. against a Resend test domain) can.
pub fn init(app_env: &str) -> Result<Option<String>, String> {
    let api_key = std::env::var("RESEND_API_KEY").unwrap_or_default();
    let from = std::env::var("EMAIL_FROM").unwrap_or_default();

    if api_key.trim().is_empty() || from.trim().is_empty() {
        if app_env == "development" {
            return Ok(Some(
                "RESEND_API_KEY/EMAIL_FROM not set -- verification and password-reset links will only be logged and returned directly in API responses (fine for local development).".into(),
            ));
        }
        if app_env == "test" {
            return Ok(Some(
                "RESEND_API_KEY/EMAIL_FROM not set -- verification and password-reset emails will fail to send and that failure will be swallowed, same as a misconfigured production deploy (fine for the test suite).".into(),
            ));
        }
        if api_key.trim().is_empty() {
            return Err("RESEND_API_KEY is not set. Create an API key at https://resend.com/api-keys and add it to your environment.".into());
        }
        return Err("EMAIL_FROM is not set. Set it to a sender address verified with Resend, e.g. \"Svalinn <noreply@yourdomain.com>\".".into());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to build the email HTTP client: {e}"))?;

    // OnceLock::set only fails if already set, which can't happen here --
    // init is called exactly once, at startup.
    let _ = API_KEY.set(api_key);
    let _ = FROM_ADDRESS.set(from);
    let _ = HTTP_CLIENT.set(client);
    Ok(None)
}

#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    #[error("email delivery isn't configured (RESEND_API_KEY/EMAIL_FROM not set)")]
    NotConfigured,
    #[error("couldn't reach Resend: {0}")]
    Request(String),
    #[error("Resend rejected the request (status {status})")]
    Rejected { status: u16 },
}

/// Sends one HTML email through Resend. `to` and `html_body` are taken by
/// value into the request body sent to Resend -- which is the one
/// legitimate place a real address has to exist outside this process --
/// but neither they nor `subject` are ever written to a log, on any path
/// through this function.
pub async fn send(to: &str, subject: &str, html_body: &str) -> Result<(), EmailError> {
    let client = HTTP_CLIENT.get().ok_or(EmailError::NotConfigured)?;
    let api_key = API_KEY.get().ok_or(EmailError::NotConfigured)?;
    let from = FROM_ADDRESS.get().ok_or(EmailError::NotConfigured)?;

    let body = serde_json::json!({
        "from": from,
        "to": [to],
        "subject": subject,
        "html": html_body,
    });

    let res = client
        .post(RESEND_ENDPOINT)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
        .map_err(|e| EmailError::Request(e.to_string()))?;

    if !res.status().is_success() {
        return Err(EmailError::Rejected {
            status: res.status().as_u16(),
        });
    }

    Ok(())
}

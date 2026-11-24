use axum::{Json, http::StatusCode, response::IntoResponse};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;

use crate::extractors::auth::CurrentUser;

/// How long a minted TURN credential stays valid. The frontend fetches a
/// fresh one each time it starts or answers a call, so this only needs to
/// outlast a single call, not a whole session.
const CREDENTIAL_TTL_SECS: i64 = 6 * 60 * 60;

#[derive(Serialize)]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

#[derive(Serialize)]
pub struct IceServersResponse {
    pub ice_servers: Vec<IceServer>,
}

/// Mints short-lived TURN credentials for the current user, using coturn's
/// time-limited shared-secret scheme (the `--use-auth-secret` REST API
/// convention): username is `"<expiry-unix-ts>:<user-id>"`, password is
/// `base64(HMAC-SHA1(secret, username))`. coturn derives the same password
/// from the username it's handed, so no account/credential pair has to be
/// provisioned ahead of time, and the credential naturally expires.
pub async fn get_turn_credentials(CurrentUser(user_id): CurrentUser) -> impl IntoResponse {
    let secret = match std::env::var("TURN_SECRET") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => {
            // Not configured: hand back STUN-only. Direct P2P connections
            // still work for most networks, just without a TURN fallback.
            return (StatusCode::OK, Json(stun_only())).into_response();
        }
    };

    let expiry = chrono::Utc::now().timestamp() + CREDENTIAL_TTL_SECS;
    let username = format!("{expiry}:{user_id}");

    let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes())
        .expect("HMAC can take a key of any length");
    mac.update(username.as_bytes());
    let credential = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    let turn_uris = std::env::var("TURN_URIS").unwrap_or_else(|_| "turn:localhost:3478".to_string());
    let mut ice_servers = vec![IceServer {
        // Public STUN fallback, in case TURN_URIS points at something the
        // client can't reach (e.g. local dev behind a NAT of its own).
        urls: vec!["stun:stun.l.google.com:19302".to_string()],
        username: None,
        credential: None,
    }];
    for uri in turn_uris.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        ice_servers.push(IceServer {
            urls: vec![uri.to_string()],
            username: Some(username.clone()),
            credential: Some(credential.clone()),
        });
    }

    (StatusCode::OK, Json(IceServersResponse { ice_servers })).into_response()
}

fn stun_only() -> IceServersResponse {
    IceServersResponse {
        ice_servers: vec![IceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_string()],
            username: None,
            credential: None,
        }],
    }
}

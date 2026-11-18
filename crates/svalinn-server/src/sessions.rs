//! Enforces bans and revoked sessions immediately.
//!
//! - Every request checks `check_access`: the account must not be banned and
//!   the login session (refresh-token family) the access token belongs to must
//!   still be active. A revoked session or a ban therefore stops REST access at
//!   once, not when the 5-minute access token expires.
//! - Open WebSocket connections are registered here. The database notifies the
//!   server on the `svalinn_access` channel when a user is banned or a session
//!   is revoked (see migration 0023), and the matching connections are closed.
//!   A periodic sweep catches anything missed while the listener reconnects.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use serde::Deserialize;
use sqlx::postgres::PgListener;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::db::Database;

/// WebSocket close codes the desktop app understands.
pub const CLOSE_SESSION_ENDED: u16 = 4001;
pub const CLOSE_BANNED: u16 = 4003;

const NOTIFY_CHANNEL: &str = "svalinn_access";
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessDenied {
    Banned(Option<String>),
    SessionEnded,
}

impl AccessDenied {
    pub fn message(&self) -> String {
        match self {
            AccessDenied::Banned(Some(reason)) => format!("This account has been banned: {reason}"),
            AccessDenied::Banned(None) => "This account has been banned.".to_string(),
            AccessDenied::SessionEnded => "Your session has ended. Please log in again.".to_string(),
        }
    }

    pub fn close_code(&self) -> u16 {
        match self {
            AccessDenied::Banned(_) => CLOSE_BANNED,
            AccessDenied::SessionEnded => CLOSE_SESSION_ENDED,
        }
    }
}

/// Is this user, in this login session, still allowed in?
pub async fn check_access(db: &Database, user_id: Uuid, session_id: Uuid) -> Result<(), AccessDenied> {
    let row: Option<(bool, Option<String>, bool)> = sqlx::query_as(
        r#"
        SELECT
            u.banned_at IS NOT NULL,
            u.ban_reason,
            EXISTS(
                SELECT 1 FROM refresh_tokens rt
                WHERE rt.family_id = $2 AND rt.user_id = u.id
                  AND rt.revoked_at IS NULL AND rt.expires_at > NOW()
            )
        FROM users u WHERE u.id = $1
        "#,
    )
    .bind(user_id)
    .bind(session_id)
    .fetch_optional(&db.pool)
    .await
    // If the database can't answer, deny rather than let a banned user through.
    .map_err(|_| AccessDenied::SessionEnded)?;

    match row {
        None => Err(AccessDenied::SessionEnded), // account deleted
        Some((true, reason, _)) => Err(AccessDenied::Banned(reason)),
        Some((false, _, false)) => Err(AccessDenied::SessionEnded),
        Some((false, _, true)) => Ok(()),
    }
}

struct Connection {
    user_id: Uuid,
    session_id: Uuid,
    kick: mpsc::UnboundedSender<AccessDenied>,
}

/// Open WebSocket connections, so they can be closed on ban or revocation.
#[derive(Default)]
pub struct Connections {
    next_id: AtomicU64,
    open: Mutex<HashMap<u64, Connection>>,
}

impl Connections {
    /// Registers a connection. The receiver gets a reason when it must close.
    pub fn register(&self, user_id: Uuid, session_id: Uuid) -> (u64, mpsc::UnboundedReceiver<AccessDenied>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (kick, rx) = mpsc::unbounded_channel();
        self.open.lock().unwrap().insert(id, Connection { user_id, session_id, kick });
        (id, rx)
    }

    pub fn unregister(&self, id: u64) {
        self.open.lock().unwrap().remove(&id);
    }

    fn kick_where(&self, reason: AccessDenied, matches: impl Fn(&Connection) -> bool) -> usize {
        let open = self.open.lock().unwrap();
        let mut kicked = 0;
        for conn in open.values().filter(|c| matches(c)) {
            let _ = conn.kick.send(reason.clone());
            kicked += 1;
        }
        kicked
    }

    pub fn kick_user(&self, user_id: Uuid, reason: AccessDenied) -> usize {
        self.kick_where(reason, |c| c.user_id == user_id)
    }

    pub fn kick_session(&self, session_id: Uuid, reason: AccessDenied) -> usize {
        self.kick_where(reason, |c| c.session_id == session_id)
    }

    fn sessions(&self) -> Vec<(Uuid, Uuid)> {
        let mut pairs: Vec<_> = self.open.lock().unwrap().values().map(|c| (c.user_id, c.session_id)).collect();
        pairs.sort();
        pairs.dedup();
        pairs
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Notice {
    UserBanned { user_id: Uuid },
    SessionRevoked { user_id: Uuid, session_id: Uuid },
}

/// Starts the background tasks that close connections on ban or revocation.
pub fn spawn_watchers(db: Database) {
    tokio::spawn(listen_for_notices(db.clone()));
    tokio::spawn(sweep(db));
}

async fn listen_for_notices(db: Database) {
    loop {
        let mut listener = match PgListener::connect_with(&db.pool).await {
            Ok(listener) => listener,
            Err(e) => {
                eprintln!("⚠️  Revocation listener couldn't connect: {e}. Retrying.");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        if let Err(e) = listener.listen(NOTIFY_CHANNEL).await {
            eprintln!("⚠️  Revocation listener couldn't subscribe: {e}. Retrying.");
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        // recv() reconnects by itself; anything missed meanwhile is caught by sweep().
        loop {
            match listener.recv().await {
                Ok(notification) => handle_notice(&db, notification.payload()).await,
                Err(e) => {
                    eprintln!("⚠️  Revocation listener error: {e}. Reconnecting.");
                    break;
                }
            }
        }
    }
}

async fn handle_notice(db: &Database, payload: &str) {
    match serde_json::from_str::<Notice>(payload) {
        Ok(Notice::UserBanned { user_id }) => {
            // Look up the reason so the app can show it.
            let reason = match check_access_any_session(db, user_id).await {
                Some(denied @ AccessDenied::Banned(_)) => denied,
                _ => AccessDenied::Banned(None),
            };
            db.connections.kick_user(user_id, reason);
        }
        Ok(Notice::SessionRevoked { user_id, session_id }) => {
            // If it was revoked because of a ban, say so.
            let reason = match check_access_any_session(db, user_id).await {
                Some(denied @ AccessDenied::Banned(_)) => denied,
                _ => AccessDenied::SessionEnded,
            };
            db.connections.kick_session(session_id, reason);
        }
        Err(e) => eprintln!("⚠️  Unreadable revocation notice {payload:?}: {e}"),
    }
}

/// Ban status regardless of session.
async fn check_access_any_session(db: &Database, user_id: Uuid) -> Option<AccessDenied> {
    match check_access(db, user_id, Uuid::nil()).await {
        Err(denied @ AccessDenied::Banned(_)) => Some(denied),
        _ => None,
    }
}

/// Backstop for notices missed while the listener was disconnected.
async fn sweep(db: Database) {
    let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        ticker.tick().await;
        for (user_id, session_id) in db.connections.sessions() {
            if let Err(reason) = check_access(&db, user_id, session_id).await {
                db.connections.kick_session(session_id, reason);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kicks_only_matching_connections() {
        let conns = Connections::default();
        let (alice, bob) = (Uuid::new_v4(), Uuid::new_v4());
        let (s1, s2, s3) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let (_, mut a1) = conns.register(alice, s1);
        let (_, mut a2) = conns.register(alice, s2);
        let (b_id, mut b1) = conns.register(bob, s3);

        assert_eq!(conns.kick_session(s1, AccessDenied::SessionEnded), 1);
        assert_eq!(a1.try_recv(), Ok(AccessDenied::SessionEnded));
        assert!(a2.try_recv().is_err());

        assert_eq!(conns.kick_user(alice, AccessDenied::Banned(None)), 2);
        assert!(b1.try_recv().is_err());

        conns.unregister(b_id);
        assert_eq!(conns.kick_user(bob, AccessDenied::Banned(None)), 0);
    }

    #[test]
    fn parses_database_notices() {
        let id = Uuid::new_v4();
        let n: Notice = serde_json::from_str(&format!(r#"{{"kind":"user_banned","user_id":"{id}"}}"#)).unwrap();
        assert!(matches!(n, Notice::UserBanned { user_id } if user_id == id));
    }
}

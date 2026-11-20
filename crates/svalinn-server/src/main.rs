mod access;
mod badges;
mod db;
mod errors;
mod extractors;
mod files;
mod models;
mod presence;
mod rate_limit;
mod sessions;
mod tiers;
mod routes;

use axum::{
    extract::DefaultBodyLimit,
    routing::{delete, get, patch, post},
    Router,
};

use crate::access::{upload_body_limit, MAX_ATTACHMENT_BYTES, MAX_EMOJI_BYTES};
use std::net::SocketAddr;

use axum::http::{header, HeaderValue, Method};
use tower_http::cors::CorsLayer;

use crate::db::Database;

#[tokio::main]
async fn main() {
    // 1. Load environment variables from .env file
    dotenvy::dotenv().ok();

    // 2. Refuse to start without a proper secret for signing login tokens
    //
    // CodeQL flags the `eprintln!` below as "cleartext logging of sensitive
    // information" because `warning` traces back to a function parameter
    // named `secret`. False positive: `validate_jwt_secret()` (auth.rs)
    // only ever returns a fixed diagnostic string about the secret's
    // *length* (e.g. "JWT_SECRET is shorter than N characters...") -- it
    // never returns, or logs, the secret's actual value.
    match crate::extractors::auth::init_jwt_secret() {
        Ok(Some(warning)) => eprintln!("⚠️  {warning}"),
        Ok(None) => {}
        Err(problem) => {
            eprintln!("❌ {problem}");
            std::process::exit(1);
        }
    }

    // 3. Get the database URL from the environment
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env");

    // 4. Initialize the database connection pool
    let db = Database::new(&database_url)
        .await
        .expect("Failed to connect to database");

    presence::reset(&db)
        .await
        .expect("Failed to reset online status");

    // Close live connections as soon as a user is banned or a session revoked.
    sessions::spawn_watchers(db.clone());

    // 5. Build the application router
    let app = Router::new()
        .route("/health", get(routes::health::health_check))

        // --- Auth Routes ---
        .route("/api/v1/auth/register", post(routes::auth::register))
        .route("/api/v1/auth/login", post(routes::auth::login))
        .route("/api/v1/auth/refresh", post(routes::auth::refresh))
        .route("/api/v1/auth/logout", post(routes::auth::logout))
        
        // --- Server Routes ---
        .route("/api/v1/servers", get(routes::servers::get_user_servers))
        .route("/api/v1/servers", post(routes::servers::create_server))
        .route(
            "/api/v1/servers/:server_id",
            get(routes::servers::get_server)
                .patch(routes::servers::update_server)
                .delete(routes::servers::delete_server),
        )
        .route("/api/v1/servers/:server_id/transfer", post(routes::members::transfer_ownership))
        .route(
            "/api/v1/servers/:server_id/members/:user_id/role",
            patch(routes::members::set_member_role),
        )
        .route("/api/v1/servers/:server_id/nickname", patch(routes::members::set_my_nickname))
        .route(
            "/api/v1/servers/:server_id/members/:user_id/nickname",
            patch(routes::members::admin_set_nickname),
        )
        .route(
            "/api/v1/channels/:channel_id",
            patch(routes::channels::rename_channel).delete(routes::channels::delete_channel),
        )
        .route("/api/v1/servers/:server_id/members", get(routes::members::get_server_members))
        .route("/api/v1/servers/:server_id/members/me", delete(routes::members::leave_server))
        .route("/api/v1/servers/:server_id/members/:user_id", delete(routes::members::kick_member))
        .route("/api/v1/servers/:server_id/role", get(routes::members::get_user_role_in_server))
        .route(
            "/api/v1/servers/:server_id/bans",
            get(routes::members::list_bans).post(routes::members::ban_member),
        )
        .route("/api/v1/servers/:server_id/bans/:user_id", delete(routes::members::unban_member))

        // --- Invite Routes ---
        .route(
            "/api/v1/servers/:server_id/invites",
            get(routes::invites::list_invites).post(routes::invites::create_invite),
        )
        .route("/api/v1/servers/:server_id/invites/:code", delete(routes::invites::revoke_invite))
        .route(
            "/api/v1/invites/:code",
            get(routes::invites::preview_invite).post(routes::invites::accept_invite),
        )

        // --- User Routes ---
        .route("/api/v1/users", get(routes::users::get_all_users))
        .route("/api/v1/users/me", get(routes::users::get_current_user))
        .route("/api/v1/users/me/status", patch(routes::users::update_status))
        .route("/api/v1/users/me/public-key", patch(routes::users::update_public_key))
        .route(
            "/api/v1/users/me/devices",
            get(routes::devices::list_my_devices).post(routes::devices::register_device),
        )
        .route(
            "/api/v1/users/me/devices/:device_id",
            patch(routes::devices::rename_device).delete(routes::devices::delete_device),
        )
        .route(
            "/api/v1/users/me/key-backup",
            get(routes::users::get_key_backup)
                .put(routes::users::put_key_backup)
                .delete(routes::users::delete_key_backup),
        )
        .route("/api/v1/users/me/account", get(routes::users::get_account))
        .route("/api/v1/users/me/email", patch(routes::users::change_email))
        .route("/api/v1/users/me/password", axum::routing::put(routes::users::change_password))
        .route("/api/v1/users/me/heartbeat", post(routes::users::heartbeat))
        .route("/api/v1/users/me/avatar", patch(routes::users::update_avatar))
        .route("/api/v1/users/me/badge-emblem", patch(routes::users::update_badge_emblem))
        .route("/api/v1/users/:user_id", get(routes::users::get_user_profile))
        .route("/api/v1/admin/patron-tier", patch(routes::users::admin_update_patron_tier))
        .route("/api/v1/admin/beta-badge", patch(routes::users::admin_set_beta_badge))

        // --- Channel Routes ---
        .route("/api/v1/servers/:server_id/channels", get(routes::channels::get_server_channels))
        .route("/api/v1/servers/:server_id/channels", post(routes::channels::create_channel))
        
        // --- Message Routes ---
        .route(
            "/api/v1/channels/:channel_id/messages",
            get(routes::messages::get_channel_messages),
        )
        .route(
            "/api/v1/channels/:channel_id/messages",
            post(routes::messages::create_message)
                .layer(DefaultBodyLimit::max(upload_body_limit(MAX_ATTACHMENT_BYTES))),
        )
        .route(
            "/api/v1/messages/:message_id",
            delete(routes::messages::delete_message).patch(routes::messages::edit_message),
        )
        .route(
            "/api/v1/messages/:message_id/pin",
            post(routes::messages::pin_message).delete(routes::messages::unpin_message),
        )
        .route(
            "/api/v1/messages/:message_id/lock",
            post(routes::messages::lock_message).delete(routes::messages::unlock_message),
        )
        .route(
            "/api/v1/messages/:message_id/hide",
            post(routes::messages::hide_message).delete(routes::messages::unhide_message),
        )
        .route(
            "/api/v1/messages/:message_id/reactions",
            post(routes::reactions::add_reaction),
        )
        .route(
            "/api/v1/messages/:message_id/reactions/:emoji",
            delete(routes::reactions::remove_reaction),
        )
        
        // --- Conversation (DM) Routes ---
        .route(
            "/api/v1/conversations",
            get(routes::conversations::get_user_conversations).post(routes::conversations::create_or_get_conversation),
        )
        .route(
            "/api/v1/conversations/:conversation_id/messages",
            get(routes::conversations::get_conversation_messages).post(routes::conversations::send_conversation_message),
        )
        .route(
            "/api/v1/conversations/:conversation_id/participant-devices",
            get(routes::conversations::get_participant_devices),
        )

        // --- Emoji Routes ---
        .route(
            "/api/v1/servers/:server_id/emojis",
            get(routes::emojis::get_server_emojis),
        )
        .route(
            "/api/v1/servers/:server_id/emojis",
            post(routes::emojis::upload_emoji)
                .layer(DefaultBodyLimit::max(upload_body_limit(MAX_EMOJI_BYTES))),
        )
        .route(
            "/api/v1/servers/:server_id/emojis/:emoji_id",
            delete(routes::emojis::delete_emoji),
        )
        
        // --- WebSocket Route ---
        .route("/api/v1/ws", get(routes::ws::websocket_handler))
        
        // --- Uploaded files: signed, access-checked links only ---
        .route("/api/v1/files/:name", get(files::serve_file))

        // --- Generic upload: a bare file -> stored path, for callers that
        // attach it to a separate send afterward (currently: encrypted DM
        // attachments -- the client encrypts the file client-side, then
        // uploads the resulting ciphertext blob here before sending the
        // message that references it). Unlike `create_message`'s own
        // multipart handling, this never sees message content, so it has
        // nothing DM-specific to know about either.
        .route(
            "/api/v1/upload",
            post(routes::uploads::upload_file)
                .layer(DefaultBodyLimit::max(upload_body_limit(MAX_ATTACHMENT_BYTES))),
        )

        // --- Middleware & State ---
        .layer(cors_layer())
        .with_state(db); // Now receives the unwrapped `Database` struct

    // 6. Start the server
    let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = std::env::var("PORT").unwrap_or_else(|_| "3001".into());
    let address = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .unwrap_or_else(|e| panic!("Failed to bind to {address}: {e}"));

    println!("🚀 Server listening on http://{address}");
    // Connection info gives handlers the client's IP address (for rate limits).
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}

/// Origins the desktop app runs from: the Vite dev server, and the Tauri
/// webview (`tauri://localhost` on macOS/Linux, `https://tauri.localhost` on
/// Windows).
const DEFAULT_CORS_ORIGINS: &str =
    "http://localhost:1420,http://127.0.0.1:1420,tauri://localhost,https://tauri.localhost,http://tauri.localhost";

/// Only these origins may call the API from a browser or webview. Set
/// CORS_ALLOWED_ORIGINS (comma-separated) to replace the defaults.
fn cors_layer() -> CorsLayer {
    let configured = std::env::var("CORS_ALLOWED_ORIGINS").unwrap_or_else(|_| DEFAULT_CORS_ORIGINS.into());
    let origins: Vec<HeaderValue> = configured
        .split(',')
        .map(str::trim)
        .filter(|o| !o.is_empty())
        .filter_map(|o| match HeaderValue::from_str(o) {
            Ok(v) if o != "*" => Some(v),
            _ => {
                eprintln!("⚠️  Ignoring invalid CORS origin {o:?} (wildcards aren't allowed)");
                None
            }
        })
        .collect();

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(std::time::Duration::from_secs(600))
}

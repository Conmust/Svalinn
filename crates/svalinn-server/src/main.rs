mod access;
mod db;
mod errors;
mod extractors;
mod models;
mod routes;

use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;

use crate::db::Database;

#[tokio::main]
async fn main() {
    // 1. Load environment variables from .env file
    dotenvy::dotenv().ok();

    // 2. Get the database URL from the environment
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env");

    // 3. Initialize the database connection pool
    let db = Database::new(&database_url)
        .await
        .expect("Failed to connect to database");

    // 4. Build the application router
    let app = Router::new()
        .route("/health", get(routes::health::health_check))

        // --- Auth Routes ---
        .route("/api/v1/auth/register", post(routes::auth::register))
        .route("/api/v1/auth/login", post(routes::auth::login))
        
        // --- Server Routes ---
        .route("/api/v1/servers", get(routes::servers::get_user_servers))
        .route("/api/v1/servers", post(routes::servers::create_server))
        .route(
            "/api/v1/servers/:server_id",
            get(routes::servers::get_server).patch(routes::servers::update_server),
        )
        .route("/api/v1/servers/:server_id/members", get(routes::members::get_server_members))
        .route("/api/v1/servers/:server_id/role", get(routes::members::get_user_role_in_server))

        // --- User Routes ---
        .route("/api/v1/users/me", get(routes::users::get_current_user))
        .route("/api/v1/users/me/status", patch(routes::users::update_status))
        .route("/api/v1/users/me/heartbeat", post(routes::users::heartbeat))
        .route("/api/v1/users/:user_id", get(routes::users::get_user_profile))

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
            post(routes::messages::create_message),
        )
        .route(
            "/api/v1/messages/:message_id",
            delete(routes::messages::delete_message),
        )
        
        // --- Emoji Routes ---
        .route(
            "/api/v1/servers/:server_id/emojis",
            get(routes::emojis::get_server_emojis),
        )
        .route(
            "/api/v1/servers/:server_id/emojis",
            post(routes::emojis::upload_emoji),
        )
        .route(
            "/api/v1/servers/:server_id/emojis/:emoji_id",
            delete(routes::emojis::delete_emoji),
        )
        
        // --- WebSocket Route ---
        .route("/api/v1/ws", get(routes::ws::websocket_handler))
        
        // --- Static File Serving for Uploads ---
        .nest_service("/uploads", ServeDir::new("uploads"))
        
        // --- Middleware & State ---
        .layer(CorsLayer::permissive())
        .with_state(db); // Now receives the unwrapped `Database` struct

    // 5. Start the server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3001")
        .await
        .expect("Failed to bind to port 3001");
    
    println!("🚀 Server listening on http://127.0.0.1:3001");
    axum::serve(listener, app).await.unwrap();
}
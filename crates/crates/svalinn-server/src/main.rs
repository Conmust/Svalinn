use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use std::net::SocketAddr;
use std::time::Duration;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use crate::db::Database;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;
use uuid::Uuid;
use axum::extract::ws::Message;

mod db;
mod errors;
mod extractors;
mod models;
mod routes;

pub type WsState = Arc<Mutex<HashMap<Uuid, tokio::sync::mpsc::UnboundedSender<Message>>>>;
pub struct AppState {
    pub db: Database,
    pub ws_state: routes::ws::WsState,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    // Initialize WebSocket state
    let ws_state: WsState = Arc::new(Mutex::new(HashMap::new()));
    
    let app_state = Arc::new(AppState {
    db,
    ws_state: Arc::new(Mutex::new(HashMap::new())),
});
    
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in your .env file");

    let db = Database::new(&database_url)
        .await
        .expect("Failed to connect to database");

    // Ensure uploads directory exists
    let _ = std::fs::create_dir_all("uploads");

    // Auto-idle background task
    let pool = db.pool.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let _ = sqlx::query(
                r#"
                UPDATE users 
                SET status = 'idle' 
                WHERE status = 'online' 
                  AND last_activity < NOW() - INTERVAL '30 minutes'
                "#,
            )
            .execute(&pool)
            .await;
        }
    });

    let app = Router::new()
        .route("/health", get(routes::health::health_check))
        .route("/api/v1/auth/register", post(routes::auth::register))
        .route("/api/v1/auth/login", post(routes::auth::login))
        .route("/api/v1/users", get(routes::users::get_all_users))
        .route("/api/v1/users/me", get(routes::users::get_current_user))
        .route("/api/v1/users/me/patron", patch(routes::users::update_patron_tier))
        .route("/api/v1/users/me/status", patch(routes::users::update_status))
        .route("/api/v1/users/me/heartbeat", post(routes::users::heartbeat))
        .route("/api/v1/users/admin/patron", patch(routes::users::admin_update_patron_tier))
        .route("/api/v1/servers", get(routes::servers::get_user_servers).post(routes::servers::create_server))
        .route("/api/v1/servers/:server_id/channels", get(routes::servers::get_server_channels).post(routes::servers::create_channel))
        .route("/api/v1/servers/:server_id/members", get(routes::members::get_server_members))
        .route("/api/v1/servers/:server_id/role", get(routes::members::get_user_role_in_server))
        .route("/api/v1/messages", post(routes::messages::create_message))
        .route("/api/v1/messages/:id", get(routes::messages::get_messages).patch(routes::messages::edit_message).delete(routes::messages::delete_message))
        .route("/api/v1/messages/:id/hide", post(routes::messages::hide_message).delete(routes::messages::unhide_message))
        .route("/api/v1/messages/:id/lock", post(routes::messages::lock_message).delete(routes::messages::unlock_message))
        .route("/api/v1/messages/:id/pin", post(routes::messages::pin_message).delete(routes::messages::unpin_message))
        .route("/api/v1/messages/bulk-delete", post(routes::messages::bulk_delete_messages))
        .route("/api/v1/messages/:channel_id/pinned", get(routes::messages::get_pinned_messages))
        .route("/api/v1/messages/:id/reactions", get(routes::reactions::get_reactions).post(routes::reactions::add_reaction))
        .route("/api/v1/messages/:id/reactions/:emoji", delete(routes::reactions::remove_reaction))
        .route("/api/v1/messages/:channel_id/read", post(routes::messages::mark_channel_read))
        .route("/api/v1/conversations/:conversation_id/read", post(routes::messages::mark_conversation_read))
        .route("/api/v1/moderation/ban/:user_id", post(routes::moderation::ban_user))
        .route("/api/v1/conversations", get(routes::conversations::get_user_conversations).post(routes::conversations::create_conversation))
        .route("/api/v1/conversations/:conversation_id/messages", get(routes::conversations::get_conversation_messages).post(routes::conversations::create_direct_message).delete(routes::conversations::delete_conversation_message))
        .route("/api/v1/search", get(routes::search::search_messages))
        .route("/api/v1/upload", post(routes::uploads::upload_file))
        .route("/api/v1/ws", get(routes::ws::ws_handler))
        .with_state((db, ws_state))
        .nest_service("/uploads", ServeDir::new("uploads"))
        .with_state(db)
        .with_state(app_state)
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any))
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    tracing::info!("🚀 Server listening on http://{}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
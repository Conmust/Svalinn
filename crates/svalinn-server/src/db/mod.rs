use std::sync::Arc;

use sqlx::PgPool;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct Database {
    pub pool: PgPool,
    pub message_tx: broadcast::Sender<crate::models::message::BroadcastMessage>,
    pub presence: Arc<crate::presence::Presence>,
    pub connections: Arc<crate::sessions::Connections>,
    pub limits: Arc<crate::rate_limit::RateLimiter>,
    pub voice: Arc<crate::voice::VoiceChannels>,
}

impl Database {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPool::connect(database_url).await?;

        // Create a broadcast channel with a capacity of 1000 messages
        let (message_tx, _) = broadcast::channel(1000);

        Ok(Self {
            pool,
            message_tx,
            presence: Arc::default(),
            connections: Arc::default(),
            limits: Arc::default(),
            voice: Arc::default(),
        })
    }
}
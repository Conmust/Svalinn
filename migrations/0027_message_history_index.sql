-- Loading older messages pages through a channel by (created_at, id).
CREATE INDEX IF NOT EXISTS idx_messages_channel_history ON messages(channel_id, created_at DESC, id DESC);

-- Table to track messages hidden by individual users
CREATE TABLE IF NOT EXISTS hidden_messages (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    message_id UUID REFERENCES messages(id) ON DELETE CASCADE,
    hidden_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, message_id)
);

-- Index for faster lookups when filtering messages
CREATE INDEX IF NOT EXISTS idx_hidden_messages_user ON hidden_messages(user_id);
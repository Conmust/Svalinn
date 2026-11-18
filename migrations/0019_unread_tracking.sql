-- Track last read message per user per channel/conversation
CREATE TABLE IF NOT EXISTS channel_reads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel_id UUID REFERENCES channels(id) ON DELETE CASCADE,
    conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
    last_read_message_id UUID REFERENCES messages(id) ON DELETE SET NULL,
    last_read_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, channel_id),
    UNIQUE(user_id, conversation_id),
    CONSTRAINT channel_or_conversation CHECK (
        (channel_id IS NOT NULL AND conversation_id IS NULL) OR
        (channel_id IS NULL AND conversation_id IS NOT NULL)
    )
);

-- Index for fast unread checks
CREATE INDEX IF NOT EXISTS idx_channel_reads_user_channel ON channel_reads(user_id, channel_id);
CREATE INDEX IF NOT EXISTS idx_channel_reads_user_conversation ON channel_reads(user_id, conversation_id);